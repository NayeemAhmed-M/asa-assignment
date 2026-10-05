import logging
import secrets
import traceback
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import NOTIFY_SERVICE_URL
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:3001",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:3000",
}


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log internal details and stack trace on the server for diagnostics
    logger.error("Unhandled exception on %s: %s\n%s", request.url, exc, traceback.format_exc())
    # Return sanitized generic error response without leaking stack traces or internal paths
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please contact support.",
        },
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ShareCreate(BaseModel):
    password: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # Redact password to prevent credential leakage in application logs
    logger.info("Login attempt for username: %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login attempt for username: '%s'", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Enforce tenant isolation / IDOR protection: verify ownership of scan record
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Share routes
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share")
def create_share_link(
    scan_id: int,
    request: Request,
    payload: ShareCreate = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Default to empty payload if none provided
    if payload is None:
        payload = ShareCreate()

    # Verify scan exists and belongs to the current user
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Generate a cryptographically secure, URL-safe token
    token = secrets.token_urlsafe(32)

    # Hash the password with bcrypt if one was provided
    password_hash = None
    if payload.password:
        password_hash = get_password_hash(payload.password)

    # Create the share link with a 24-hour expiry window
    share_link = models.ShareLink(
        scan_id=scan_id,
        token=token,
        password_hash=password_hash,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        created_by=current_user.id,
    )
    db.add(share_link)
    db.commit()
    db.refresh(share_link)

    # Validate Host header against allowed domains to mitigate Host Header Injection & Phishing
    incoming_host = request.headers.get("host", "localhost:8000")
    hostname = incoming_host.split(":")[0].lower()
    trusted_hosts = {"localhost", "127.0.0.1", "testserver", "vulntracker.local"}
    if hostname in trusted_hosts or hostname.endswith(".internal"):
        safe_host = incoming_host
    else:
        safe_host = "localhost:8000"

    base_url = f"{request.url.scheme}://{safe_host}"
    share_url = f"{base_url}/share/{token}"

    return {"share_url": share_url}


@app.get("/share/{token}")
def access_shared_scan(
    token: str,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # Look up the share link by token
    share_link = db.query(models.ShareLink).filter(
        models.ShareLink.token == token,
    ).first()

    # Use a single error message for not-found and expired to prevent token enumeration
    if not share_link or share_link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    # Verify password if the share link is password-protected
    if share_link.password_hash:
        if not password:
            raise HTTPException(status_code=401, detail="Password required")
        if not verify_password(password, share_link.password_hash):
            raise HTTPException(status_code=401, detail="Invalid password")

    # Fetch and return the scan data
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == share_link.scan_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": scan.id,
        "title": scan.title,
        "description": scan.description,
        "severity": scan.severity,
        "status": scan.status,
        "cve_id": scan.cve_id,
        "affected_component": scan.affected_component,
        "remediation_notes": scan.remediation_notes,
        "owner_id": scan.owner_id,
        "created_at": scan.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
