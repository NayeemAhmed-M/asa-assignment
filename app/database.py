from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str) -> list:
    # Use parameterized SQL binding to prevent SQL injection vulnerabilities
    sql = (
        "SELECT id, title, description, severity, status, cve_id, "
        "affected_component, owner_id, created_at FROM scan_results "
        "WHERE title LIKE :search_pattern OR description LIKE :search_pattern "
        "OR cve_id LIKE :search_pattern"
    )
    result = db.execute(text(sql), {"search_pattern": f"%{query}%"})
    return [dict(row._mapping) for row in result]
