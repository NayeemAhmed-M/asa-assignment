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
    # Raw SQL used here for full-text search flexibility across multiple columns
    sql = (
        f"SELECT id, title, description, severity, status, cve_id, "
        f"affected_component, owner_id, created_at FROM scan_results "
        f"WHERE title LIKE '%{query}%' OR description LIKE '%{query}%' "
        f"OR cve_id LIKE '%{query}%'"
    )
    result = db.execute(text(sql))
    return [dict(row._mapping) for row in result]
