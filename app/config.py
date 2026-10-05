import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = os.getenv("SECRET_KEY", "v3ry-s3cr3t-jwt-k3y-do-not-share")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database credentials (injected via secrets manager in production)
DB_USER = os.getenv("DB_USER", "vulntracker_app")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Tr@cker2024!")

# Internal service API key
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c")

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")

