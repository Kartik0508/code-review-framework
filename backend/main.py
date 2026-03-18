import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from loguru import logger

from backend.core.config import settings
from backend.db.database import Base, engine


# ── Logging ───────────────────────────────────────────────────────────────────
logger.remove()
logger.add(sys.stdout, level=settings.LOG_LEVEL, colorize=True,
           format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level}</level> | {message}")


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Secure Code Review Framework API")
    # Import models so they are registered with Base before create_all
    import backend.db.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database tables created. Environment: {settings.ENVIRONMENT}")
    yield
    logger.info("Shutting down Secure Code Review Framework API")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Secure Code Review Framework API",
    version="1.0.0",
    description=(
        "Automated security vulnerability detection platform integrating "
        "SonarQube, Semgrep, Bandit, Gitleaks, and OWASP Dependency-Check."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else ["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
from backend.auth.router import router as auth_router
from backend.api.users import router as users_router
from backend.api.projects import router as projects_router
from backend.api.scans import router as scans_router
from backend.api.reports import router as reports_router

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(reports_router)


# ── Core endpoints ────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
    }
