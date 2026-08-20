"""FastAPI application entry point."""
import signal
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.database import connect_to_mongodb, close_mongodb
from app.api import auth, consent, dashboard, admin
from app.core.logging import setup_logging, get_logger
from app.core.security import setup_security
from app.core.session_validator import SessionValidationMiddleware
from app.api.admin import AdminAuthError
from app.core.language import LanguageMiddleware

# Initialize logging
setup_logging()
logger = get_logger(__name__)
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown events."""
    # Startup
    logger.info("🚀 Starting Sanpsy Health OAuth Connector")
    await connect_to_mongodb()
    
    # Graceful shutdown handler for Cloud Run
    def handle_sigterm(*args):
        logger.info("🛑 Received SIGTERM, shutting down gracefully...")
        raise KeyboardInterrupt
    
    signal.signal(signal.SIGTERM, handle_sigterm)
    
    yield

    # Shutdown
    logger.info("🛑 Shutting down Sanpsy Health OAuth Connector")
    await close_mongodb()

def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    
    app = FastAPI(
        title="Sanpsy Health OAuth Connector",
        description="Secure Google Health authentication service",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
    )

    setup_security(app)


    # MIDDLEWARES (Order matters!)
    # Added first -> Runs last (closest to the app routes)
    
    # 1. Session Validation (Needs session, so it must run after SessionMiddleware)
    app.add_middleware(SessionValidationMiddleware)
    
    # 2. Language Middleware (Needs session, so it must run after SessionMiddleware)
    app.add_middleware(LanguageMiddleware)
    
    # 3. Session Middleware (Populates request.session)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        https_only=settings.is_production,
        same_site="lax"
    )
    
    # 4. CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.base_url] if settings.is_production else ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )
    
    # 5. GZip Middleware (Added last -> Runs first on incoming request)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Static files and templates
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    
    # Register routers
    app.include_router(auth.public_router)  # Public OAuth endpoints
    app.include_router(auth.router)         # API endpoints
    app.include_router(dashboard.router)    # Dashboard endpoints
    app.include_router(consent.router)      # User consent endpoints
    app.include_router(admin.router)        # Admin endpoints
    
    # Root health check
    @app.get("/health")
    async def root_health():
        """Root health check."""
        from app.database import health_check
        return await health_check()
    
    
    # EXCEPTION HANDLERS
    
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Catch-all for unhandled exceptions."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "error_type": type(exc).__name__
            }
        )
    
    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request: Request, exc: HTTPException):
        """
        Custom handler for HTTPException.
        Redirects 401 (Unauthorized) to homepage instead of showing error page.
        """
        # If user is not authenticated, redirect to homepage
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            return RedirectResponse(url="/?not_authenticated=true", status_code=status.HTTP_303_SEE_OTHER)
        
        # For all other HTTP errors (403, 404, 500, etc.), show the error page
        from app.core.templates import templates
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": f"Error {exc.status_code}",
                "message": exc.detail,
                "details": None
            },
            status_code=exc.status_code
        )
    
    @app.exception_handler(AdminAuthError)
    async def admin_auth_error_handler(request: Request, exc: AdminAuthError):
        """Redirect unauthenticated admins to the login page."""
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
        
    logger.info("✅ FastAPI application configured")
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8080,
        reload=not settings.is_production,
        log_level=settings.log_level.lower()
    )