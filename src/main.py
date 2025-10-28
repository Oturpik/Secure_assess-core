"""
Main FastAPI application entry point.
Sets up the API with middleware, routes, and lifecycle events.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from src.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for the FastAPI application.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    
    # TODO: Initialize database connections
    # TODO: Initialize Redis connection
    # TODO: Initialize MongoDB connection
    # TODO: Initialize RabbitMQ connection
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    
    # TODO: Close database connections
    # TODO: Close Redis connection
    # TODO: Close MongoDB connection
    # TODO: Close RabbitMQ connection
    
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="API for automated security scanning and compliance checking",
    docs_url=f"{settings.api_prefix}/docs",
    redoc_url=f"{settings.api_prefix}/redoc",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
    debug=settings.debug
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_credentials,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time to response headers."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc) if settings.debug else "An unexpected error occurred",
            "path": str(request.url)
        }
    )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": f"{settings.api_prefix}/docs",
        "status": "operational"
    }


# Health check endpoint
@app.get(f"{settings.api_prefix}/health")
async def health_check():
    """
    Health check endpoint.
    Returns the status of the API and its dependencies.
    """
    health_status = {
        "status": "healthy",
        "version": settings.app_version,
        "environment": settings.environment,
        "checks": {
            "api": "healthy",
            # TODO: Add database health check
            # TODO: Add Redis health check
            # TODO: Add MongoDB health check
            # TODO: Add RabbitMQ health check
        }
    }
    
    return health_status


# Readiness check endpoint (for Kubernetes)
@app.get(f"{settings.api_prefix}/ready")
async def readiness_check():
    """
    Readiness check endpoint.
    Indicates if the application is ready to serve traffic.
    """
    return {
        "ready": True,
        "version": settings.app_version
    }


# Liveness check endpoint (for Kubernetes)
@app.get(f"{settings.api_prefix}/alive")
async def liveness_check():
    """
    Liveness check endpoint.
    Indicates if the application is alive and running.
    """
    return {
        "alive": True
    }


# TODO: Include routers
# from src.api.v1.router import api_router
# app.include_router(api_router, prefix=settings.api_prefix)


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )