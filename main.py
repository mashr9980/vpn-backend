from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import logging
import sys
from datetime import datetime
from sqlalchemy.orm import Session
from database import get_db, engine
from models import Base
from routes import auth, vpn, admin, servers
from config import settings, validate_config, get_config_summary
import uvicorn

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

if settings.LOG_FILE:
    file_handler = logging.FileHandler(settings.LOG_FILE)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logging.getLogger().addHandler(file_handler)

logger = logging.getLogger(__name__)

wg_easy_manager = None
tunnel_manager = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global wg_easy_manager, tunnel_manager
    
    logger.info("Starting WireGuard VPN Backend...")
    
    try:
        validate_config()
        logger.info("Configuration validation passed")
        
        config_summary = get_config_summary()
        logger.info(f"Configuration loaded: {config_summary}")
        
        logger.info("Initializing database...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
        
        logger.info("Initializing wg-easy connection...")
        from utils.wg_panel_manager import WgEasyManager, DynamicTunnelManager
        
        wg_easy_manager = WgEasyManager(
            panel_url=settings.WG_EASY_PANEL_URL,
            password=settings.WG_EASY_PASSWORD
        )
        
        success, message = wg_easy_manager.test_connection()
        if success:
            logger.info(f"wg-easy connection successful: {message}")
        else:
            logger.error(f"wg-easy connection failed: {message}")
            if not settings.DEBUG:
                raise RuntimeError(f"Cannot connect to wg-easy panel: {message}")
        
        if settings.ENABLE_DYNAMIC_TUNNELS:
            logger.info("Initializing dynamic tunnel manager...")
            tunnel_manager = DynamicTunnelManager(wg_easy_manager)
            logger.info("Dynamic tunnel manager initialized")
        
        app.state.wg_easy_manager = wg_easy_manager
        app.state.tunnel_manager = tunnel_manager
        
        logger.info("WireGuard VPN Backend started successfully!")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    finally:
        logger.info("Shutting down WireGuard VPN Backend...")
        logger.info("WireGuard VPN Backend shutdown complete")

app = FastAPI(
    title="WireGuard VPN Backend",
    description="Dynamic WireGuard VPN management with wg-easy integration",
    version="2.0.0",
    docs_url=settings.DOCS_URL,
    redoc_url=settings.REDOC_URL,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS_LIST,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(vpn.router, prefix="/vpn", tags=["VPN"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])
app.include_router(servers.router, prefix="/servers", tags=["Servers"])

@app.get("/")
async def root():
    return {
        "message": "WireGuard VPN Backend API",
        "version": "2.0.0",
        "features": {
            "dynamic_tunnels": settings.ENABLE_DYNAMIC_TUNNELS,
            "wg_easy_integration": True,
            "auto_cleanup": settings.TUNNEL_AUTO_CLEANUP,
            "background_tasks": settings.ENABLE_BACKGROUND_TASKS,
            "metrics": settings.ENABLE_METRICS
        },
        "endpoints": {
            "auth": "/auth",
            "vpn": "/vpn",
            "admin": "/admin",
            "servers": "/servers",
            "health": "/health",
            "docs": settings.DOCS_URL,
            "redoc": settings.REDOC_URL
        }
    }

@app.get("/health")
async def health_check():
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {},
        "metrics": {}
    }
    
    try:
        try:
            db = next(get_db())
            db.execute("SELECT 1")
            health_status["services"]["database"] = {"status": "healthy", "message": "Connected"}
        except Exception as e:
            health_status["services"]["database"] = {"status": "unhealthy", "message": str(e)}
            health_status["status"] = "degraded"
        
        if wg_easy_manager:
            try:
                success, message = wg_easy_manager.test_connection()
                health_status["services"]["wg_easy"] = {
                    "status": "healthy" if success else "unhealthy",
                    "message": message
                }
                if not success:
                    health_status["status"] = "degraded"
            except Exception as e:
                health_status["services"]["wg_easy"] = {"status": "unhealthy", "message": str(e)}
                health_status["status"] = "degraded"
        else:
            health_status["services"]["wg_easy"] = {"status": "not_configured", "message": "wg-easy manager not initialized"}
        
        if tunnel_manager:
            try:
                active_tunnels = tunnel_manager.get_active_tunnel_count()
                health_status["services"]["tunnel_manager"] = {"status": "healthy", "message": "Running"}
                health_status["metrics"]["active_tunnels"] = active_tunnels
            except Exception as e:
                health_status["services"]["tunnel_manager"] = {"status": "unhealthy", "message": str(e)}
                health_status["status"] = "degraded"
        else:
            health_status["services"]["tunnel_manager"] = {"status": "disabled", "message": "Dynamic tunnels disabled"}
        
        health_status["metrics"]["python_version"] = sys.version.split()[0]
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@app.get("/metrics")
async def get_metrics():
    if not settings.ENABLE_METRICS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics endpoint is disabled"
        )
    
    try:
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": 0,
            "total_requests": 0,
            "active_tunnels": 0,
            "wg_easy_status": "unknown"
        }
        
        if tunnel_manager:
            metrics["active_tunnels"] = tunnel_manager.get_active_tunnel_count()
        
        if wg_easy_manager:
            success, _ = wg_easy_manager.test_connection()
            metrics["wg_easy_status"] = "connected" if success else "disconnected"
        
        return metrics
        
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get metrics"
        )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower()
    )