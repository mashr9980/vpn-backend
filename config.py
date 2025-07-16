from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # Database Configuration
    POSTGRES_USER: str = os.getenv("DB_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("DB_PASSWORD", "123")
    POSTGRES_SERVER: str = os.getenv("DB_HOST", "localhost")
    POSTGRES_PORT: str = os.getenv("DB_PORT", "5432")
    POSTGRES_DB: str = os.getenv("DB_NAME", "vpn_db")
    
    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "asassa")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "300"))

    # WG-Easy Configuration
    WG_EASY_PANEL_URL: str = os.getenv("WG_EASY_PANEL_URL", "http://74.208.112.39:51821")
    WG_EASY_PASSWORD: str = os.getenv("WG_EASY_PASSWORD", "123456789")
    WG_EASY_USERNAME: str = os.getenv("WG_EASY_USERNAME", "admin")
    
    # Dynamic Tunnel Management
    ENABLE_DYNAMIC_TUNNELS: bool = os.getenv("ENABLE_DYNAMIC_TUNNELS", "true").lower() == "true"
    MAX_TUNNELS_PER_USER: int = int(os.getenv("MAX_TUNNELS_PER_USER", "1"))
    TUNNEL_AUTO_CLEANUP: bool = os.getenv("TUNNEL_AUTO_CLEANUP", "true").lower() == "true"
    TUNNEL_CLEANUP_DELAY: int = int(os.getenv("TUNNEL_CLEANUP_DELAY", "300"))
    TUNNEL_IDLE_TIMEOUT: int = int(os.getenv("TUNNEL_IDLE_TIMEOUT", "3600"))
    
    # Legacy WireGuard Configuration
    WIREGUARD_CONFIG_PATH: str = "/etc/wireguard"
    WIREGUARD_INTERFACE: str = "wg0"
    VPN_SUBNET: str = "10.8.0.0/24"
    VPN_DNS: str = "1.1.1.1"
    
    # Server Configuration
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8002"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: Optional[str] = os.getenv("LOG_FILE", None)
    
    # Security Configuration
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "3600"))
    
    # Monitoring Configuration
    ENABLE_METRICS: bool = os.getenv("ENABLE_METRICS", "true").lower() == "true"
    METRICS_PORT: int = int(os.getenv("METRICS_PORT", "9090"))
    HEALTH_CHECK_INTERVAL: int = int(os.getenv("HEALTH_CHECK_INTERVAL", "60"))
    
    # Background Tasks Configuration
    ENABLE_BACKGROUND_TASKS: bool = os.getenv("ENABLE_BACKGROUND_TASKS", "true").lower() == "true"
    CLEANUP_TASK_INTERVAL: int = int(os.getenv("CLEANUP_TASK_INTERVAL", "300"))
    STATS_UPDATE_INTERVAL: int = int(os.getenv("STATS_UPDATE_INTERVAL", "60"))
    
    # API Configuration
    API_VERSION: str = "v1"
    DOCS_URL: Optional[str] = "/docs"
    REDOC_URL: Optional[str] = "/redoc"
    
    # WebSocket Configuration
    ENABLE_WEBSOCKET: bool = os.getenv("ENABLE_WEBSOCKET", "false").lower() == "true"
    WEBSOCKET_PATH: str = "/ws"
    
    # Backup Configuration
    ENABLE_AUTO_BACKUP: bool = os.getenv("ENABLE_AUTO_BACKUP", "false").lower() == "true"
    BACKUP_INTERVAL: int = int(os.getenv("BACKUP_INTERVAL", "86400"))
    BACKUP_PATH: str = os.getenv("BACKUP_PATH", "/var/backups/vpn")
    
    @property
    def CORS_ORIGINS_LIST(self) -> list:
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

def validate_config():
    errors = []
    
    if not settings.WG_EASY_PANEL_URL:
        errors.append("WG_EASY_PANEL_URL is required")
    
    if not settings.WG_EASY_PASSWORD:
        errors.append("WG_EASY_PASSWORD is required")
    
    if not all([settings.POSTGRES_USER, settings.POSTGRES_PASSWORD, 
                settings.POSTGRES_SERVER, settings.POSTGRES_DB]):
        errors.append("Database configuration is incomplete")
    
    if settings.SECRET_KEY == "your-secret-key-change-this-in-production":
        errors.append("SECRET_KEY must be changed from default value")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    return True

def get_config_summary():
    return {
        "database": {
            "host": settings.POSTGRES_SERVER,
            "port": settings.POSTGRES_PORT,
            "database": settings.POSTGRES_DB,
            "user": settings.POSTGRES_USER
        },
        "wg_easy": {
            "panel_url": settings.WG_EASY_PANEL_URL,
            "username": settings.WG_EASY_USERNAME,
            "dynamic_tunnels": settings.ENABLE_DYNAMIC_TUNNELS,
            "max_tunnels_per_user": settings.MAX_TUNNELS_PER_USER,
            "auto_cleanup": settings.TUNNEL_AUTO_CLEANUP
        },
        "server": {
            "host": settings.HOST,
            "port": settings.PORT,
            "debug": settings.DEBUG,
            "log_level": settings.LOG_LEVEL
        },
        "features": {
            "dynamic_tunnels": settings.ENABLE_DYNAMIC_TUNNELS,
            "background_tasks": settings.ENABLE_BACKGROUND_TASKS,
            "metrics": settings.ENABLE_METRICS,
            "websocket": settings.ENABLE_WEBSOCKET,
            "auto_backup": settings.ENABLE_AUTO_BACKUP
        }
    }