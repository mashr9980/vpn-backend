from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # Using your existing database credentials
    POSTGRES_USER: str = os.getenv("DB_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("DB_PASSWORD", "123")
    POSTGRES_SERVER: str = os.getenv("DB_HOST", "localhost")
    POSTGRES_PORT: str = os.getenv("DB_PORT", "5432")
    POSTGRES_DB: str = os.getenv("DB_NAME", "vpn_db")
    DATABASE_URL: str = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}:{POSTGRES_PORT}/{POSTGRES_DB}"

    SECRET_KEY: str = "your-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    WIREGUARD_CONFIG_PATH: str = "/etc/wireguard"
    WIREGUARD_INTERFACE: str = "wg0"
    VPN_SUBNET: str = "10.8.0.0/24"
    VPN_DNS: str = "1.1.1.1"
    
    class Config:
        env_file = ".env"

settings = Settings()