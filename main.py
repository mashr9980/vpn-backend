from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import get_db, engine
from models import Base
from routes import auth, vpn, admin, servers
from auth.jwt_handler import verify_token
import uvicorn

app = FastAPI(title="WireGuard VPN Backend", version="1.0.0")

security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(vpn.router, prefix="/vpn", tags=["VPN"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])
app.include_router(servers.router, prefix="/servers", tags=["Servers"])

@app.get("/")
async def root():
    return {"message": "WireGuard VPN Backend API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8002)