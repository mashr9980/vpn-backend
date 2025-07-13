from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import UserCreate, UserLogin, AuthResponse, UserResponse, SuccessResponse
from models import User
from auth.password import hash_password, verify_password
from auth.jwt_handler import create_access_token
from exceptions import AuthenticationError, ValidationError, ResourceConflictError
from datetime import timedelta, datetime
from config import settings
import logging
from dependencies import get_current_user
from models import VPNConfig, UsageLog

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.username == user_data.username.lower()).first()
        if existing_user:
            raise ResourceConflictError("Username already exists", "user")
        
        existing_email = db.query(User).filter(User.email == user_data.email.lower()).first()
        if existing_email:
            raise ResourceConflictError("Email already registered", "email")
        
        hashed_password = hash_password(user_data.password)
        new_user = User(
            username=user_data.username.lower(),
            email=user_data.email.lower(),
            hashed_password=hashed_password,
            is_active=True,
            is_admin=False
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": new_user.username}, 
            expires_delta=access_token_expires
        )
        
        user_response = UserResponse(
            id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            is_active=new_user.is_active,
            is_admin=new_user.is_admin,
            created_at=new_user.created_at
        )
        
        logger.info(f"New user registered: {new_user.username}")
        
        return AuthResponse(
            status="success",
            message="User registered successfully",
            data={
                "user": user_response.dict(),
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
        )
        
    except (ResourceConflictError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.rollback()
        raise Exception("Registration failed. Please try again.")

@router.post("/login", response_model=AuthResponse)
async def login_user(credentials: UserLogin, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == credentials.username.lower()).first()
        
        if not user:
            raise AuthenticationError("Invalid username or password")
        
        if not verify_password(credentials.password, user.hashed_password):
            raise AuthenticationError("Invalid username or password")
        
        if not user.is_active:
            raise AuthenticationError("Account is deactivated. Please contact support.")
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, 
            expires_delta=access_token_expires
        )
        
        user_response = UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            is_active=user.is_active,
            is_admin=user.is_admin,
            created_at=user.created_at
        )
        
        logger.info(f"User logged in: {user.username}")
        
        return AuthResponse(
            status="success",
            message="Login successful",
            data={
                "user": user_response.dict(),
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
        )
        
    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise Exception("Login failed. Please try again.")

@router.post("/logout", response_model=SuccessResponse)
async def logout_user(current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"User logged out: {current_user.username}")
        
        return SuccessResponse(
            status="success",
            message="Logout successful",
            data={"logged_out_at": datetime.utcnow().isoformat()}
        )
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise Exception("Logout failed. Please try again.")

@router.get("/me", response_model=AuthResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        from sqlalchemy import func
        
        vpn_configs_count = db.query(VPNConfig).filter(
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        ).count()
        
        total_usage_logs = db.query(UsageLog).filter(UsageLog.user_id == current_user.id).count()
        
        latest_usage = db.query(UsageLog).filter(
            UsageLog.user_id == current_user.id
        ).order_by(UsageLog.session_start.desc()).first()
        
        total_bytes_sent = db.query(func.sum(UsageLog.bytes_sent)).filter(
            UsageLog.user_id == current_user.id
        ).scalar() or 0
        
        total_bytes_received = db.query(func.sum(UsageLog.bytes_received)).filter(
            UsageLog.user_id == current_user.id
        ).scalar() or 0
        
        user_data = {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "is_active": current_user.is_active,
            "is_admin": current_user.is_admin,
            "created_at": current_user.created_at.isoformat(),
            "vpn_stats": {
                "active_configs": vpn_configs_count,
                "total_sessions": total_usage_logs,
                "total_bytes_sent": total_bytes_sent,
                "total_bytes_received": total_bytes_received,
                "total_data_used": total_bytes_sent + total_bytes_received,
                "last_connection": latest_usage.session_start.isoformat() if latest_usage else None
            }
        }
        
        return AuthResponse(
            status="success",
            message="User information retrieved successfully",
            data={
                "user": user_data,
                "access_token": None,
                "token_type": "bearer",
                "expires_in": None
            }
        )
        
    except Exception as e:
        logger.error(f"Get user info error: {str(e)}")
        raise Exception("Failed to retrieve user information.")

@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(current_user: User = Depends(get_current_user)):
    try:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": current_user.username}, 
            expires_delta=access_token_expires
        )
        
        user_response = UserResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            is_active=current_user.is_active,
            is_admin=current_user.is_admin,
            created_at=current_user.created_at
        )
        
        logger.info(f"Token refreshed for user: {current_user.username}")
        
        return AuthResponse(
            status="success",
            message="Token refreshed successfully",
            data={
                "user": user_response.dict(),
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
        )
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise Exception("Token refresh failed. Please login again.")