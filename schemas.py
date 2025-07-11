from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class StatusEnum(str, Enum):
    success = "success"
    error = "error"
    warning = "warning"

class BaseResponse(BaseModel):
    status: StatusEnum
    message: str
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=20, regex="^[a-zA-Z0-9_]+$")
    email: EmailStr

    @validator('username')
    def validate_username(cls, v):
        if not v.replace('_', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v.lower()

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=50)

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        if not any(c.isalpha() for c in v):
            raise ValueError('Password must contain at least one letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        return v

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)

class AuthResponse(BaseResponse):
    data: Optional[Dict[str, Any]] = Field(default_factory=lambda: {
        "user": None,
        "access_token": None,
        "token_type": "bearer",
        "expires_in": 3600
    })

class ServerBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=50)
    location: str = Field(..., min_length=2, max_length=50)
    endpoint: str = Field(..., regex=r'^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    port: int = Field(..., ge=1, le=65535)

class ServerCreate(ServerBase):
    pass

class ServerCreateFromPanel(BaseModel):
    panel_url: str = Field(..., regex=r'^https?://.+')
    name: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1)
    location: str = Field(default="Unknown Location", max_length=50)

    @validator('panel_url')
    def validate_panel_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Panel URL must start with http:// or https://')
        return v

class ServerResponse(ServerBase):
    id: int
    is_active: bool
    created_at: datetime
    panel_url: Optional[str] = None
    
    class Config:
        from_attributes = True

class ServerListResponse(BaseResponse):
    data: Optional[Dict[str, List[ServerResponse]]] = Field(default_factory=lambda: {"servers": []})

class ServerHealthStatus(BaseModel):
    server_id: int
    is_healthy: bool
    response_time: float
    wireguard_status: bool
    peer_count: int
    last_check: float
    error_message: Optional[str] = None
    panel_url: Optional[str] = None

class VPNConfigCreate(BaseModel):
    server_id: int = Field(..., gt=0)

class VPNConfigResponse(BaseModel):
    id: int
    server_id: int
    allocated_ip: str
    config_content: str
    is_active: bool
    created_at: datetime
    server: ServerResponse
    
    class Config:
        from_attributes = True

class VPNConfigFile(BaseModel):
    config_content: str
    qr_code: str
    server_info: Dict[str, Any]
    connection_info: Dict[str, Any]

class VPNConnectionStatus(BaseModel):
    config_id: int
    is_connected: bool
    allocated_ip: str
    bytes_sent: int = 0
    bytes_received: int = 0
    last_handshake: Optional[datetime] = None
    endpoint: Optional[str] = None
    connection_time: Optional[datetime] = None

class VPNResponse(BaseResponse):
    data: Optional[Dict[str, Any]] = None

class UsageLogResponse(BaseModel):
    id: int
    bytes_sent: int
    bytes_received: int
    last_handshake: Optional[datetime]
    session_start: datetime
    session_end: Optional[datetime]
    duration_minutes: Optional[int] = None
    
    class Config:
        from_attributes = True

class AdminUserResponse(UserResponse):
    vpn_configs: List[VPNConfigResponse] = []
    total_data_used: int = 0
    last_connection: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class ConnectionStatsResponse(BaseModel):
    total_users: int
    active_users: int
    total_servers: int
    active_servers: int
    total_connections: int
    active_connections: int
    total_data_transferred: int
    today_connections: int
    server_stats: List[Dict[str, Any]] = []

class AdminStatsResponse(BaseResponse):
    data: Optional[ConnectionStatsResponse] = None

class ErrorDetail(BaseModel):
    field: Optional[str] = None
    message: str
    code: Optional[str] = None

class ValidationErrorResponse(BaseResponse):
    status: StatusEnum = StatusEnum.error
    errors: List[ErrorDetail] = []
    
class SuccessResponse(BaseResponse):
    status: StatusEnum = StatusEnum.success

class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=10, ge=1, le=100)
    search: Optional[str] = Field(default=None, max_length=100)

class PaginatedResponse(BaseResponse):
    data: Optional[Dict[str, Any]] = Field(default_factory=lambda: {
        "items": [],
        "total": 0,
        "page": 1,
        "limit": 10,
        "pages": 0
    })