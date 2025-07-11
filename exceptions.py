from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, DatabaseError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
from datetime import datetime
from typing import Union, Dict, Any, List

logger = logging.getLogger(__name__)

class VPNException(Exception):
    def __init__(self, message: str, code: str = "VPN_ERROR", details: Dict[str, Any] = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

class AuthenticationError(VPNException):
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTH_ERROR")

class AuthorizationError(VPNException):
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, "AUTHORIZATION_ERROR")

class ValidationError(VPNException):
    def __init__(self, message: str, field: str = None):
        details = {"field": field} if field else {}
        super().__init__(message, "VALIDATION_ERROR", details)

class ResourceNotFoundError(VPNException):
    def __init__(self, resource: str, resource_id: Union[int, str] = None):
        message = f"{resource} not found"
        if resource_id:
            message += f" (ID: {resource_id})"
        super().__init__(message, "RESOURCE_NOT_FOUND", {"resource": resource, "id": resource_id})

class ResourceConflictError(VPNException):
    def __init__(self, message: str, resource: str = None):
        super().__init__(message, "RESOURCE_CONFLICT", {"resource": resource})

class ServerError(VPNException):
    def __init__(self, message: str, server_id: int = None):
        super().__init__(message, "SERVER_ERROR", {"server_id": server_id})

class PanelError(VPNException):
    def __init__(self, message: str, panel_url: str = None):
        super().__init__(message, "PANEL_ERROR", {"panel_url": panel_url})

class VPNConnectionError(VPNException):
    def __init__(self, message: str, config_id: int = None):
        super().__init__(message, "VPN_CONNECTION_ERROR", {"config_id": config_id})

class DatabaseConnectionError(VPNException):
    def __init__(self, message: str = "Database connection failed"):
        super().__init__(message, "DATABASE_ERROR")

class RateLimitError(VPNException):
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, "RATE_LIMIT_ERROR")

def create_error_response(
    status_code: int,
    message: str,
    code: str = "ERROR",
    details: Dict[str, Any] = None,
    errors: List[str] = None
) -> Dict[str, Any]:
    return {
        "status": "error",
        "message": message,
        "code": code,
        "data": None,
        "errors": errors or [],
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat()
    }

def create_validation_error_response(errors: List[Dict[str, Any]]) -> Dict[str, Any]:
    formatted_errors = []
    for error in errors:
        formatted_errors.append({
            "field": ".".join(str(loc) for loc in error.get("loc", [])),
            "message": error.get("msg", "Validation error"),
            "type": error.get("type", "validation_error"),
            "input": error.get("input")
        })
    
    return {
        "status": "error",
        "message": "Validation failed",
        "code": "VALIDATION_ERROR",
        "data": None,
        "errors": formatted_errors,
        "timestamp": datetime.utcnow().isoformat()
    }

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validation error on {request.url}: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content=create_validation_error_response(exc.errors())
    )

async def vpn_exception_handler(request: Request, exc: VPNException):
    logger.error(f"VPN error on {request.url}: {exc.message}")
    
    status_code_map = {
        "AUTH_ERROR": 401,
        "AUTHORIZATION_ERROR": 403,
        "VALIDATION_ERROR": 400,
        "RESOURCE_NOT_FOUND": 404,
        "RESOURCE_CONFLICT": 409,
        "SERVER_ERROR": 500,
        "PANEL_ERROR": 502,
        "VPN_CONNECTION_ERROR": 503,
        "DATABASE_ERROR": 500,
        "RATE_LIMIT_ERROR": 429
    }
    
    status_code = status_code_map.get(exc.code, 500)
    
    return JSONResponse(
        status_code=status_code,
        content=create_error_response(
            status_code=status_code,
            message=exc.message,
            code=exc.code,
            details=exc.details
        )
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.error(f"HTTP error on {request.url}: {exc.detail}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content=create_error_response(
            status_code=exc.status_code,
            message=exc.detail,
            code=f"HTTP_{exc.status_code}"
        )
    )

async def database_exception_handler(request: Request, exc: DatabaseError):
    logger.error(f"Database error on {request.url}: {str(exc)}")
    
    if isinstance(exc, IntegrityError):
        return JSONResponse(
            status_code=409,
            content=create_error_response(
                status_code=409,
                message="Resource already exists or constraint violation",
                code="DATABASE_CONSTRAINT_ERROR"
            )
        )
    
    return JSONResponse(
        status_code=500,
        content=create_error_response(
            status_code=500,
            message="Database operation failed",
            code="DATABASE_ERROR"
        )
    )

async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error on {request.url}: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content=create_error_response(
            status_code=500,
            message="An unexpected error occurred",
            code="INTERNAL_SERVER_ERROR"
        )
    )

def setup_exception_handlers(app):
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(VPNException, vpn_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(DatabaseError, database_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)