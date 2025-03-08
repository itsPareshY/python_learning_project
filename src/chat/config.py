import os
from typing import List, Dict
from pydantic import BaseSettings, SecretStr, validator
from datetime import timedelta

class SecuritySettings(BaseSettings):
    # API Settings
    API_KEY: SecretStr
    ALLOWED_ORIGINS: List[str]
    
    # Rate Limiting
    RATE_LIMIT: int = 5
    RATE_WINDOW: int = 60
    
    # Security Timeouts
    SESSION_TIMEOUT: int = 3600  # 1 hour
    TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS Settings
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["POST"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Model Settings
    MODEL_NAME: str = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
    
    # Security Headers
    SECURITY_HEADERS: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; connect-src 'self'",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "X-Content-Security-Policy": "default-src 'self'",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }
    
    # Input Validation
    MAX_MESSAGE_LENGTH: int = 500
    ALLOWED_CHARS_PATTERN: str = r'^[\w\s.,!?()-]+$'
    
    # Blocking Settings
    MAX_FAILED_ATTEMPTS: int = 5
    BLOCK_DURATION: timedelta = timedelta(minutes=15)
    FAILED_WINDOW: timedelta = timedelta(minutes=10)
    
    @validator('ALLOWED_ORIGINS')
    def validate_origins(cls, v):
        if not v:
            raise ValueError("At least one origin must be specified")
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = SecuritySettings()
