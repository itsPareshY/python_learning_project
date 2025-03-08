import os
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, SecretStr
from transformers import pipeline
import torch
import asyncio
from typing import Dict, Optional, List
import time
import hashlib
from dotenv import load_dotenv

from .security import security
from .config import settings

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Chatbot API",
             description="Secure chatbot API for personal website",
             version="1.0.0")

# Add CORS middleware with specific origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
    expose_headers=list(settings.SECURITY_HEADERS.keys())
)

# Security settings
API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "message": "Hello, how are you?",
                "conversation_id": "optional-conversation-id"
            }
        }

class ChatResponse(BaseModel):
    message: str
    conversation_id: str

async def verify_api_key(api_key: str = Depends(API_KEY_HEADER)):
    """Verify API key and check for potential security threats."""
    if not hmac.compare_digest(api_key, settings.API_KEY.get_secret_value()):
        security.record_failed_attempt(request.client.host)
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    return api_key

@app.on_event("startup")
async def startup_event():
    """Initialize the model and security settings."""
    global generator
    generator = pipeline('text-generation',
                        model=settings.MODEL_NAME,
                        torch_dtype=torch.float32,
                        device='cpu')

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Add security headers and perform security checks."""
    # Check if IP is blocked
    if security.is_ip_blocked(request.client.host):
        return JSONResponse(
            status_code=403,
            content={"detail": "Access denied"}
        )
    
    # Add security headers
    response = await call_next(request)
    response.headers.update(settings.SECURITY_HEADERS)
    
    return response

@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(verify_api_key)])
async def chat_endpoint(request: Request, chat_request: ChatRequest):
    """Handle chat requests with enhanced security measures."""
    client_ip = request.client.host
    
    try:
        # Validate and sanitize input
        message = security.sanitize_input(chat_request.message)
        if not security.validate_input(message, settings.MAX_MESSAGE_LENGTH):
            raise HTTPException(
                status_code=400,
                detail="Invalid message content"
            )
        
        # Generate conversation ID if not provided
        conversation_id = chat_request.conversation_id or hashlib.sha256(
            f"{client_ip}-{time.time()}".encode()
        ).hexdigest()
        
        # Prepare prompt with security context
        prompt = f"""<|system|>You are a helpful assistant for Paresh's personal website. 
        Be concise and professional in your responses. Never disclose sensitive information.
        Avoid any potentially harmful or malicious content."""
        
        # Get response from the model and clean it
        response = clean_response(generator.generate(prompt)[0]['generated_text'])
        
        return ChatResponse(message=response, conversation_id=conversation_id)
    except Exception as e:
        # Log the error and return a generic error message
        print(f"Error in chat endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request."
        )

def clean_response(response: str) -> str:
    """Clean and format the model's response."""
    response = (
        response
            .replace('<|system|>', '')
            .replace('<|assistant|>', '')
            .replace('\n\n', '\n')
            .strip()
    )
    return response