import time
from typing import Dict, List, Optional
import hashlib
import hmac
import os
from fastapi import HTTPException, Request
import ipaddress
import re
from datetime import datetime, timedelta

class SecurityMiddleware:
    def __init__(self):
        self.rate_limits: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.BLOCK_DURATION = timedelta(minutes=15)
        self.MAX_FAILED_ATTEMPTS = 5
        self.FAILED_WINDOW = timedelta(minutes=10)
        
        # Load blocked IP ranges (e.g., known malicious ranges)
        self.blocked_ranges = [
            ipaddress.ip_network('0.0.0.0/8'),      # Invalid addresses
            ipaddress.ip_network('10.0.0.0/8'),     # Private network
            ipaddress.ip_network('100.64.0.0/10'),  # Carrier-grade NAT
            ipaddress.ip_network('127.0.0.0/8'),    # Localhost
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('172.16.0.0/12'),  # Private network
            ipaddress.ip_network('192.168.0.0/16'), # Private network
            ipaddress.ip_network('224.0.0.0/4'),    # Multicast
        ]
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is in blocked list or ranges."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            # Check if IP is in blocked ranges
            for blocked_range in self.blocked_ranges:
                if ip_addr in blocked_range:
                    return True
            
            # Check temporary blocks
            if ip in self.blocked_ips:
                if datetime.now() < self.blocked_ips[ip]:
                    return True
                else:
                    del self.blocked_ips[ip]
            return False
        except ValueError:
            return True  # Block invalid IP addresses

    def record_failed_attempt(self, ip: str):
        """Record failed authentication attempt."""
        now = datetime.now()
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        
        # Clean old attempts
        self.failed_attempts[ip] = [
            attempt for attempt in self.failed_attempts[ip]
            if now - attempt < self.FAILED_WINDOW
        ]
        
        self.failed_attempts[ip].append(now)
        
        # Check if should block
        if len(self.failed_attempts[ip]) >= self.MAX_FAILED_ATTEMPTS:
            self.blocked_ips[ip] = now + self.BLOCK_DURATION
            del self.failed_attempts[ip]

    def verify_request_signature(self, request: Request, api_key: str) -> bool:
        """Verify request signature using HMAC."""
        if 'X-Request-Signature' not in request.headers:
            return False
            
        timestamp = request.headers.get('X-Timestamp')
        if not timestamp:
            return False
            
        # Check timestamp freshness (5 minutes)
        try:
            req_time = datetime.fromtimestamp(float(timestamp))
            if abs((datetime.now() - req_time).total_seconds()) > 300:
                return False
        except ValueError:
            return False
            
        # Reconstruct signature
        body = await request.body()
        message = f"{timestamp}{body.decode()}"
        expected_signature = hmac.new(
            api_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(
            expected_signature.encode(),
            request.headers['X-Request-Signature'].encode()
        )

    def sanitize_input(self, text: str) -> str:
        """Sanitize user input."""
        # Remove any HTML/script tags
        text = re.sub(r'<[^>]*>', '', text)
        
        # Remove potential SQL injection patterns
        text = re.sub(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)', '', text, flags=re.IGNORECASE)
        
        # Remove special characters
        text = re.sub(r'[^\w\s.,!?()-]', '', text)
        
        return text.strip()

    def validate_input(self, text: str, max_length: int = 500) -> bool:
        """Validate user input."""
        if not text or len(text) > max_length:
            return False
            
        # Check for common attack patterns
        suspicious_patterns = [
            r'(?i)script',
            r'(?i)alert\s*\(',
            r'(?i)eval\s*\(',
            r'(?i)function\s*\(',
            r'(?i)document\.',
            r'(?i)window\.',
            r'(?i)localStorage',
            r'(?i)sessionStorage',
            r'(?i)cookie',
            r'(?i)xhr',
            r'(?i)fetch',
            r'(?i)ajax',
            r'(?i)src=',
            r'(?i)href=',
            r'(?i)data:',
            r'(?i)base64',
        ]
        
        return not any(re.search(pattern, text) for pattern in suspicious_patterns)

security = SecurityMiddleware()
