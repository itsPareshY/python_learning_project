Need to fix chat functionality in this folder.

#File Structure to be made:

personal-website/
├── .git/
├── .gitignore
├── README.md
├── api/
│   ├── chatbot.py        # Python chatbot backend
│   └── run_server.bat    # Server startup script
├── images/
│   └── favicon.svg       # Website favicon
├── index.html           # Main HTML file
├── requirements.txt     # Python dependencies
├── script.js           # Frontend JavaScript
└── styles.css          # CSS styles

Security improvements made:

1. Backend (chatbot.py):
- Added API key authentication
- Environment variables for sensitive data
- Strict CORS policy with specific origins
- Enhanced security headers
- Input validation and sanitization
- Rate limiting improvements
- Secure response handling
2. Frontend (script.js):
    - Added API key handling
    - Enhanced input validation
    - Better rate limiting
    - XSS protection
    - Secure message handling
    - Error handling improvements
3. HTML:
    - Added Content Security Policy
    - Security headers
    - Input restrictions
    - ARIA attributes for accessibility
    - Secure resource loading
4. General:
    - Added .env for configuration
    - Improved error handling
    - Rate limiting on both frontend and backend
    - Input sanitization on both ends
    - Secure data transmission

To complete the setup:
1. Create a .env file with your actual API key
2. Update the API key in the frontend JavaScript
3. Consider using HTTPS in production
4. Regularly update dependencies for security 

Additional security improvements made:

1. Added comprehensive security middleware:
    - IP blocking for suspicious activity
    - Request signature verification
    - Advanced input validation and sanitization
    - Protection against common attack patterns
2. Enhanced configuration management:
        - Centralized security settings
    - Environment-based configuration
    - Strict validation of settings
3. Improved API security:
    - HMAC-based API key verification
    - Request timestamp validation
    - Comprehensive security headers
    - Strict CORS policy
4. Added security audit capabilities:
    - Dependency vulnerability scanning
    - Code security scanning with Bandit
    - Sensitive file detection
    - Audit logging
5. Enhanced input/output security:
    - Advanced input sanitization
    - Pattern-based attack detection
    - Secure response formatting
    - Prevention of information disclosure

To use these enhancements:

1. Create a secure .env file with your settings
2. Install the updated requirements: pip install -r requirements.txt
3. Run the security audit: python security_audit.py
4. Review and address any security findings