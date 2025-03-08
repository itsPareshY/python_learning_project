import subprocess
import sys
import os
import json
from datetime import datetime

# Run security checks on the codebase
def run_security_checks():
    """Run security checks on the codebase."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "checks": []
    }
    
    # Check Python dependencies for vulnerabilities
    print("Checking dependencies for vulnerabilities...")
    try:
        subprocess.run(["safety", "check"], check=True)
        results["checks"].append({
            "name": "dependency_check",
            "status": "passed"
        })
    except subprocess.CalledProcessError:
        results["checks"].append({
            "name": "dependency_check",
            "status": "failed",
            "message": "Vulnerabilities found in dependencies"
        })
    
    # Run Bandit for security issues
    print("Running Bandit security scanner...")
    try:
        subprocess.run(["bandit", "-r", "."], check=True)
        results["checks"].append({
            "name": "bandit_scan",
            "status": "passed"
        })
    except subprocess.CalledProcessError:
        results["checks"].append({
            "name": "bandit_scan",
            "status": "failed",
            "message": "Security issues found in code"
        })
    
    # Check for sensitive files
    print("Checking for sensitive files...")
    sensitive_patterns = [
        ".env",
        "*.key",
        "*.pem",
        "*.cert",
        "password",
        "secret"
    ]
    
    found_sensitive = []
    for root, dirs, files in os.walk("."):
        for pattern in sensitive_patterns:
            for file in files:
                if pattern in file.lower():
                    found_sensitive.append(os.path.join(root, file))
    
    if found_sensitive:
        results["checks"].append({
            "name": "sensitive_files",
            "status": "warning",
            "message": f"Found potentially sensitive files: {found_sensitive}"
        })
    else:
        results["checks"].append({
            "name": "sensitive_files",
            "status": "passed"
        })
    
    # Save results
    with open("security_audit_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nSecurity audit complete. Results saved to security_audit_results.json")
    return results

if __name__ == "__main__":
    run_security_checks()
