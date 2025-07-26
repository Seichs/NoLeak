#!/usr/bin/env python3
"""
Example file containing various fake secrets for testing NoLeak scanner.

This file demonstrates different types of hardcoded secrets that the scanner
should detect. All secrets in this file are fake and for testing purposes only.

WARNING: This file intentionally contains fake secrets for testing.
Do not use any of these values in real applications!
"""

import os
import requests
from typing import Dict, Any

# API Key examples - should be detected
API_KEY = "sk_live_abcd1234567890123456789012345678"
api_key = "pk_test_9876543210abcdef1234567890abcdef"
STRIPE_API_KEY = "sk_live_51234567890abcdef1234567890abcdef"

# AWS Credentials - should be detected
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
aws_session_token = "FwoGZXIvYXdzEBEaDHU0bXU3b1BQNjBWdyK2AaGVhWh5pYpNyQ=="

# Database connection strings - should be detected
DATABASE_URL = "postgres://user:password@localhost:5432/production_db"
MONGODB_URI = "mongodb://admin:secret123@cluster.mongodb.net/myapp"
mysql_connection = "mysql://root:supersecret@db.example.com:3306/app_data"

# GitHub tokens - should be detected
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"
github_personal_token = "gho_1234567890abcdef1234567890abcdef"

# JWT tokens - should be detected
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Slack tokens - should be detected
SLACK_BOT_TOKEN = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
slack_webhook = "xoxp-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz123456"

# Google API keys - should be detected
GOOGLE_API_KEY = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
google_service_key = "AIzaBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

# Twitter API credentials - should be detected
TWITTER_API_KEY = "abcdefghijklmnopqrstuvwxy"
TWITTER_ACCESS_TOKEN = "1234567890-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
twitter_bearer_token = "AAAAAAAAAAAAAAAAAAAAAA%2FAAAAAAAAAA%3DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# Email credentials - should be detected
SMTP_PASSWORD = "email_password_123"
mail_auth_token = "smtp_secret_token_456"

# Docker credentials - should be detected
DOCKER_PASSWORD = "docker_hub_secret_password"
docker_auth_token = "dckr_pat_1234567890abcdef1234567890abcdef"

# Generic passwords - should be detected
password = "super_secret_password_123"
admin_password = "admin123!@#"
user_pwd = "mySecretPassword"

# Private keys - should be detected (fake content)
private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5/example
-----END PRIVATE KEY-----"""

rsa_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1example...
-----END RSA PRIVATE KEY-----"""

# SSH private key - should be detected
ssh_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==
-----END OPENSSH PRIVATE KEY-----"""

# Certificate - should be detected (lower severity)
certificate = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAExample...
-----END CERTIFICATE-----"""

# Configuration dictionary with secrets
config = {
    "database": {
        "host": "localhost",
        "user": "admin", 
        "password": "database_secret_password",
        "connection_string": "postgres://user:secret@localhost/db"
    },
    "api": {
        "stripe_key": "sk_test_abcdefghijklmnopqrstuvwxyz123456",
        "sendgrid_api_key": "SG.abcdefghijklmnopqrstuvwxyz.1234567890abcdef",
        "jwt_secret": "my_jwt_secret_key_for_tokens"
    },
    "aws": {
        "access_key": "AKIAI44QH8DHBEXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzAMPLEKEY"
    }
}

class DatabaseConnection:
    """Example class with hardcoded credentials."""
    
    def __init__(self):
        # These should be detected
        self.username = "admin"
        self.password = "hardcoded_password_123"
        self.api_key = "app_api_key_abcdefghijklmnopqrstuvwxyz"
        
    def connect(self):
        """Connect to database with hardcoded credentials."""
        connection_url = "postgresql://user:password@db.example.com/myapp"
        # This is bad practice - credentials should come from environment
        return connection_url

def make_api_request():
    """Function with hardcoded API credentials."""
    headers = {
        "Authorization": "Bearer sk_live_1234567890abcdef1234567890abcdef",
        "X-API-Key": "api_key_abcdefghijklmnopqrstuvwxyz123456"
    }
    
    # Another example
    auth_token = "ghp_example_github_token_abcdefghijklmnopqrstuvwx"
    
    return requests.get("https://api.example.com", headers=headers)

def email_configuration():
    """Email settings with hardcoded credentials."""
    smtp_config = {
        "host": "smtp.gmail.com",
        "port": 587,
        "username": "user@example.com",
        "password": "smtp_password_secret_123",  # Should be detected
        "use_tls": True
    }
    return smtp_config

# Environment variable assignments (these might be in scripts)
os.environ["API_KEY"] = "env_api_key_1234567890abcdef"
os.environ["DATABASE_PASSWORD"] = "env_db_password_secret"

# Some false positives that should be handled carefully
# These might trigger rules but are less likely to be real secrets
example_hash = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
example_id = "user_id_1234567890"
version_string = "v1.2.3-build.1234567890"

# Base64 encoded data that might trigger rules
base64_data = "dGVzdGluZ19iYXNlNjRfZW5jb2RlZF9kYXRhX2hlcmVfMTIzNDU2Nzg5MA=="
secret_data = "YWRtaW46cGFzc3dvcmQxMjM="  # "admin:password123" encoded

if __name__ == "__main__":
    print("This file contains fake secrets for testing NoLeak scanner.")
    print("Run: noleak examples/fake_leaks.py")
    print("Expected: Multiple secret detections with various severity levels.")
