"""Built-in regex rules for detecting common secrets and credentials."""

import re
from typing import Dict, List, Any

# Rule structure: name, description, pattern, severity, enabled
BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "id": "generic_api_key",
        "name": "Generic API Key",
        "description": "Detects generic API key patterns",
        "pattern": r"(?i)(?:api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "api_key = 'sk_live_abcd1234567890123456'",
            "API-KEY: abc123xyz789",
            'apikey="very_long_secret_key_12345"'
        ]
    },
    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "description": "Detects AWS Access Key IDs",
        "pattern": r"(?i)(?:aws[_-]?access[_-]?key[_-]?id|AKIA[0-9A-Z]{16})",
        "severity": "critical",
        "enabled": True,
        "test_cases": [
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "aws-access-key-id: AKIAI44QH8DHBEXAMPLE"
        ]
    },
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Access Key",
        "description": "Detects AWS Secret Access Keys",
        "pattern": r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+]{40})['\"]?",
        "severity": "critical",
        "enabled": True,
        "test_cases": [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            'aws_secret_key: "abcd1234567890abcd1234567890abcd12345678"'
        ]
    },
    {
        "id": "aws_session_token",
        "name": "AWS Session Token",
        "description": "Detects AWS temporary session tokens",
        "pattern": r"(?i)aws[_-]?session[_-]?token\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{100,})['\"]?",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "AWS_SESSION_TOKEN=FwoGZXIvYXdzEBEaDHU0bXU3b1BQNjBWdyK2AaGVhWh5pYpNyQ=="
        ]
    },
    {
        "id": "jwt_token",
        "name": "JWT Token",
        "description": "Detects JSON Web Tokens",
        "pattern": r"\b(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)\b",
        "severity": "medium",
        "enabled": True,
        "test_cases": [
            "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ]
    },
    {
        "id": "github_token",
        "name": "GitHub Token",
        "description": "Detects GitHub personal access tokens",
        "pattern": r"(?i)(?:github[_-]?token|gh[po]_[a-zA-Z0-9]{36})",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456",
            "github-token: gho_1234567890abcdef1234567890abcdef"
        ]
    },
    {
        "id": "slack_token",
        "name": "Slack Token",
        "description": "Detects Slack API tokens",
        "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "SLACK_TOKEN=xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
        ]
    },
    {
        "id": "google_api_key",
        "name": "Google API Key",
        "description": "Detects Google API keys",
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "GOOGLE_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
        ]
    },
    {
        "id": "stripe_api_key",
        "name": "Stripe API Key",
        "description": "Detects Stripe API keys",
        "pattern": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "enabled": True,
        "test_cases": [
            "STRIPE_SECRET_KEY=sk_test_abcdefghijklmnopqrstuvwxyz123456",
            "stripe_key = sk_live_1234567890abcdef1234567890abcdef"
        ]
    },
    {
        "id": "twitter_api_key",
        "name": "Twitter API Key",
        "description": "Detects Twitter API keys and tokens",
        "pattern": r"(?i)(?:twitter[_-]?(?:api[_-]?key|access[_-]?token|bearer[_-]?token))\s*[:=]\s*['\"]?([a-zA-Z0-9]{25,})['\"]?",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "TWITTER_API_KEY=abcdefghijklmnopqrstuvwxy",
            "twitter_access_token: 1234567890-abcdefghijklmnopqrstuvwxyz"
        ]
    },
    {
        "id": "password_assignment",
        "name": "Password Assignment",
        "description": "Detects password assignments in code",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        "severity": "medium",
        "enabled": True,
        "test_cases": [
            'password = "mySecretPassword123"',
            "passwd: 'admin123'",
            "PWD=\"super_secret_password\""
        ]
    },
    {
        "id": "database_connection",
        "name": "Database Connection String",
        "description": "Detects database connection strings with credentials",
        "pattern": r"(?i)(?:postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+",
        "severity": "critical",
        "enabled": True,
        "test_cases": [
            "postgres://user:password@localhost:5432/dbname",
            "mysql://admin:secret123@db.example.com:3306/production"
        ]
    },
    {
        "id": "private_key",
        "name": "Private Key",
        "description": "Detects private key files and content",
        "pattern": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "severity": "critical",
        "enabled": True,
        "test_cases": [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----"
        ]
    },
    {
        "id": "ssh_private_key",
        "name": "SSH Private Key",
        "description": "Detects SSH private keys",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "critical",
        "enabled": True,
        "test_cases": [
            "-----BEGIN OPENSSH PRIVATE KEY-----"
        ]
    },
    {
        "id": "certificate",
        "name": "Certificate",
        "description": "Detects certificate content",
        "pattern": r"-----BEGIN CERTIFICATE-----",
        "severity": "low",
        "enabled": True,
        "test_cases": [
            "-----BEGIN CERTIFICATE-----"
        ]
    },
    {
        "id": "docker_auth",
        "name": "Docker Auth",
        "description": "Detects Docker authentication configurations",
        "pattern": r"(?i)(?:docker[_-]?(?:password|token|auth))\s*[:=]\s*['\"]?([a-zA-Z0-9_\-+=./]{20,})['\"]?",
        "severity": "high",
        "enabled": True,
        "test_cases": [
            "DOCKER_PASSWORD=mySecretDockerPassword123",
            "docker_auth_token: abcd1234567890"
        ]
    },
    {
        "id": "generic_secret",
        "name": "Generic Secret",
        "description": "Detects generic secret patterns",
        "pattern": r"(?i)(?:secret|token|key|credential|auth)\s*[:=]\s*['\"]([a-zA-Z0-9_\-+=./]{16,})['\"]",
        "severity": "medium",
        "enabled": False,  # Disabled by default due to potential false positives
        "test_cases": [
            'secret = "very_long_secret_value_12345"',
            "auth_token: 'abcdefghijklmnopqrstuvwxyz'"
        ]
    },
    {
        "id": "base64_encoded",
        "name": "Base64 Encoded Data",
        "description": "Detects potential base64 encoded secrets",
        "pattern": r"(?i)(?:secret|token|key|password|auth)[_-]?(?:data|value)?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{50,}={0,2})['\"]?",
        "severity": "low",
        "enabled": False,  # Disabled by default due to potential false positives
        "test_cases": [
            "secret_data = dGVzdGluZ19iYXNlNjRfZW5jb2RlZF9kYXRhX2hlcmVfMTIzNDU2Nzg5MA=="
        ]
    },
    {
        "id": "email_credentials",
        "name": "Email Credentials",
        "description": "Detects email service credentials",
        "pattern": r"(?i)(?:smtp[_-]?(?:password|user|auth)|mail[_-]?(?:password|auth))\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        "severity": "medium",
        "enabled": True,
        "test_cases": [
            'smtp_password = "emailSecret123"',
            "mail_auth: 'smtp_credentials'"
        ]
    },
    {
        "id": "ftp_credentials",
        "name": "FTP Credentials",
        "description": "Detects FTP credentials",
        "pattern": r"(?i)ftp://[^:]+:[^@]+@[^/]+",
        "severity": "medium",
        "enabled": True,
        "test_cases": [
            "ftp://username:password@ftp.example.com"
        ]
    }
]


def get_builtin_rules() -> List[Dict[str, Any]]:
    """Get all built-in rules.
    
    Returns:
        List of rule dictionaries.
    """
    return BUILTIN_RULES.copy()


def get_enabled_builtin_rules() -> List[Dict[str, Any]]:
    """Get only enabled built-in rules.
    
    Returns:
        List of enabled rule dictionaries.
    """
    return [rule for rule in BUILTIN_RULES if rule.get("enabled", True)]


def get_rule_by_id(rule_id: str) -> Dict[str, Any]:
    """Get a specific rule by its ID.
    
    Args:
        rule_id: The rule ID to search for.
        
    Returns:
        Rule dictionary if found.
        
    Raises:
        KeyError: If the rule ID is not found.
    """
    for rule in BUILTIN_RULES:
        if rule["id"] == rule_id:
            return rule.copy()
    raise KeyError(f"Rule not found: {rule_id}")


def validate_rule(rule: Dict[str, Any]) -> bool:
    """Validate a rule dictionary structure.
    
    Args:
        rule: Rule dictionary to validate.
        
    Returns:
        True if the rule is valid.
        
    Raises:
        ValueError: If the rule structure is invalid.
    """
    required_fields = ["id", "name", "description", "pattern", "severity"]
    
    for field in required_fields:
        if field not in rule:
            raise ValueError(f"Missing required field: {field}")
    
    if not isinstance(rule["pattern"], str):
        raise ValueError("Pattern must be a string")
    
    if rule["severity"] not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"Invalid severity level: {rule['severity']}")
    
    # Test if the regex pattern compiles
    try:
        re.compile(rule["pattern"])
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")
    
    return True


def test_builtin_rules() -> Dict[str, bool]:
    """Test all built-in rules against their test cases.
    
    Returns:
        Dictionary mapping rule IDs to test results.
    """
    results = {}
    
    for rule in BUILTIN_RULES:
        rule_id = rule["id"]
        pattern = re.compile(rule["pattern"])
        test_cases = rule.get("test_cases", [])
        
        if not test_cases:
            results[rule_id] = True
            continue
        
        # Test if the pattern matches all test cases
        all_passed = True
        for test_case in test_cases:
            if not pattern.search(test_case):
                all_passed = False
                break
        
        results[rule_id] = all_passed
    
    return results
