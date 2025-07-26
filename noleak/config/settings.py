"""Configuration settings and constants for NoLeak scanner."""

import os
from pathlib import Path
from typing import Set, Dict, Any

# Application metadata
APP_NAME = "NoLeak"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "A DevSecOps tool for scanning hardcoded secrets in source code"

# Exit codes
EXIT_SUCCESS = 0
EXIT_LEAKS_FOUND = 1
EXIT_ERROR = 2

# Supported file extensions for scanning
DEFAULT_SUPPORTED_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".c", ".cpp", ".cc", ".cxx",
    ".go", ".rs", ".php", ".rb", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".zsh",
    ".env", ".yaml", ".yml", ".json", ".xml",
    ".ini", ".conf", ".config", ".cfg",
    ".sql", ".dockerfile", ".tf", ".hcl"
}

# Files and directories to exclude by default
DEFAULT_EXCLUDED_PATTERNS: Set[str] = {
    ".git", ".svn", ".hg", ".bzr",
    "__pycache__", ".pytest_cache", ".tox",
    "node_modules", ".npm", ".yarn",
    ".venv", "venv", "env",
    "build", "dist", "target", "out",
    ".idea", ".vscode", ".vs",
    "*.pyc", "*.pyo", "*.egg-info",
    "*.log", "*.tmp", "*.temp"
}

# Maximum file size to scan (in bytes) to prevent memory issues
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

# Default output settings
DEFAULT_OUTPUT_FORMAT = "console"
SUPPORTED_OUTPUT_FORMATS = {"console", "json"}

# Built-in rules configuration
BUILTIN_RULES_ENABLED = True
RULE_SEVERITY_LEVELS = {"low", "medium", "high", "critical"}

# Performance settings
MAX_CONCURRENT_FILES = 50
CHUNK_SIZE_BYTES = 1024 * 1024  # 1MB chunks for large files

def get_project_root() -> Path:
    """Get the project root directory.
    
    Returns:
        Path object pointing to the project root.
    """
    return Path(__file__).parent.parent.parent

def get_builtin_rules_path() -> Path:
    """Get the path to built-in rules directory.
    
    Returns:
        Path object pointing to the built-in rules directory.
    """
    return Path(__file__).parent.parent / "rules"

def get_default_config() -> Dict[str, Any]:
    """Get default configuration dictionary.
    
    Returns:
        Dictionary containing default configuration values.
    """
    return {
        "supported_extensions": DEFAULT_SUPPORTED_EXTENSIONS.copy(),
        "excluded_patterns": DEFAULT_EXCLUDED_PATTERNS.copy(),
        "max_file_size": MAX_FILE_SIZE_BYTES,
        "output_format": DEFAULT_OUTPUT_FORMAT,
        "builtin_rules_enabled": BUILTIN_RULES_ENABLED,
        "max_concurrent_files": MAX_CONCURRENT_FILES,
        "chunk_size": CHUNK_SIZE_BYTES,
    }

class ScannerConfig:
    """Configuration class for scanner settings."""
    
    def __init__(self, **kwargs) -> None:
        """Initialize scanner configuration.
        
        Args:
            **kwargs: Configuration overrides.
        """
        default_config = get_default_config()
        default_config.update(kwargs)
        
        self.supported_extensions: Set[str] = set(default_config["supported_extensions"])
        self.excluded_patterns: Set[str] = set(default_config["excluded_patterns"])
        self.max_file_size: int = default_config["max_file_size"]
        self.output_format: str = default_config["output_format"]
        self.builtin_rules_enabled: bool = default_config["builtin_rules_enabled"]
        self.max_concurrent_files: int = default_config["max_concurrent_files"]
        self.chunk_size: int = default_config["chunk_size"]
        
    def validate(self) -> None:
        """Validate configuration values.
        
        Raises:
            ValueError: If configuration values are invalid.
        """
        if self.output_format not in SUPPORTED_OUTPUT_FORMATS:
            raise ValueError(f"Unsupported output format: {self.output_format}")
        
        if self.max_file_size <= 0:
            raise ValueError("Max file size must be positive")
        
        if self.max_concurrent_files <= 0:
            raise ValueError("Max concurrent files must be positive")
        
        if self.chunk_size <= 0:
            raise ValueError("Chunk size must be positive")
