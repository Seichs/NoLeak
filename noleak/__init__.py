"""NoLeak: A DevSecOps tool for scanning hardcoded secrets in source code.

NoLeak is a professional-grade secret scanner designed to detect hardcoded
credentials, API keys, tokens, and other sensitive information in source code.
It uses advanced regex patterns to identify potential security vulnerabilities
before they reach production.

Key Features:
- Built-in rules for common secret patterns
- Support for custom rules via YAML files
- Multiple output formats (console, JSON, SARIF)
- Concurrent scanning for performance
- Professional CLI interface
- Extensible architecture

Example usage:
    import noleak
    
    # Create a scanner with default configuration
    scanner = noleak.create_scanner()
    
    # Scan a directory
    result = scanner.scan_path("/path/to/project")
    
    # Check for secrets
    if result.matches:
        print(f"Found {len(result.matches)} potential secrets!")
"""

from .config.settings import APP_NAME, APP_VERSION, APP_DESCRIPTION
from .core.scanner import SecretScanner, create_scanner, ScanResult, ScanStats
from .core.matcher import Match, PatternMatcher, MatchFilter
from .rules.loader import RuleLoader, create_default_loader
from .output.console import ConsoleFormatter, MinimalConsoleFormatter
from .output.json_export import JSONFormatter, SARIFFormatter, CompactJSONFormatter

# Package metadata
__title__ = APP_NAME
__version__ = APP_VERSION
__description__ = APP_DESCRIPTION
__author__ = "NoLeak Team"
__email__ = "security@noleak.dev"
__license__ = "MIT"
__url__ = "https://github.com/Seichs/NoLeak"

# Version tuple for programmatic access
VERSION = tuple(map(int, __version__.split('.')))

# Main exports for public API
__all__ = [
    # Core classes
    "SecretScanner",
    "Match", 
    "ScanResult",
    "ScanStats",
    
    # Factory functions
    "create_scanner",
    "create_default_loader",
    
    # Rule management
    "RuleLoader",
    
    # Pattern matching
    "PatternMatcher",
    "MatchFilter",
    
    # Output formatters
    "ConsoleFormatter",
    "MinimalConsoleFormatter", 
    "JSONFormatter",
    "SARIFFormatter",
    "CompactJSONFormatter",
    
    # Package metadata
    "__version__",
    "__title__",
    "__description__",
    "__author__",
    "__email__",
    "__license__",
    "__url__",
    "VERSION",
]


def scan_text(text: str, source_name: str = "<text>") -> list:
    """Convenience function to scan text content for secrets.
    
    This is a simple wrapper around the scanner for quick text scanning.
    
    Args:
        text: Text content to scan for secrets.
        source_name: Name to use for the source in results.
        
    Returns:
        List of Match objects for detected secrets.
        
    Example:
        >>> import noleak
        >>> matches = noleak.scan_text('api_key = "secret123"')
        >>> if matches:
        ...     print(f"Found {len(matches)} secrets")
    """
    scanner = create_scanner()
    return scanner.scan_text(text, source_name)


def scan_file(file_path: str) -> list:
    """Convenience function to scan a single file for secrets.
    
    Args:
        file_path: Path to the file to scan.
        
    Returns:
        List of Match objects for detected secrets.
        
    Example:
        >>> import noleak
        >>> matches = noleak.scan_file("config.py")
        >>> if matches:
        ...     print(f"Found secrets in {file_path}")
    """
    scanner = create_scanner()
    result = scanner.scan_path(file_path)
    return result.matches


# Add convenience functions to exports
__all__.extend(["scan_text", "scan_file"])
