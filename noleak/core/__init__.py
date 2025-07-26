"""Core scanning engine package for NoLeak."""

from .scanner import SecretScanner, create_scanner, ScanResult, ScanStats
from .matcher import Match, PatternMatcher, MatchFilter
from .file_loader import FileLoader

__all__ = [
    "SecretScanner",
    "create_scanner", 
    "ScanResult",
    "ScanStats",
    "Match",
    "PatternMatcher",
    "MatchFilter", 
    "FileLoader"
]
