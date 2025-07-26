"""Base formatter and formatting utilities for scan results."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.matcher import Match
from ..core.scanner import ScanResult, ScanStats


class BaseFormatter(ABC):
    """Abstract base class for output formatters."""
    
    @abstractmethod
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format a list of matches for output.
        
        Args:
            matches: List of Match objects to format.
            base_path: Base path for relative path display.
            
        Returns:
            Formatted string representation of the matches.
        """
        pass
    
    @abstractmethod
    def format_stats(self, stats: ScanStats) -> str:
        """Format scan statistics for output.
        
        Args:
            stats: ScanStats object to format.
            
        Returns:
            Formatted string representation of the statistics.
        """
        pass
    
    @abstractmethod
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format a complete scan result for output.
        
        Args:
            result: ScanResult object to format.
            base_path: Base path for relative path display.
            
        Returns:
            Formatted string representation of the result.
        """
        pass


class MatchGrouper:
    """Utility class for grouping and organizing matches."""
    
    @staticmethod
    def group_by_file(matches: List[Match]) -> Dict[str, List[Match]]:
        """Group matches by file path.
        
        Args:
            matches: List of matches to group.
            
        Returns:
            Dictionary mapping file paths to lists of matches.
        """
        grouped = {}
        for match in matches:
            file_path = str(match.file_path)
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(match)
        return grouped
    
    @staticmethod
    def group_by_severity(matches: List[Match]) -> Dict[str, List[Match]]:
        """Group matches by severity level.
        
        Args:
            matches: List of matches to group.
            
        Returns:
            Dictionary mapping severity levels to lists of matches.
        """
        grouped = {}
        for match in matches:
            severity = match.severity
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(match)
        return grouped
    
    @staticmethod
    def group_by_rule(matches: List[Match]) -> Dict[str, List[Match]]:
        """Group matches by rule ID.
        
        Args:
            matches: List of matches to group.
            
        Returns:
            Dictionary mapping rule IDs to lists of matches.
        """
        grouped = {}
        for match in matches:
            rule_id = match.rule_id
            if rule_id not in grouped:
                grouped[rule_id] = []
            grouped[rule_id].append(match)
        return grouped


class FormattingUtils:
    """Utility functions for formatting output."""
    
    @staticmethod
    def get_relative_path(file_path: Path, base_path: Optional[Path]) -> str:
        """Get a relative path for display purposes.
        
        Args:
            file_path: The file path to format.
            base_path: Base path to make it relative to.
            
        Returns:
            Relative path string if possible, absolute path otherwise.
        """
        if base_path:
            try:
                return str(file_path.relative_to(base_path))
            except ValueError:
                pass
        return str(file_path)
    
    @staticmethod
    def truncate_text(text: str, max_length: int = 100) -> str:
        """Truncate text to a maximum length with ellipsis.
        
        Args:
            text: Text to truncate.
            max_length: Maximum length before truncation.
            
        Returns:
            Truncated text with ellipsis if needed.
        """
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."
    
    @staticmethod
    def highlight_match(line: str, start: int, end: int, highlight_char: str = "^") -> str:
        """Create a highlight line showing where a match occurred.
        
        Args:
            line: The original line content.
            start: Start position of the match.
            end: End position of the match.
            highlight_char: Character to use for highlighting.
            
        Returns:
            Formatted highlight line.
        """
        # Create a line with spaces and highlight characters
        highlight_line = " " * len(line)
        if 0 <= start < len(line) and 0 <= end <= len(line):
            highlight_list = list(highlight_line)
            for i in range(start, min(end, len(line))):
                highlight_list[i] = highlight_char
            highlight_line = "".join(highlight_list)
        
        return highlight_line.rstrip()
    
    @staticmethod
    def format_file_path(file_path: Path, base_path: Optional[Path] = None) -> str:
        """Format a file path for display.
        
        Args:
            file_path: Path to format.
            base_path: Base path for relative display.
            
        Returns:
            Formatted file path string.
        """
        display_path = FormattingUtils.get_relative_path(file_path, base_path)
        return display_path
    
    @staticmethod
    def format_severity(severity: str) -> str:
        """Format severity level for display.
        
        Args:
            severity: Severity level to format.
            
        Returns:
            Formatted severity string.
        """
        severity_symbols = {
            "low": "[L]",
            "medium": "[M]", 
            "high": "[H]",
            "critical": "[C]"
        }
        return severity_symbols.get(severity.lower(), f"[{severity.upper()}]")
    
    @staticmethod
    def format_line_number(line_number: int, max_line_number: int = 9999) -> str:
        """Format line number with consistent width.
        
        Args:
            line_number: Line number to format.
            max_line_number: Maximum line number for width calculation.
            
        Returns:
            Formatted line number string.
        """
        width = len(str(max_line_number))
        return f"{line_number:>{width}}"
    
    @staticmethod
    def sanitize_output(text: str) -> str:
        """Sanitize text for safe output (remove control characters).
        
        Args:
            text: Text to sanitize.
            
        Returns:
            Sanitized text string.
        """
        # Remove or replace control characters that might cause issues
        sanitized = ""
        for char in text:
            if ord(char) < 32 and char not in '\t\n\r':
                sanitized += f"\\x{ord(char):02x}"
            else:
                sanitized += char
        return sanitized
    
    @staticmethod
    def create_separator(length: int = 80, char: str = "-") -> str:
        """Create a separator line.
        
        Args:
            length: Length of the separator.
            char: Character to use for the separator.
            
        Returns:
            Separator string.
        """
        return char * length
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in a human-readable format.
        
        Args:
            seconds: Duration in seconds.
            
        Returns:
            Formatted duration string.
        """
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        else:
            minutes = int(seconds // 60)
            remaining_seconds = seconds % 60
            return f"{minutes}m {remaining_seconds:.1f}s"
    
    @staticmethod
    def pluralize(count: int, singular: str, plural: Optional[str] = None) -> str:
        """Return singular or plural form based on count.
        
        Args:
            count: Number to check.
            singular: Singular form of the word.
            plural: Plural form of the word (defaults to singular + 's').
            
        Returns:
            Appropriate form of the word.
        """
        if count == 1:
            return singular
        return plural or f"{singular}s"


class ColorCodes:
    """ANSI color codes for terminal output."""
    
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Text colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    
    @classmethod
    def colorize(cls, text: str, color: str, bold: bool = False) -> str:
        """Apply color to text.
        
        Args:
            text: Text to colorize.
            color: Color code to apply.
            bold: Whether to make text bold.
            
        Returns:
            Colorized text string.
        """
        prefix = f"{cls.BOLD if bold else ''}{color}"
        return f"{prefix}{text}{cls.RESET}"
    
    @classmethod
    def severity_color(cls, severity: str) -> str:
        """Get color code for severity level.
        
        Args:
            severity: Severity level.
            
        Returns:
            Appropriate color code.
        """
        colors = {
            "low": cls.BLUE,
            "medium": cls.YELLOW,
            "high": cls.RED,
            "critical": cls.MAGENTA
        }
        return colors.get(severity.lower(), cls.WHITE)
