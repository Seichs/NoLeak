"""Console output formatter for displaying scan results in terminal."""

import sys
import os
from typing import List, Optional
from pathlib import Path

from ..core.matcher import Match
from ..core.scanner import ScanResult, ScanStats
from .formatter import (
    BaseFormatter, 
    MatchGrouper, 
    FormattingUtils, 
    ColorCodes
)


class ConsoleFormatter(BaseFormatter):
    """Formatter for console/terminal output."""
    
    def __init__(
        self, 
        use_colors: bool = True,
        show_context: bool = True,
        max_line_length: int = 120
    ) -> None:
        """Initialize the console formatter.
        
        Args:
            use_colors: Whether to use ANSI colors in output.
            show_context: Whether to show surrounding context for matches.
            max_line_length: Maximum length for displayed lines.
        """
        self.use_colors = use_colors and self._supports_colors()
        self.show_context = show_context
        self.max_line_length = max_line_length
    
    def _supports_colors(self) -> bool:
        """Check if the terminal supports ANSI colors.
        
        Returns:
            True if colors are supported, False otherwise.
        """
        # Simple heuristic for color support
        return (
            hasattr(sys.stdout, 'isatty') and
            sys.stdout.isatty() and
            'TERM' in os.environ and
            os.environ['TERM'] != 'dumb'
        )
    
    def _colorize(self, text: str, color: str, bold: bool = False) -> str:
        """Apply color to text if colors are enabled.
        
        Args:
            text: Text to colorize.
            color: Color code to apply.
            bold: Whether to make text bold.
            
        Returns:
            Colorized text if colors enabled, plain text otherwise.
        """
        if self.use_colors:
            return ColorCodes.colorize(text, color, bold)
        return text
    
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format matches for console display.
        
        Args:
            matches: List of matches to format.
            base_path: Base path for relative path display.
            
        Returns:
            Formatted string for console output.
        """
        if not matches:
            return self._colorize("No secrets detected.", ColorCodes.GREEN, bold=True)
        
        output_lines = []
        
        # Group matches by file for better organization
        grouped_matches = MatchGrouper.group_by_file(matches)
        
        for file_path, file_matches in grouped_matches.items():
            # File header
            display_path = FormattingUtils.get_relative_path(Path(file_path), base_path)
            file_header = f"\n{display_path}"
            output_lines.append(self._colorize(file_header, ColorCodes.CYAN, bold=True))
            
            # Sort matches by line number within the file
            file_matches.sort(key=lambda m: m.line_number)
            
            for match in file_matches:
                match_lines = self._format_single_match(match)
                output_lines.extend(match_lines)
        
        return "\n".join(output_lines)
    
    def _format_single_match(self, match: Match) -> List[str]:
        """Format a single match for display.
        
        Args:
            match: Match object to format.
            
        Returns:
            List of formatted lines for the match.
        """
        lines = []
        
        # Severity and rule info
        severity_text = FormattingUtils.format_severity(match.severity)
        severity_color = ColorCodes.severity_color(match.severity)
        colored_severity = self._colorize(severity_text, severity_color, bold=True)
        
        rule_info = f"{colored_severity} {match.rule_name} ({match.rule_id})"
        lines.append(f"  {rule_info}")
        
        # Description
        description = f"    {match.description}"
        lines.append(self._colorize(description, ColorCodes.GRAY))
        
        # Line number and content
        line_num_text = f"    Line {match.line_number}:"
        lines.append(self._colorize(line_num_text, ColorCodes.BLUE))
        
        # Sanitize and truncate line content
        sanitized_line = FormattingUtils.sanitize_output(match.line_content)
        if len(sanitized_line) > self.max_line_length:
            sanitized_line = FormattingUtils.truncate_text(sanitized_line, self.max_line_length)
        
        # Show the line with the match
        indented_line = f"      {sanitized_line}"
        lines.append(indented_line)
        
        # Show highlight if the match position is reasonable
        if (match.start_position >= 0 and 
            match.end_position > match.start_position and
            match.end_position <= len(match.line_content)):
            
            # Create highlight line
            highlight = FormattingUtils.highlight_match(
                sanitized_line, 
                match.start_position + 6,  # Account for indentation
                match.end_position + 6,
                "^"
            )
            if highlight.strip():
                highlight_line = self._colorize(highlight, ColorCodes.RED, bold=True)
                lines.append(highlight_line)
        
        # Show matched secret (truncated for security)
        if match.matched_text and len(match.matched_text.strip()) > 0:
            truncated_match = FormattingUtils.truncate_text(match.matched_text.strip(), 50)
            match_text = f"    Matched: {truncated_match}"
            lines.append(self._colorize(match_text, ColorCodes.YELLOW))
        
        lines.append("")  # Empty line for spacing
        
        return lines
    
    def format_stats(self, stats: ScanStats) -> str:
        """Format scan statistics for console display.
        
        Args:
            stats: Statistics to format.
            
        Returns:
            Formatted statistics string.
        """
        lines = []
        
        # Summary header
        separator = FormattingUtils.create_separator(50, "=")
        lines.append(self._colorize(separator, ColorCodes.BLUE))
        lines.append(self._colorize("SCAN SUMMARY", ColorCodes.BLUE, bold=True))
        lines.append(self._colorize(separator, ColorCodes.BLUE))
        
        # File statistics
        file_stats = [
            f"Files scanned: {stats.files_scanned}",
            f"Files failed: {stats.files_failed}",
        ]
        
        for stat in file_stats:
            lines.append(f"  {stat}")
        
        # Match statistics
        matches_text = f"Secrets found: {stats.matches_found}"
        if stats.matches_found > 0:
            matches_line = self._colorize(matches_text, ColorCodes.RED, bold=True)
        else:
            matches_line = self._colorize(matches_text, ColorCodes.GREEN, bold=True)
        lines.append(f"  {matches_line}")
        
        # Performance statistics
        duration_text = f"Scan duration: {FormattingUtils.format_duration(stats.scan_time)}"
        lines.append(f"  {duration_text}")
        
        rules_text = f"Rules used: {stats.rules_used}"
        lines.append(f"  {rules_text}")
        
        lines.append("")
        
        return "\n".join(lines)
    
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format complete scan result for console display.
        
        Args:
            result: Scan result to format.
            base_path: Base path for relative path display.
            
        Returns:
            Formatted result string.
        """
        lines = []
        
        # Format matches
        matches_output = self.format_matches(result.matches, base_path)
        lines.append(matches_output)
        
        # Format statistics
        stats_output = self.format_stats(result.stats)
        lines.append(stats_output)
        
        # Exit code information
        exit_info = self._format_exit_info(result.exit_code, result.stats.matches_found)
        lines.append(exit_info)
        
        return "\n".join(lines)
    
    def _format_exit_info(self, exit_code: int, matches_found: int) -> str:
        """Format exit code information.
        
        Args:
            exit_code: Exit code from the scan.
            matches_found: Number of matches found.
            
        Returns:
            Formatted exit information.
        """
        if exit_code == 0:
            if matches_found == 0:
                message = "No secrets detected. Repository appears clean."
                return self._colorize(message, ColorCodes.GREEN, bold=True)
            else:
                # This shouldn't happen (matches found but exit code 0)
                return "Scan completed successfully."
        elif exit_code == 1:
            message = f"WARNING: {matches_found} secret(s) detected in repository!"
            return self._colorize(message, ColorCodes.RED, bold=True)
        else:
            message = "ERROR: Scan failed due to an error."
            return self._colorize(message, ColorCodes.RED, bold=True)


class MinimalConsoleFormatter(BaseFormatter):
    """Minimal console formatter for simple output."""
    
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format matches in minimal format.
        
        Args:
            matches: List of matches to format.
            base_path: Base path for relative path display.
            
        Returns:
            Minimal formatted output.
        """
        if not matches:
            return "No secrets detected."
        
        lines = []
        for match in matches:
            file_path = FormattingUtils.get_relative_path(match.file_path, base_path)
            severity = FormattingUtils.format_severity(match.severity)
            line = f"{file_path}:{match.line_number}: {severity} {match.rule_name}"
            lines.append(line)
        
        return "\n".join(lines)
    
    def format_stats(self, stats: ScanStats) -> str:
        """Format stats in minimal format.
        
        Args:
            stats: Statistics to format.
            
        Returns:
            Minimal stats output.
        """
        return (
            f"Scanned {stats.files_scanned} files, "
            f"found {stats.matches_found} secrets "
            f"in {FormattingUtils.format_duration(stats.scan_time)}"
        )
    
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format result in minimal format.
        
        Args:
            result: Scan result to format.
            base_path: Base path for relative path display.
            
        Returns:
            Minimal result output.
        """
        lines = []
        
        matches_output = self.format_matches(result.matches, base_path)
        if matches_output:
            lines.append(matches_output)
        
        stats_output = self.format_stats(result.stats)
        lines.append(stats_output)
        
        return "\n".join(lines)
