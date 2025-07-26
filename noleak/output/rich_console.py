"""Rich console output formatter for beautiful terminal output."""

from typing import List, Optional, Dict, Any
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich import box
from rich.align import Align

from ..core.matcher import Match
from ..core.scanner import ScanResult, ScanStats
from .formatter import BaseFormatter, MatchGrouper, FormattingUtils


class RichConsoleFormatter(BaseFormatter):
    """Enhanced console formatter using Rich library for beautiful output."""
    
    def __init__(
        self,
        use_colors: bool = True,
        show_context: bool = True,
        width: Optional[int] = None
    ) -> None:
        """Initialize the Rich console formatter.
        
        Args:
            use_colors: Whether to use colors in output.
            show_context: Whether to show code context.
            width: Console width (auto-detect if None).
        """
        self.console = Console(
            color_system="auto" if use_colors else None,
            width=width,
            legacy_windows=False
        )
        self.show_context = show_context
    
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format matches using Rich components.
        
        Args:
            matches: List of matches to format.
            base_path: Base path for relative path display.
            
        Returns:
            Rich-formatted string representation.
        """
        if not matches:
            success_panel = Panel(
                "[bold green]SUCCESS: No secrets detected[/bold green]",
                title="Security Scan Results",
                border_style="green",
                box=box.ROUNDED
            )
            with self.console.capture() as capture:
                self.console.print(success_panel)
            return capture.get()
        
        # Group matches by file
        grouped_matches = MatchGrouper.group_by_file(matches)
        
        with self.console.capture() as capture:
            # Header
            header_text = f"[bold red]WARNING: {len(matches)} secrets detected across {len(grouped_matches)} files[/bold red]"
            header_panel = Panel(
                header_text,
                title="Security Scan Results",
                border_style="red",
                box=box.ROUNDED
            )
            self.console.print(header_panel)
            self.console.print()
            
            # Process each file
            for file_path, file_matches in grouped_matches.items():
                self._format_file_matches(file_path, file_matches, base_path)
                self.console.print()
        
        return capture.get()
    
    def _format_file_matches(
        self, 
        file_path: str, 
        matches: List[Match], 
        base_path: Optional[Path]
    ) -> None:
        """Format matches for a single file.
        
        Args:
            file_path: Path to the file.
            matches: Matches found in the file.
            base_path: Base path for relative display.
        """
        # File header
        display_path = FormattingUtils.get_relative_path(Path(file_path), base_path)
        file_panel = Panel(
            f"[bold cyan]{display_path}[/bold cyan]",
            border_style="cyan",
            box=box.MINIMAL
        )
        self.console.print(file_panel)
        
        # Create table for matches
        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            box=box.SIMPLE
        )
        table.add_column("Line", style="dim", width=6)
        table.add_column("Severity", width=10)
        table.add_column("Rule", style="bold")
        table.add_column("Preview", style="dim")
        
        # Sort matches by line number
        sorted_matches = sorted(matches, key=lambda m: m.line_number)
        
        for match in sorted_matches:
            # Format severity with colors
            severity_color = self._get_severity_color(match.severity)
            severity_text = f"[{severity_color}]{self._get_severity_icon(match.severity)} {match.severity.upper()}[/{severity_color}]"
            
            # Truncate line content for preview
            preview = FormattingUtils.truncate_text(match.line_content.strip(), 60)
            preview = FormattingUtils.sanitize_output(preview)
            
            table.add_row(
                str(match.line_number),
                severity_text,
                match.rule_name,
                f"[dim]{preview}[/dim]"
            )
        
        self.console.print(table)
        
        # Show detailed context if requested
        if self.show_context:
            self._show_detailed_matches(sorted_matches)
    
    def _show_detailed_matches(self, matches: List[Match]) -> None:
        """Show detailed information for each match.
        
        Args:
            matches: List of matches to show details for.
        """
        for match in matches:
            # Create detailed panel for each match
            severity_color = self._get_severity_color(match.severity)
            
            detail_content = []
            detail_content.append(f"[bold]Rule:[/bold] {match.rule_name} ({match.rule_id})")
            detail_content.append(f"[bold]Description:[/bold] {match.description}")
            detail_content.append(f"[bold]Line {match.line_number}:[/bold]")
            
            # Show the code line with syntax highlighting if possible
            try:
                syntax = Syntax(
                    match.line_content.rstrip(),
                    "python",  # Default to Python, could be detected from file extension
                    theme="monokai",
                    line_numbers=False,
                    background_color="default"
                )
                detail_content.append("")
                
                # Use console capture to get syntax as string
                with self.console.capture() as syntax_capture:
                    self.console.print(syntax)
                detail_content.append(syntax_capture.get().rstrip())
                
            except Exception:
                # Fallback to plain text
                detail_content.append(f"    {match.line_content.rstrip()}")
            
            # Show matched text
            if match.matched_text and match.matched_text.strip():
                truncated_match = FormattingUtils.truncate_text(match.matched_text.strip(), 50)
                detail_content.append(f"[bold]Matched:[/bold] [yellow]{truncated_match}[/yellow]")
            
            detail_panel = Panel(
                "\n".join(detail_content),
                border_style=severity_color,
                box=box.MINIMAL,
                padding=(0, 1)
            )
            self.console.print(detail_panel)
    
    def format_stats(self, stats: ScanStats) -> str:
        """Format scan statistics using Rich.
        
        Args:
            stats: Statistics to format.
            
        Returns:
            Rich-formatted statistics string.
        """
        with self.console.capture() as capture:
            # Create statistics table
            stats_table = Table(
                title="Scan Statistics",
                show_header=False,
                border_style="blue",
                box=box.ROUNDED
            )
            stats_table.add_column("Metric", style="bold cyan")
            stats_table.add_column("Value", style="bold")
            
            # Add statistics rows
            stats_table.add_row("Files Scanned", str(stats.files_scanned))
            stats_table.add_row("Files Failed", str(stats.files_failed))
            
            # Color-code the matches found
            matches_color = "red" if stats.matches_found > 0 else "green"
            stats_table.add_row(
                "Secrets Found", 
                f"[{matches_color}]{stats.matches_found}[/{matches_color}]"
            )
            
            stats_table.add_row("Scan Duration", FormattingUtils.format_duration(stats.scan_time))
            stats_table.add_row("Rules Used", str(stats.rules_used))
            
            self.console.print(stats_table)
        
        return capture.get()
    
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format complete scan result using Rich.
        
        Args:
            result: Scan result to format.
            base_path: Base path for relative paths.
            
        Returns:
            Rich-formatted result string.
        """
        with self.console.capture() as capture:
            # Format matches
            matches_output = self.format_matches(result.matches, base_path)
            self.console.print(matches_output, end="")
            
            # Add spacing
            self.console.print()
            
            # Format statistics
            stats_output = self.format_stats(result.stats)
            self.console.print(stats_output, end="")
            
            # Final status message
            self._format_final_status(result.exit_code, result.stats.matches_found)
        
        return capture.get()
    
    def _format_final_status(self, exit_code: int, matches_found: int) -> None:
        """Format final status message.
        
        Args:
            exit_code: Exit code from scan.
            matches_found: Number of matches found.
        """
        if exit_code == 0:
            if matches_found == 0:
                status_panel = Panel(
                    "[bold green]SUCCESS: Repository appears clean - no secrets detected[/bold green]",
                    border_style="green",
                    box=box.ROUNDED
                )
            else:
                status_panel = Panel(
                    "[bold blue]INFO: Scan completed successfully[/bold blue]",
                    border_style="blue",
                    box=box.ROUNDED
                )
        elif exit_code == 1:
            status_panel = Panel(
                f"[bold red]WARNING: {matches_found} secret(s) detected in repository![/bold red]",
                border_style="red",
                box=box.ROUNDED
            )
        else:
            status_panel = Panel(
                "[bold red]ERROR: Scan failed due to an error[/bold red]",
                border_style="red",
                box=box.ROUNDED
            )
        
        self.console.print()
        self.console.print(status_panel)
    
    def _get_severity_color(self, severity: str) -> str:
        """Get Rich color for severity level.
        
        Args:
            severity: Severity level.
            
        Returns:
            Rich color name.
        """
        colors = {
            "low": "blue",
            "medium": "yellow", 
            "high": "red",
            "critical": "bold red"
        }
        return colors.get(severity.lower(), "white")
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get text icon for severity level.
        
        Args:
            severity: Severity level.
            
        Returns:
            Text-based severity indicator.
        """
        icons = {
            "low": "[L]",
            "medium": "[M]",
            "high": "[H]",
            "critical": "[C]"
        }
        return icons.get(severity.lower(), "[?]")


def create_progress_scanner(console: Console) -> Progress:
    """Create a progress bar for scanning operations.
    
    Args:
        console: Rich console instance.
        
    Returns:
        Configured Progress instance.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) 