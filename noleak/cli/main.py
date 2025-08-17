"""Command-line interface for NoLeak secret scanner."""

import argparse
import sys
from pathlib import Path
from typing import Optional, List

from ..config.settings import (
    APP_NAME, APP_VERSION, APP_DESCRIPTION,
    EXIT_SUCCESS, EXIT_LEAKS_FOUND, EXIT_ERROR,
    SUPPORTED_OUTPUT_FORMATS
)
from ..core.scanner import create_scanner
from ..output.console import ConsoleFormatter, MinimalConsoleFormatter
from ..output.json_export import JSONFormatter, SARIFFormatter, CompactJSONFormatter

# Try to import Rich formatter (optional)
try:
    from ..output.rich_console import RichConsoleFormatter
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False
    RichConsoleFormatter = None
from ..rules.loader import create_example_rules_file


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.
    
    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="noleak",
        description=APP_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  noleak .                          # Scan current directory
  noleak /path/to/project           # Scan specific directory
  noleak file.py                    # Scan single file
  noleak . --output json            # Output results as JSON
  noleak . --rules custom.yaml      # Use custom rules
  noleak . --output json > results.json  # Save JSON to file

Exit codes:
  0  No secrets found
  1  Secrets detected
  2  Error occurred

For more information, visit: https://github.com/Seichs/NoLeak
        """
    )
    
    # Positional arguments
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to scan (file or directory)"
    )
    
    # Output format options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o",
        choices=["console", "rich", "json", "sarif", "compact"],
        default="console",
        help="Output format (default: console)"
    )
    
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    output_group.add_argument(
        "--minimal",
        action="store_true",
        help="Use minimal output format"
    )
    
    output_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except errors"
    )
    
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    # Rule configuration options
    rules_group = parser.add_argument_group("Rule Options")
    rules_group.add_argument(
        "--rules", "-r",
        metavar="FILE",
        help="Path to custom rules file (YAML format)"
    )
    
    rules_group.add_argument(
        "--no-builtin-rules",
        action="store_true",
        help="Disable built-in rules"
    )
    
    rules_group.add_argument(
        "--list-rules",
        action="store_true",
        help="List all available rules and exit"
    )
    
    rules_group.add_argument(
        "--create-rules-example",
        metavar="FILE",
        help="Create an example rules file and exit"
    )
    
    # Scanning options
    scan_group = parser.add_argument_group("Scanning Options")
    scan_group.add_argument(
        "--max-file-size",
        type=int,
        metavar="BYTES",
        help="Maximum file size to scan in bytes (default: 10MB)"
    )
    
    scan_group.add_argument(
        "--include-ext",
        action="append",
        metavar="EXT",
        help="Include additional file extensions (e.g., .txt)"
    )
    
    scan_group.add_argument(
        "--exclude-ext",
        action="append",
        metavar="EXT",
        help="Exclude file extensions from scanning"
    )
    
    scan_group.add_argument(
        "--threads",
        type=int,
        metavar="N",
        help="Number of concurrent threads for scanning (default: 50)"
    )
    
    # Information options
    info_group = parser.add_argument_group("Information")
    info_group.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}"
    )
    
    info_group.add_argument(
        "--info",
        action="store_true",
        help="Show scanner configuration and exit"
    )
    
    return parser


def handle_special_actions(args: argparse.Namespace) -> bool:
    """Handle special actions that don't require scanning.
    
    Args:
        args: Parsed command line arguments.
        
    Returns:
        True if a special action was handled, False otherwise.
    """
    # Create example rules file
    if args.create_rules_example:
        try:
            create_example_rules_file(args.create_rules_example)
            print(f"Example rules file created: {args.create_rules_example}")
            return True
        except Exception as e:
            print(f"Error creating rules file: {e}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
    
    # List rules
    if args.list_rules:
        scanner = create_scanner(
            builtin_rules=not args.no_builtin_rules,
            external_rules_file=args.rules
        )
        list_rules(scanner)
        return True
    
    # Show scanner info
    if args.info:
        scanner = create_scanner(
            builtin_rules=not args.no_builtin_rules,
            external_rules_file=args.rules
        )
        show_scanner_info(scanner)
        return True
    
    return False


def list_rules(scanner) -> None:
    """List all available rules.
    
    Args:
        scanner: Scanner instance to get rules from.
    """
    print(f"{APP_NAME} Rules")
    print("=" * 50)
    
    rules = scanner.rule_loader.get_rules()
    
    if not rules:
        print("No rules loaded.")
        return
    
    # Group rules by severity
    from ..output.formatter import MatchGrouper
    
    # Create fake matches to use grouping functionality
    fake_matches = []
    for rule in rules:
        from ..core.matcher import Match
        fake_match = Match(
            rule_id=rule["id"],
            rule_name=rule["name"],
            description=rule["description"],
            severity=rule["severity"],
            file_path=Path(""),
            line_number=0,
            line_content="",
            matched_text="",
            start_position=0,
            end_position=0
        )
        fake_matches.append(fake_match)
    
    grouped = MatchGrouper.group_by_severity(fake_matches)
    
    for severity in ["critical", "high", "medium", "low"]:
        if severity in grouped:
            print(f"\n{severity.upper()} Severity:")
            for match in grouped[severity]:
                enabled = "✓" if next((r for r in rules if r["id"] == match.rule_id), {}).get("enabled", True) else "✗"
                print(f"  {enabled} {match.rule_id:<20} {match.rule_name}")
    
    print(f"\nTotal: {len(rules)} rules")


def show_scanner_info(scanner) -> None:
    """Show scanner configuration information.
    
    Args:
        scanner: Scanner instance to get info from.
    """
    info = scanner.get_scanner_info()
    
    print(f"{APP_NAME} {APP_VERSION}")
    print("=" * 50)
    
    print("\nScanner Configuration:")
    config = info["scanner_config"]
    print(f"  Max file size: {config['max_file_size']:,} bytes")
    print(f"  Concurrent files: {config['max_concurrent_files']}")
    print(f"  Supported extensions: {len(config['supported_extensions'])}")
    print(f"  Excluded patterns: {len(config['excluded_patterns'])}")
    
    print("\nRules:")
    rules_info = info["rules"]
    print(f"  Total rules: {rules_info['total_rules']}")
    print(f"  Enabled rules: {rules_info['enabled']}")
    print(f"  Critical: {rules_info.get('critical', 0)}")
    print(f"  High: {rules_info.get('high', 0)}")
    print(f"  Medium: {rules_info.get('medium', 0)}")
    print(f"  Low: {rules_info.get('low', 0)}")


def create_formatter(args: argparse.Namespace):
    """Create appropriate formatter based on arguments.
    
    Args:
        args: Parsed command line arguments.
        
    Returns:
        Formatter instance.
    """
    if args.output == "json":
        return JSONFormatter(
            indent=None if args.minimal else 2,
            include_metadata=not args.minimal,
            include_stats=not args.minimal
        )
    elif args.output == "sarif":
        return SARIFFormatter()
    elif args.output == "compact":
        return CompactJSONFormatter()
    elif args.output == "rich":
        if not _RICH_AVAILABLE:
            print("Error: Rich output requires 'rich' library. Install with: pip install rich", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        return RichConsoleFormatter(
            use_colors=not args.no_color,
            show_context=args.verbose
        )
    else:  # console
        if args.minimal:
            return MinimalConsoleFormatter()
        else:
            return ConsoleFormatter(
                use_colors=not args.no_color,
                show_context=args.verbose
            )


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments.
    
    Args:
        args: Parsed arguments to validate.
        
    Raises:
        SystemExit: If arguments are invalid.
    """
    # Check if path is required and exists
    if args.path is None:
        print("Error: Path argument is required", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    
    # Check rules file if specified
    if args.rules:
        rules_path = Path(args.rules)
        if not rules_path.exists():
            print(f"Error: Rules file does not exist: {args.rules}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
    
    # Validate numeric arguments
    if args.max_file_size is not None and args.max_file_size <= 0:
        print("Error: Max file size must be positive", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    
    if args.threads is not None and args.threads <= 0:
        print("Error: Thread count must be positive", file=sys.stderr)
        sys.exit(EXIT_ERROR)


def main() -> None:
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle special actions first
    if handle_special_actions(args):
        sys.exit(EXIT_SUCCESS)
    
    # Validate arguments
    validate_arguments(args)
    
    try:
        # Build scanner configuration
        config_overrides = {}
        
        if args.max_file_size is not None:
            config_overrides["max_file_size"] = args.max_file_size
        
        if args.threads is not None:
            config_overrides["max_concurrent_files"] = args.threads
        
        # Handle file extension modifications
        if args.include_ext or args.exclude_ext:
            from ..config.settings import DEFAULT_SUPPORTED_EXTENSIONS
            extensions = DEFAULT_SUPPORTED_EXTENSIONS.copy()
            
            if args.include_ext:
                for ext in args.include_ext:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    extensions.add(ext.lower())
            
            if args.exclude_ext:
                for ext in args.exclude_ext:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    extensions.discard(ext.lower())
            
            config_overrides["supported_extensions"] = extensions
        
        # Create scanner
        scanner = create_scanner(
            builtin_rules=not args.no_builtin_rules,
            external_rules_file=args.rules,
            **config_overrides
        )
        
        # Create formatter
        formatter = create_formatter(args)
        
        # Perform scan
        if not args.quiet:
            if args.verbose:
                print(f"Scanning {args.path}...", file=sys.stderr)
        
        result = scanner.scan_path(args.path)
        
        # Format and output results
        if not args.quiet:
            base_path = Path(args.path) if Path(args.path).is_dir() else Path(args.path).parent
            formatted_output = formatter.format_result(result, base_path)
            print(formatted_output)
        
        # Exit with appropriate code
        sys.exit(result.exit_code)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
