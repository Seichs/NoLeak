"""Main scanner engine that orchestrates the secret detection process."""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..config.settings import ScannerConfig, EXIT_SUCCESS, EXIT_LEAKS_FOUND, EXIT_ERROR

# Set up logger for this module
logger = logging.getLogger(__name__)
from ..rules.loader import RuleLoader, create_default_loader
from ..utils.path_tools import get_scannable_files, normalize_path
from .file_loader import FileLoader
from .matcher import PatternMatcher, Match, MatchFilter


@dataclass
class ScanStats:
    """Statistics about a scanning operation."""
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    matches_found: int = 0
    scan_time: float = 0.0
    rules_used: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary representation.
        
        Returns:
            Dictionary representation of the stats.
        """
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_failed": self.files_failed,
            "matches_found": self.matches_found,
            "scan_time_seconds": round(self.scan_time, 2),
            "rules_used": self.rules_used
        }


@dataclass
class ScanResult:
    """Complete result of a scanning operation."""
    matches: List[Match]
    stats: ScanStats
    exit_code: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation.
        
        Returns:
            Dictionary representation of the result.
        """
        return {
            "matches": [match.to_dict() for match in self.matches],
            "stats": self.stats.to_dict(),
            "exit_code": self.exit_code
        }


class SecretScanner:
    """Main scanner class that orchestrates the secret detection process."""
    
    def __init__(
        self,
        config: Optional[ScannerConfig] = None,
        rule_loader: Optional[RuleLoader] = None
    ) -> None:
        """Initialize the secret scanner.
        
        Args:
            config: Scanner configuration. Uses default if None.
            rule_loader: Rule loader instance. Creates default if None.
        """
        self.config = config or ScannerConfig()
        self.rule_loader = rule_loader or create_default_loader()
        
        self.file_loader = FileLoader(self.config)
        self.pattern_matcher = PatternMatcher(self.rule_loader)
        
        # Validate configuration
        self.config.validate()
    
    def scan_path(self, target_path: str) -> ScanResult:
        """Scan a file or directory for secrets.
        
        Args:
            target_path: Path to scan (file or directory).
            
        Returns:
            ScanResult object with matches and statistics.
        """
        start_time = time.time()
        stats = ScanStats()
        matches = []
        
        try:
            # Normalize and validate path
            normalized_path = normalize_path(target_path)
            
            # Get list of files to scan
            files_to_scan = get_scannable_files(normalized_path, self.config)
            
            if not files_to_scan:
                stats.scan_time = time.time() - start_time
                return ScanResult(
                    matches=[],
                    stats=stats,
                    exit_code=EXIT_SUCCESS
                )
            
            # Scan files
            if self.config.max_concurrent_files > 1 and len(files_to_scan) > 1:
                # Concurrent scanning for multiple files
                file_matches = self._scan_files_concurrent(files_to_scan, stats)
            else:
                # Sequential scanning
                file_matches = self._scan_files_sequential(files_to_scan, stats)
            
            # Aggregate all matches
            for file_match_list in file_matches:
                matches.extend(file_match_list)
            
            # Apply post-processing filters
            matches = self._post_process_matches(matches)
            
            # Update final statistics
            stats.matches_found = len(matches)
            stats.rules_used = self.pattern_matcher.get_rule_count()
            stats.scan_time = time.time() - start_time
            
            # Determine exit code
            exit_code = EXIT_LEAKS_FOUND if matches else EXIT_SUCCESS
            
            return ScanResult(
                matches=matches,
                stats=stats,
                exit_code=exit_code
            )
            
        except Exception as e:
            stats.scan_time = time.time() - start_time
            # Log the error for debugging and user feedback
            logger.error(f"Scan failed for path '{target_path}': {e}")
            return ScanResult(
                matches=[],
                stats=stats,
                exit_code=EXIT_ERROR
            )
    
    def _scan_files_sequential(
        self,
        files: List[Path],
        stats: ScanStats
    ) -> List[List[Match]]:
        """Scan files sequentially.
        
        Args:
            files: List of file paths to scan.
            stats: Stats object to update.
            
        Returns:
            List of match lists, one per file.
        """
        results = []
        
        for file_path in files:
            try:
                file_matches = self._scan_single_file(file_path)
                results.append(file_matches)
                stats.files_scanned += 1
            except Exception:
                stats.files_failed += 1
                results.append([])
        
        return results
    
    def _scan_files_concurrent(
        self,
        files: List[Path],
        stats: ScanStats
    ) -> List[List[Match]]:
        """Scan files concurrently using thread pool.
        
        Args:
            files: List of file paths to scan.
            stats: Stats object to update.
            
        Returns:
            List of match lists, one per file.
        """
        results = []
        max_workers = min(self.config.max_concurrent_files, len(files))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scanning tasks
            future_to_file = {
                executor.submit(self._scan_single_file, file_path): file_path
                for file_path in files
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                try:
                    file_matches = future.result()
                    results.append(file_matches)
                    stats.files_scanned += 1
                except Exception:
                    stats.files_failed += 1
                    results.append([])
        
        return results
    
    def _scan_single_file(self, file_path: Path) -> List[Match]:
        """Scan a single file for secrets.
        
        Args:
            file_path: Path to the file to scan.
            
        Returns:
            List of Match objects found in the file.
        """
        # Skip binary files
        if self.file_loader.is_binary_file(file_path):
            return []
        
        # Read file content
        content = self.file_loader.read_file(file_path)
        if content is None:
            return []
        
        # Preprocess content if needed
        content = self.file_loader.preprocess_content(content)
        
        # Scan for matches
        matches = self.pattern_matcher.scan_text(content, file_path)
        
        # Also check for multiline patterns
        multiline_matches = self.pattern_matcher.scan_multiline_text(content, file_path)
        matches.extend(multiline_matches)
        
        return matches
    
    def _post_process_matches(self, matches: List[Match]) -> List[Match]:
        """Apply post-processing filters to matches.
        
        Args:
            matches: Raw list of matches.
            
        Returns:
            Filtered and processed list of matches.
        """
        # Remove duplicates
        matches = MatchFilter.deduplicate_matches(matches)
        
        # Sort by severity and location
        matches = MatchFilter.sort_matches(matches, sort_by="severity")
        
        return matches
    
    def scan_text(self, text: str, source_name: str = "<text>") -> List[Match]:
        """Scan arbitrary text content for secrets.
        
        This method is useful for scanning content that doesn't come from files,
        such as API responses, database content, or user input.
        
        Args:
            text: Text content to scan.
            source_name: Name to use for the source in match results.
            
        Returns:
            List of Match objects found in the text.
        """
        fake_path = Path(source_name)
        
        # Scan for line-based matches
        matches = self.pattern_matcher.scan_text(text, fake_path)
        
        # Scan for multiline matches
        multiline_matches = self.pattern_matcher.scan_multiline_text(text, fake_path)
        matches.extend(multiline_matches)
        
        # Apply post-processing
        matches = self._post_process_matches(matches)
        
        return matches
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get information about the scanner configuration and rules.
        
        Returns:
            Dictionary with scanner information.
        """
        rule_summary = self.pattern_matcher.get_rule_summary()
        rule_counts = self.rule_loader.get_rule_count()
        
        return {
            "scanner_config": {
                "max_file_size": self.config.max_file_size,
                "supported_extensions": list(self.config.supported_extensions),
                "excluded_patterns": list(self.config.excluded_patterns),
                "max_concurrent_files": self.config.max_concurrent_files
            },
            "rules": {
                **rule_summary,
                **rule_counts
            },
            "file_loader": self.file_loader.get_cache_stats()
        }
    
    def add_custom_rule(self, rule: Dict[str, Any]) -> None:
        """Add a custom rule to the scanner.
        
        Args:
            rule: Rule dictionary to add.
            
        Raises:
            ValueError: If the rule is invalid.
        """
        # Add rule to loader (this validates it)
        self.rule_loader._add_rule(rule)
        
        # Refresh the pattern matcher with new rules
        self.pattern_matcher.refresh_rules()
    
    def disable_rule(self, rule_id: str) -> None:
        """Disable a specific rule.
        
        Args:
            rule_id: ID of the rule to disable.
            
        Raises:
            KeyError: If the rule ID is not found.
        """
        self.rule_loader.disable_rule(rule_id)
        self.pattern_matcher.refresh_rules()
    
    def enable_rule(self, rule_id: str) -> None:
        """Enable a specific rule.
        
        Args:
            rule_id: ID of the rule to enable.
            
        Raises:
            KeyError: If the rule ID is not found.
        """
        self.rule_loader.enable_rule(rule_id)
        self.pattern_matcher.refresh_rules()
    
    def clear_caches(self) -> None:
        """Clear all internal caches."""
        self.file_loader.clear_encoding_cache()


def create_scanner(
    builtin_rules: bool = True,
    external_rules_file: Optional[str] = None,
    **config_overrides
) -> SecretScanner:
    """Create a scanner instance with specified configuration.
    
    Args:
        builtin_rules: Whether to load built-in rules.
        external_rules_file: Path to external rules file.
        **config_overrides: Configuration overrides.
        
    Returns:
        Configured SecretScanner instance.
    """
    # Create configuration
    config = ScannerConfig(**config_overrides)
    
    # Create rule loader
    rule_loader = create_default_loader(
        builtin_rules=builtin_rules,
        external_rules_file=external_rules_file
    )
    
    return SecretScanner(config=config, rule_loader=rule_loader)
