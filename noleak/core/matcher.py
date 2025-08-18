"""Pattern matcher for detecting secrets using regex rules."""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, NamedTuple, Iterator
from dataclasses import dataclass

from ..rules.loader import RuleLoader

# Set up logger for this module
logger = logging.getLogger(__name__)


@dataclass
class Match:
    """Represents a single pattern match in a file."""
    rule_id: str
    rule_name: str
    description: str
    severity: str
    file_path: Path
    line_number: int
    line_content: str
    matched_text: str
    start_position: int
    end_position: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary representation.
        
        Returns:
            Dictionary representation of the match.
        """
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "matched_text": self.matched_text,
            "start_position": self.start_position,
            "end_position": self.end_position
        }


class PatternMatcher:
    """Handles pattern matching using compiled regex rules."""
    
    def __init__(self, rule_loader: RuleLoader) -> None:
        """Initialize the pattern matcher.
        
        Args:
            rule_loader: RuleLoader instance with loaded rules.
        """
        self.rule_loader = rule_loader
        self._compiled_rules: List[Dict[str, Any]] = []
        self._compile_rules()
    
    def _compile_rules(self) -> None:
        """Compile all enabled rules for efficient matching."""
        self._compiled_rules.clear()
        
        for rule in self.rule_loader.get_enabled_rules():
            try:
                compiled_pattern = re.compile(rule["pattern"], re.MULTILINE)
                compiled_rule = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "pattern": compiled_pattern,
                    "raw_pattern": rule["pattern"]
                }
                self._compiled_rules.append(compiled_rule)
            except re.error as e:
                # Log warning about invalid regex pattern
                logger.warning(f"Invalid regex pattern in rule '{rule['id']}': {e}")
    
    def scan_text(self, text: str, file_path: Path) -> List[Match]:
        """Scan text content for pattern matches.
        
        Args:
            text: Text content to scan.
            file_path: Path to the file being scanned.
            
        Returns:
            List of Match objects for all detected patterns.
        """
        matches = []
        lines = text.splitlines()
        
        for rule in self._compiled_rules:
            # Find matches for this rule
            for line_idx, line in enumerate(lines, 1):
                line_matches = self._find_line_matches(rule, line, line_idx, file_path)
                matches.extend(line_matches)
        
        return matches
    
    def _find_line_matches(
        self,
        rule: Dict[str, Any],
        line: str,
        line_number: int,
        file_path: Path
    ) -> List[Match]:
        """Find all matches for a rule in a single line.
        
        Args:
            rule: Compiled rule dictionary.
            line: Line content to search.
            line_number: Line number in the file.
            file_path: Path to the file being scanned.
            
        Returns:
            List of Match objects for the line.
        """
        matches = []
        pattern = rule["pattern"]
        
        for match in pattern.finditer(line):
            # Get the matched text
            matched_text = match.group(0)
            
            # If there are capture groups, use the first one as the matched secret
            if match.groups():
                matched_text = match.group(1)
            
            # Create Match object
            match_obj = Match(
                rule_id=rule["id"],
                rule_name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                file_path=file_path,
                line_number=line_number,
                line_content=line,
                matched_text=matched_text,
                start_position=match.start(),
                end_position=match.end()
            )
            
            matches.append(match_obj)
        
        return matches
    
    def scan_multiline_text(self, text: str, file_path: Path) -> List[Match]:
        """Scan text content for multiline pattern matches.
        
        This method is useful for patterns that span multiple lines,
        such as multi-line certificates or keys.
        
        Args:
            text: Text content to scan.
            file_path: Path to the file being scanned.
            
        Returns:
            List of Match objects for all detected patterns.
        """
        matches = []
        
        for rule in self._compiled_rules:
            pattern = rule["pattern"]
            
            for match in pattern.finditer(text):
                # Calculate line number where match starts
                line_number = text[:match.start()].count('\n') + 1
                
                # Get the line content containing the match start
                lines = text.splitlines()
                if line_number <= len(lines):
                    line_content = lines[line_number - 1]
                else:
                    line_content = ""
                
                # Get the matched text
                matched_text = match.group(0)
                if match.groups():
                    matched_text = match.group(1)
                
                # Create Match object
                match_obj = Match(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    description=rule["description"],
                    severity=rule["severity"],
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line_content,
                    matched_text=matched_text,
                    start_position=match.start(),
                    end_position=match.end()
                )
                
                matches.append(match_obj)
        
        return matches
    
    def get_rule_count(self) -> int:
        """Get the number of compiled rules.
        
        Returns:
            Number of compiled rules ready for matching.
        """
        return len(self._compiled_rules)
    
    def get_rule_summary(self) -> Dict[str, Any]:
        """Get a summary of loaded rules.
        
        Returns:
            Dictionary with rule statistics and information.
        """
        severity_counts = {}
        for severity in ["low", "medium", "high", "critical"]:
            severity_counts[severity] = len([
                r for r in self._compiled_rules
                if r["severity"] == severity
            ])
        
        return {
            "total_rules": len(self._compiled_rules),
            "severity_breakdown": severity_counts,
            "rule_ids": [rule["id"] for rule in self._compiled_rules]
        }
    
    def refresh_rules(self) -> None:
        """Refresh compiled rules from the rule loader.
        
        This should be called if rules are modified in the loader.
        """
        self._compile_rules()


class MatchFilter:
    """Filters and deduplicates matches based on various criteria."""
    
    @staticmethod
    def deduplicate_matches(matches: List[Match]) -> List[Match]:
        """Remove duplicate matches based on file, line, and matched text.
        
        Args:
            matches: List of matches to deduplicate.
            
        Returns:
            List of unique matches.
        """
        seen = set()
        unique_matches = []
        
        for match in matches:
            # Create a key for deduplication
            key = (
                str(match.file_path),
                match.line_number,
                match.matched_text,
                match.rule_id
            )
            
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)
        
        return unique_matches
    
    @staticmethod
    def filter_by_severity(
        matches: List[Match],
        min_severity: str = "low"
    ) -> List[Match]:
        """Filter matches by minimum severity level.
        
        Args:
            matches: List of matches to filter.
            min_severity: Minimum severity level to include.
            
        Returns:
            List of filtered matches.
        """
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity, 0)
        
        return [
            match for match in matches
            if severity_order.get(match.severity, 0) >= min_level
        ]
    
    @staticmethod
    def sort_matches(
        matches: List[Match],
        sort_by: str = "severity"
    ) -> List[Match]:
        """Sort matches by various criteria.
        
        Args:
            matches: List of matches to sort.
            sort_by: Sort criteria ('severity', 'file', 'line').
            
        Returns:
            List of sorted matches.
        """
        if sort_by == "severity":
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            return sorted(
                matches,
                key=lambda m: (
                    severity_order.get(m.severity, 4),
                    str(m.file_path),
                    m.line_number
                )
            )
        elif sort_by == "file":
            return sorted(
                matches,
                key=lambda m: (str(m.file_path), m.line_number)
            )
        elif sort_by == "line":
            return sorted(
                matches,
                key=lambda m: (str(m.file_path), m.line_number)
            )
        else:
            return matches
    
    @staticmethod
    def filter_by_file_pattern(
        matches: List[Match],
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ) -> List[Match]:
        """Filter matches by file path patterns.
        
        Args:
            matches: List of matches to filter.
            include_patterns: Patterns that file paths must match.
            exclude_patterns: Patterns that file paths must not match.
            
        Returns:
            List of filtered matches.
        """
        import fnmatch
        
        filtered_matches = matches.copy()
        
        if include_patterns:
            filtered_matches = [
                match for match in filtered_matches
                if any(
                    fnmatch.fnmatch(str(match.file_path), pattern)
                    for pattern in include_patterns
                )
            ]
        
        if exclude_patterns:
            filtered_matches = [
                match for match in filtered_matches
                if not any(
                    fnmatch.fnmatch(str(match.file_path), pattern)
                    for pattern in exclude_patterns
                )
            ]
        
        return filtered_matches
