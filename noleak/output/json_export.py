"""JSON output formatter for structured scan results export."""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timezone

from ..core.matcher import Match
from ..core.scanner import ScanResult, ScanStats
from ..config.settings import APP_NAME, APP_VERSION
from .formatter import BaseFormatter, MatchGrouper, FormattingUtils


class JSONFormatter(BaseFormatter):
    """Formatter for JSON output."""
    
    def __init__(
        self,
        indent: Optional[int] = 2,
        include_metadata: bool = True,
        include_stats: bool = True,
        relative_paths: bool = True
    ) -> None:
        """Initialize the JSON formatter.
        
        Args:
            indent: JSON indentation level (None for compact output).
            include_metadata: Whether to include metadata in output.
            include_stats: Whether to include statistics in output.
            relative_paths: Whether to use relative paths in output.
        """
        self.indent = indent
        self.include_metadata = include_metadata
        self.include_stats = include_stats
        self.relative_paths = relative_paths
    
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format matches as JSON.
        
        Args:
            matches: List of matches to format.
            base_path: Base path for relative path display.
            
        Returns:
            JSON string representation of matches.
        """
        formatted_matches = []
        
        for match in matches:
            match_dict = self._format_single_match(match, base_path)
            formatted_matches.append(match_dict)
        
        return json.dumps(formatted_matches, indent=self.indent, ensure_ascii=False)
    
    def _format_single_match(self, match: Match, base_path: Optional[Path] = None) -> Dict[str, Any]:
        """Format a single match as dictionary.
        
        Args:
            match: Match object to format.
            base_path: Base path for relative path display.
            
        Returns:
            Dictionary representation of the match.
        """
        # Determine file path format
        if self.relative_paths and base_path:
            file_path = FormattingUtils.get_relative_path(match.file_path, base_path)
        else:
            file_path = str(match.file_path)
        
        match_dict = {
            "rule": {
                "id": match.rule_id,
                "name": match.rule_name,
                "description": match.description,
                "severity": match.severity
            },
            "location": {
                "file": file_path,
                "line": match.line_number,
                "column": match.start_position,
                "end_column": match.end_position
            },
            "content": {
                "line": match.line_content.rstrip(),
                "matched_text": match.matched_text
            }
        }
        
        return match_dict
    
    def format_stats(self, stats: ScanStats) -> str:
        """Format statistics as JSON.
        
        Args:
            stats: Statistics to format.
            
        Returns:
            JSON string representation of statistics.
        """
        stats_dict = stats.to_dict()
        return json.dumps(stats_dict, indent=self.indent)
    
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format complete scan result as JSON.
        
        Args:
            result: Scan result to format.
            base_path: Base path for relative path display.
            
        Returns:
            JSON string representation of the result.
        """
        output_dict = {}
        
        # Add metadata if requested
        if self.include_metadata:
            output_dict["metadata"] = self._create_metadata(base_path)
        
        # Add matches
        formatted_matches = []
        for match in result.matches:
            match_dict = self._format_single_match(match, base_path)
            formatted_matches.append(match_dict)
        
        output_dict["matches"] = formatted_matches
        
        # Add statistics if requested
        if self.include_stats:
            output_dict["statistics"] = result.stats.to_dict()
        
        # Add summary information
        output_dict["summary"] = {
            "total_matches": len(result.matches),
            "exit_code": result.exit_code,
            "has_secrets": len(result.matches) > 0
        }
        
        return json.dumps(output_dict, indent=self.indent, ensure_ascii=False)
    
    def _create_metadata(self, base_path: Optional[Path] = None) -> Dict[str, Any]:
        """Create metadata for the JSON output.
        
        Args:
            base_path: Base path that was scanned.
            
        Returns:
            Metadata dictionary.
        """
        metadata = {
            "tool": {
                "name": APP_NAME,
                "version": APP_VERSION
            },
            "scan": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": str(base_path) if base_path else None
            }
        }
        
        return metadata


class SARIFFormatter(BaseFormatter):
    """Formatter for SARIF (Static Analysis Results Interchange Format) output."""
    
    def __init__(self, include_rules: bool = True) -> None:
        """Initialize the SARIF formatter.
        
        Args:
            include_rules: Whether to include rule definitions in output.
        """
        self.include_rules = include_rules
    
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format matches as SARIF JSON.
        
        Args:
            matches: List of matches to format.
            base_path: Base path for relative path display.
            
        Returns:
            SARIF JSON string.
        """
        sarif_dict = self._create_sarif_document(matches, base_path)
        return json.dumps(sarif_dict, indent=2, ensure_ascii=False)
    
    def format_stats(self, stats: ScanStats) -> str:
        """Format statistics (not applicable for SARIF).
        
        Args:
            stats: Statistics to format.
            
        Returns:
            Empty JSON object.
        """
        return "{}"
    
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format complete scan result as SARIF.
        
        Args:
            result: Scan result to format.
            base_path: Base path for relative path display.
            
        Returns:
            SARIF JSON string.
        """
        return self.format_matches(result.matches, base_path)
    
    def _create_sarif_document(self, matches: List[Match], base_path: Optional[Path] = None) -> Dict[str, Any]:
        """Create a SARIF document structure.
        
        Args:
            matches: List of matches to include.
            base_path: Base path for relative paths.
            
        Returns:
            SARIF document dictionary.
        """
        # Group matches by rule for rule definitions
        rules_dict = {}
        results = []
        
        for match in matches:
            # Add to rules if not seen before
            if match.rule_id not in rules_dict:
                rules_dict[match.rule_id] = {
                    "id": match.rule_id,
                    "name": match.rule_name,
                    "shortDescription": {
                        "text": match.rule_name
                    },
                    "fullDescription": {
                        "text": match.description
                    },
                    "properties": {
                        "security-severity": self._severity_to_score(match.severity)
                    }
                }
            
            # Create result entry
            file_path = FormattingUtils.get_relative_path(match.file_path, base_path) if base_path else str(match.file_path)
            
            result_entry = {
                "ruleId": match.rule_id,
                "level": self._severity_to_level(match.severity),
                "message": {
                    "text": f"Potential secret detected: {match.rule_name}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        },
                        "region": {
                            "startLine": match.line_number,
                            "startColumn": match.start_position + 1,  # SARIF uses 1-based columns
                            "endColumn": match.end_position + 1,
                            "snippet": {
                                "text": match.line_content.rstrip()
                            }
                        }
                    }
                }]
            }
            
            results.append(result_entry)
        
        # Create SARIF document structure
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": APP_NAME,
                        "version": APP_VERSION,
                        "informationUri": "https://github.com/Seichs/NoLeak",
                        "rules": list(rules_dict.values()) if self.include_rules else []
                    }
                },
                "results": results
            }]
        }
        
        return sarif_doc
    
    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level.
        
        Args:
            severity: NoLeak severity level.
            
        Returns:
            SARIF level string.
        """
        mapping = {
            "low": "note",
            "medium": "warning",
            "high": "error",
            "critical": "error"
        }
        return mapping.get(severity.lower(), "warning")
    
    def _severity_to_score(self, severity: str) -> str:
        """Convert severity to SARIF security score.
        
        Args:
            severity: NoLeak severity level.
            
        Returns:
            SARIF security score string.
        """
        mapping = {
            "low": "3.0",
            "medium": "5.0", 
            "high": "7.0",
            "critical": "9.0"
        }
        return mapping.get(severity.lower(), "5.0")


class CompactJSONFormatter(BaseFormatter):
    """Compact JSON formatter for minimal output."""
    
    def format_matches(self, matches: List[Match], base_path: Optional[Path] = None) -> str:
        """Format matches in compact JSON.
        
        Args:
            matches: List of matches to format.
            base_path: Base path for relative paths.
            
        Returns:
            Compact JSON string.
        """
        compact_matches = []
        
        for match in matches:
            file_path = FormattingUtils.get_relative_path(match.file_path, base_path) if base_path else str(match.file_path)
            
            compact_match = {
                "file": file_path,
                "line": match.line_number,
                "rule": match.rule_id,
                "severity": match.severity,
                "message": match.rule_name
            }
            compact_matches.append(compact_match)
        
        return json.dumps(compact_matches, separators=(',', ':'))
    
    def format_stats(self, stats: ScanStats) -> str:
        """Format stats in compact JSON.
        
        Args:
            stats: Statistics to format.
            
        Returns:
            Compact JSON string.
        """
        compact_stats = {
            "files": stats.files_scanned,
            "matches": stats.matches_found,
            "time": round(stats.scan_time, 2)
        }
        return json.dumps(compact_stats, separators=(',', ':'))
    
    def format_result(self, result: ScanResult, base_path: Optional[Path] = None) -> str:
        """Format result in compact JSON.
        
        Args:
            result: Scan result to format.
            base_path: Base path for relative paths.
            
        Returns:
            Compact JSON string.
        """
        compact_result = {
            "matches": json.loads(self.format_matches(result.matches, base_path)),
            "stats": json.loads(self.format_stats(result.stats)),
            "exit_code": result.exit_code
        }
        return json.dumps(compact_result, separators=(',', ':'))
