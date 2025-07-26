"""Rule loader for external and built-in regex rules."""

import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from .builtins import get_enabled_builtin_rules, validate_rule


class RuleLoader:
    """Handles loading and managing regex rules from various sources."""
    
    def __init__(self) -> None:
        """Initialize the rule loader."""
        self._rules: List[Dict[str, Any]] = []
        self._rule_ids: set = set()
    
    def load_builtin_rules(self) -> None:
        """Load built-in rules into the rule set."""
        builtin_rules = get_enabled_builtin_rules()
        for rule in builtin_rules:
            self._add_rule(rule)
    
    def load_rules_from_file(self, file_path: Union[str, Path]) -> None:
        """Load rules from a YAML file.
        
        Args:
            file_path: Path to the YAML rules file.
            
        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the file format is invalid.
            yaml.YAMLError: If the YAML is malformed.
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Rules file not found: {file_path}")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML in rules file {file_path}: {e}")
        
        if not isinstance(data, dict):
            raise ValueError(f"Rules file must contain a YAML dictionary: {file_path}")
        
        # Support both 'rules' key or direct rule list
        rules_data = data.get("rules", data)
        
        if isinstance(rules_data, list):
            # List of rules
            for rule in rules_data:
                self._load_rule_from_dict(rule, file_path)
        elif isinstance(rules_data, dict):
            # Single rule or rules as dictionary values
            if "id" in rules_data:
                # Single rule
                self._load_rule_from_dict(rules_data, file_path)
            else:
                # Rules as dictionary values
                for rule_id, rule_data in rules_data.items():
                    if isinstance(rule_data, dict):
                        rule_data["id"] = rule_id
                        self._load_rule_from_dict(rule_data, file_path)
        else:
            raise ValueError(f"Invalid rules format in file: {file_path}")
    
    def _load_rule_from_dict(self, rule_data: Dict[str, Any], source_file: Path) -> None:
        """Load a single rule from dictionary data.
        
        Args:
            rule_data: Rule data dictionary.
            source_file: Source file path for error reporting.
            
        Raises:
            ValueError: If the rule data is invalid.
        """
        try:
            # Set default values
            rule = {
                "enabled": True,
                "severity": "medium",
                **rule_data
            }
            
            # Validate the rule
            validate_rule(rule)
            
            # Add source information
            rule["source"] = str(source_file)
            
            self._add_rule(rule)
            
        except (ValueError, KeyError) as e:
            raise ValueError(f"Invalid rule in {source_file}: {e}")
    
    def _add_rule(self, rule: Dict[str, Any]) -> None:
        """Add a rule to the rule set.
        
        Args:
            rule: Rule dictionary to add.
            
        Raises:
            ValueError: If a rule with the same ID already exists.
        """
        rule_id = rule["id"]
        
        if rule_id in self._rule_ids:
            raise ValueError(f"Duplicate rule ID: {rule_id}")
        
        self._rules.append(rule)
        self._rule_ids.add(rule_id)
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all loaded rules.
        
        Returns:
            List of rule dictionaries.
        """
        return self._rules.copy()
    
    def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Get only enabled rules.
        
        Returns:
            List of enabled rule dictionaries.
        """
        return [rule for rule in self._rules if rule.get("enabled", True)]
    
    def get_rules_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get rules filtered by severity level.
        
        Args:
            severity: Severity level to filter by.
            
        Returns:
            List of rules matching the severity level.
        """
        return [
            rule for rule in self._rules
            if rule.get("severity") == severity and rule.get("enabled", True)
        ]
    
    def disable_rule(self, rule_id: str) -> None:
        """Disable a specific rule.
        
        Args:
            rule_id: ID of the rule to disable.
            
        Raises:
            KeyError: If the rule ID is not found.
        """
        for rule in self._rules:
            if rule["id"] == rule_id:
                rule["enabled"] = False
                return
        raise KeyError(f"Rule not found: {rule_id}")
    
    def enable_rule(self, rule_id: str) -> None:
        """Enable a specific rule.
        
        Args:
            rule_id: ID of the rule to enable.
            
        Raises:
            KeyError: If the rule ID is not found.
        """
        for rule in self._rules:
            if rule["id"] == rule_id:
                rule["enabled"] = True
                return
        raise KeyError(f"Rule not found: {rule_id}")
    
    def clear_rules(self) -> None:
        """Clear all loaded rules."""
        self._rules.clear()
        self._rule_ids.clear()
    
    def get_rule_count(self) -> Dict[str, int]:
        """Get statistics about loaded rules.
        
        Returns:
            Dictionary with rule count statistics.
        """
        total = len(self._rules)
        enabled = len([r for r in self._rules if r.get("enabled", True)])
        
        severity_counts = {}
        for severity in ["low", "medium", "high", "critical"]:
            severity_counts[severity] = len([
                r for r in self._rules
                if r.get("severity") == severity and r.get("enabled", True)
            ])
        
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            **severity_counts
        }


def create_example_rules_file(output_path: Union[str, Path]) -> None:
    """Create an example rules file for users to customize.
    
    Args:
        output_path: Path where to create the example file.
    """
    example_rules = {
        "rules": [
            {
                "id": "custom_api_key",
                "name": "Custom API Key Pattern",
                "description": "Detects custom API key patterns specific to your application",
                "pattern": r"(?i)myapp[_-]?api[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{32})['\"]?",
                "severity": "high",
                "enabled": True
            },
            {
                "id": "internal_token",
                "name": "Internal Service Token",
                "description": "Detects internal service authentication tokens",
                "pattern": r"(?i)internal[_-]?token\s*[:=]\s*['\"]?([a-zA-Z0-9_\-+=./]{20,})['\"]?",
                "severity": "medium",
                "enabled": True
            }
        ]
    }
    
    output_path = Path(output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(example_rules, f, default_flow_style=False, indent=2)


def load_rules_from_directory(directory: Union[str, Path]) -> RuleLoader:
    """Load all YAML rule files from a directory.
    
    Args:
        directory: Directory containing YAML rule files.
        
    Returns:
        RuleLoader instance with all rules loaded.
        
    Raises:
        FileNotFoundError: If the directory doesn't exist.
    """
    directory = Path(directory)
    
    if not directory.exists():
        raise FileNotFoundError(f"Rules directory not found: {directory}")
    
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")
    
    loader = RuleLoader()
    
    # Load YAML files
    yaml_patterns = ["*.yaml", "*.yml"]
    for pattern in yaml_patterns:
        for file_path in directory.glob(pattern):
            try:
                loader.load_rules_from_file(file_path)
            except Exception as e:
                # Log warning but continue loading other files
                print(f"Warning: Failed to load rules from {file_path}: {e}")
    
    return loader


def create_default_loader(
    builtin_rules: bool = True,
    external_rules_file: Optional[Union[str, Path]] = None
) -> RuleLoader:
    """Create a rule loader with default configuration.
    
    Args:
        builtin_rules: Whether to load built-in rules.
        external_rules_file: Optional path to external rules file.
        
    Returns:
        Configured RuleLoader instance.
    """
    loader = RuleLoader()
    
    if builtin_rules:
        loader.load_builtin_rules()
    
    if external_rules_file:
        loader.load_rules_from_file(external_rules_file)
    
    return loader
