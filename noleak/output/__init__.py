"""Output formatting package for NoLeak."""

from .formatter import BaseFormatter, MatchGrouper, FormattingUtils, ColorCodes
from .console import ConsoleFormatter, MinimalConsoleFormatter
from .json_export import JSONFormatter, SARIFFormatter, CompactJSONFormatter

# Try to import Rich formatter (optional dependency)
try:
    from .rich_console import RichConsoleFormatter
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False
    RichConsoleFormatter = None

__all__ = [
    "BaseFormatter",
    "MatchGrouper", 
    "FormattingUtils",
    "ColorCodes",
    "ConsoleFormatter",
    "MinimalConsoleFormatter",
    "JSONFormatter",
    "SARIFFormatter",
    "CompactJSONFormatter"
]

# Add Rich formatter to exports if available
if _RICH_AVAILABLE:
    __all__.append("RichConsoleFormatter")
