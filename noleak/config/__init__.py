"""Configuration package for NoLeak."""

from .settings import (
    APP_NAME, APP_VERSION, APP_DESCRIPTION,
    EXIT_SUCCESS, EXIT_LEAKS_FOUND, EXIT_ERROR,
    ScannerConfig,
    get_default_config
)

__all__ = [
    "APP_NAME",
    "APP_VERSION", 
    "APP_DESCRIPTION",
    "EXIT_SUCCESS",
    "EXIT_LEAKS_FOUND",
    "EXIT_ERROR",
    "ScannerConfig",
    "get_default_config"
] 