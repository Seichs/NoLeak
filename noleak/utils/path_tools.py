"""Path utilities for file filtering and path management."""

import os
import fnmatch
from pathlib import Path
from typing import List, Set, Iterator, Union, Optional

from ..config.settings import ScannerConfig


def normalize_path(path: Union[str, Path]) -> Path:
    """Normalize a path to a Path object with resolved components.
    
    Args:
        path: The path to normalize.
        
    Returns:
        Normalized Path object.
    """
    return Path(path).resolve()


def is_file_supported(file_path: Path, supported_extensions: Set[str]) -> bool:
    """Check if a file has a supported extension.
    
    Args:
        file_path: Path to the file to check.
        supported_extensions: Set of supported file extensions (with dots).
        
    Returns:
        True if the file extension is supported, False otherwise.
    """
    return file_path.suffix.lower() in supported_extensions


def is_path_excluded(path: Path, excluded_patterns: Set[str]) -> bool:
    """Check if a path matches any excluded pattern.
    
    Args:
        path: Path to check.
        excluded_patterns: Set of patterns to exclude.
        
    Returns:
        True if the path should be excluded, False otherwise.
    """
    path_str = str(path)
    path_name = path.name
    
    for pattern in excluded_patterns:
        # Check against full path
        if fnmatch.fnmatch(path_str, pattern):
            return True
        # Check against just the filename/dirname
        if fnmatch.fnmatch(path_name, pattern):
            return True
        # Check if any parent directory matches
        for parent in path.parents:
            if fnmatch.fnmatch(parent.name, pattern):
                return True
    
    return False


def get_file_size(file_path: Path) -> int:
    """Get the size of a file in bytes.
    
    Args:
        file_path: Path to the file.
        
    Returns:
        File size in bytes.
        
    Raises:
        OSError: If the file cannot be accessed.
    """
    return file_path.stat().st_size


def is_file_too_large(file_path: Path, max_size: int) -> bool:
    """Check if a file exceeds the maximum allowed size.
    
    Args:
        file_path: Path to the file to check.
        max_size: Maximum allowed file size in bytes.
        
    Returns:
        True if the file is too large, False otherwise.
    """
    try:
        return get_file_size(file_path) > max_size
    except OSError:
        # If we can't get the file size, assume it's too large to be safe
        return True


def scan_directory(
    directory: Path,
    config: ScannerConfig,
    recursive: bool = True
) -> Iterator[Path]:
    """Scan a directory for files that should be processed.
    
    Args:
        directory: Directory to scan.
        config: Scanner configuration.
        recursive: Whether to scan subdirectories recursively.
        
    Yields:
        Path objects for files that should be scanned.
        
    Raises:
        OSError: If the directory cannot be accessed.
    """
    if not directory.is_dir():
        raise OSError(f"Not a directory: {directory}")
    
    # Use glob pattern based on recursive flag
    pattern = "**/*" if recursive else "*"
    
    try:
        for path in directory.glob(pattern):
            # Skip directories
            if not path.is_file():
                continue
            
            # Skip excluded paths
            if is_path_excluded(path, config.excluded_patterns):
                continue
            
            # Skip unsupported file types
            if not is_file_supported(path, config.supported_extensions):
                continue
            
            # Skip files that are too large
            if is_file_too_large(path, config.max_file_size):
                continue
            
            yield path
            
    except PermissionError:
        # Skip directories we don't have permission to read
        pass


def get_scannable_files(
    target_path: Path,
    config: ScannerConfig
) -> List[Path]:
    """Get a list of files that should be scanned.
    
    Args:
        target_path: Path to scan (file or directory).
        config: Scanner configuration.
        
    Returns:
        List of Path objects for files to scan.
        
    Raises:
        FileNotFoundError: If the target path doesn't exist.
        OSError: If there are permission issues.
    """
    if not target_path.exists():
        raise FileNotFoundError(f"Path does not exist: {target_path}")
    
    files = []
    
    if target_path.is_file():
        # Single file
        if (not is_path_excluded(target_path, config.excluded_patterns) and
            is_file_supported(target_path, config.supported_extensions) and
            not is_file_too_large(target_path, config.max_file_size)):
            files.append(target_path)
    
    elif target_path.is_dir():
        # Directory - scan recursively
        files.extend(scan_directory(target_path, config, recursive=True))
    
    return sorted(files)






