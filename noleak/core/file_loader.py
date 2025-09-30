"""File loader with safe reading and encoding detection."""

import os
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import chardet

from ..config.settings import ScannerConfig

logger = logging.getLogger(__name__)


class FileLoader:
    """Handles safe loading and reading of files for scanning."""
    
    def __init__(self, config: ScannerConfig) -> None:
        """Initialize the file loader.
        
        Args:
            config: Scanner configuration.
        """
        self.config = config
        self._encoding_cache: Dict[str, str] = {}
    
    def read_file(self, file_path: Path) -> Optional[str]:
        """Read a file's contents safely with proper encoding detection.
        
        Args:
            file_path: Path to the file to read.
            
        Returns:
            File contents as string, or None if reading failed.
        """
        # Check file size first
        try:
            file_size = file_path.stat().st_size
            if file_size > self.config.max_file_size:
                return None
        except OSError:
            return None
        
        # Try cached encoding first
        file_key = str(file_path)
        if file_key in self._encoding_cache:
            encoding = self._encoding_cache[file_key]
            try:
                with open(file_path, "r", encoding=encoding, errors="ignore") as f:
                    return f.read()
            except (OSError, UnicodeDecodeError):
                # Remove from cache and fall through to detection
                del self._encoding_cache[file_key]
        
        # Detect encoding and read
        content = self._read_with_encoding_detection(file_path)
        
        return content
    
    def _read_with_encoding_detection(self, file_path: Path) -> Optional[str]:
        """Read file with automatic encoding detection.
        
        Args:
            file_path: Path to the file to read.
            
        Returns:
            File contents as string, or None if reading failed.
        """
        # Try common encodings first (fast path)
        common_encodings = ["utf-8", "utf-8-sig", "ascii"]
        
        for encoding in common_encodings:
            try:
                with open(file_path, "r", encoding=encoding, errors="strict") as f:
                    content = f.read()
                    self._encoding_cache[str(file_path)] = encoding
                    return content
            except (UnicodeDecodeError, OSError):
                continue
        
        # Fall back to chardet for encoding detection
        detected_encoding = self._detect_encoding(file_path)
        if detected_encoding:
            try:
                with open(file_path, "r", encoding=detected_encoding, errors="ignore") as f:
                    content = f.read()
                    self._encoding_cache[str(file_path)] = detected_encoding
                    return content
            except (OSError, UnicodeDecodeError):
                pass
        
        # Final fallback: try with different encodings and ignore errors
        fallback_encodings = ["latin1", "cp1252", "iso-8859-1"]
        for encoding in fallback_encodings:
            try:
                logger.warning(
                    f"Encoding issues with file: {file_path}. "
                    f"Using fallback encoding ({encoding}) with replacement strategy."
                )
                with open(file_path, "r", encoding=encoding, errors="replace") as f:
                    content = f.read()
                    self._encoding_cache[str(file_path)] = encoding
                    return content
            except OSError:
                continue
        
        return None
    
    def _detect_encoding(self, file_path: Path) -> Optional[str]:
        """Detect file encoding using chardet.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Detected encoding name, or None if detection failed.
        """
        try:
            # Read a sample of the file for detection
            sample_size = min(8192, self.config.chunk_size)
            
            with open(file_path, "rb") as f:
                raw_data = f.read(sample_size)
            
            if not raw_data:
                return "utf-8"  # Empty file, default to UTF-8
            
            result = chardet.detect(raw_data)
            if result and result["confidence"] > 0.5:
                return result["encoding"]
            
        except (OSError, Exception):
            # chardet might not be available or might fail
            pass
        
        return None
    
    def read_file_chunked(self, file_path: Path) -> List[str]:
        """Read a large file in chunks.
        
        Args:
            file_path: Path to the file to read.
            
        Returns:
            List of text chunks, or empty list if reading failed.
        """
        chunks = []
        
        # Detect encoding first
        encoding = self._encoding_cache.get(str(file_path))
        if not encoding:
            # Try to detect encoding with a small sample
            encoding = self._detect_encoding(file_path) or "utf-8"
        
        try:
            with open(file_path, "r", encoding=encoding, errors="ignore") as f:
                while True:
                    chunk = f.read(self.config.chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    
                    # Prevent reading too many chunks for very large files
                    if len(chunks) * self.config.chunk_size > self.config.max_file_size:
                        break
            
            # Cache the successful encoding
            self._encoding_cache[str(file_path)] = encoding
            
        except (OSError, UnicodeDecodeError):
            return []
        
        return chunks
    
    def is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is likely to be binary.
        
        Args:
            file_path: Path to the file to check.
            
        Returns:
            True if the file appears to be binary, False otherwise.
        """
        try:
            # Read a small sample to check for binary content
            with open(file_path, "rb") as f:
                sample = f.read(1024)
            
            if not sample:
                return False  # Empty file is not binary
            
            # Check for null bytes (common in binary files)
            if b'\x00' in sample:
                return True
            
            # Check for high ratio of non-printable characters
            non_printable = sum(1 for byte in sample if byte < 32 and byte not in (9, 10, 13))
            if len(sample) > 0 and non_printable / len(sample) > 0.1:
                return True
            
            return False
            
        except OSError:
            return True  # If we can't read it, assume it's binary
    
    def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get information about a file.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Dictionary with file information.
        """
        try:
            stat_info = file_path.stat()
            
            return {
                "path": str(file_path),
                "size": stat_info.st_size,
                "modified": stat_info.st_mtime,
                "is_binary": self.is_binary_file(file_path),
                "encoding": self._encoding_cache.get(str(file_path)),
                "readable": True
            }
        except OSError:
            return {
                "path": str(file_path),
                "size": 0,
                "modified": 0,
                "is_binary": True,
                "encoding": None,
                "readable": False
            }
    
    def preprocess_content(self, content: str) -> str:
        """Preprocess file content before scanning.
        
        Currently returns content unchanged for maximum scanning speed
        and reliability. Future versions may add optional preprocessing
        features such as comment removal and content normalization.
        
        Args:
            content: Raw file content.
            
        Returns:
            Content ready for pattern matching (currently unmodified).
        """
        # No preprocessing applied - prioritizing speed and reliability
        # Future enhancements could include:
        # - Comment removal for supported file types
        # - Whitespace normalization  
        # - String unescaping
        # - Base64/hex decoding
        return content
    
    def clear_encoding_cache(self) -> None:
        """Clear the encoding detection cache."""
        self._encoding_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get statistics about the encoding cache.
        
        Returns:
            Dictionary with cache statistics.
        """
        return {
            "cached_files": len(self._encoding_cache),
            "encodings_used": list(set(self._encoding_cache.values()))
        }
