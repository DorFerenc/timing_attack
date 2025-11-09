"""
Logging utility with console and file output.

Implements ILogger interface for dependency injection.

Author: Your Name
Date: 2025
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from core.interfaces import ILogger


class Logger(ILogger):
    """
    Concrete implementation of logging functionality.

    Provides both console and file logging with configurable levels.
    Thread-safe for parallel operations.
    """

    def __init__(
        self,
        name: str = "TimingAttack",
        level: str = "INFO",
        log_file: Optional[str] = None,
        console: bool = True
    ):
        """
        Initialize logger.

        Args:
            name: Logger name
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for log output
            console: Whether to log to console
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))

        # Clear any existing handlers
        self.logger.handlers.clear()

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Console handler with UTF-8 encoding support
        if console:
            # Force UTF-8 encoding for console output to handle Unicode characters
            import io
            utf8_stdout = io.TextIOWrapper(
                sys.stdout.buffer,
                encoding='utf-8',
                errors='replace',  # Replace unencodable characters
                line_buffering=True
            )
            console_handler = logging.StreamHandler(utf8_stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # File handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(message)

    def info(self, message: str) -> None:
        """Log info message."""
        self.logger.info(message)

    def warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(message)

    def error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(message)