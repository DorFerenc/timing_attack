"""
Utilities: Logging, exceptions, and configuration helpers.
Consolidates logger.py and exceptions.py.
"""

import logging
import sys
import io
from pathlib import Path
from typing import Optional
import os
from dotenv import load_dotenv


# ============================================
# EXCEPTIONS
# ============================================

class TimingAttackException(Exception):
    """Base exception for timing attack errors."""
    pass


class ConnectionFailedException(TimingAttackException):
    """Raised when HTTP connection fails."""
    def __init__(self, url: str, error: str):
        self.url = url
        self.error = error
        super().__init__(f"Connection failed to {url}: {error}")


class InsufficientDataException(TimingAttackException):
    """Raised when not enough timing samples collected."""
    def __init__(self, samples_collected: int, samples_required: int):
        self.samples_collected = samples_collected
        self.samples_required = samples_required
        super().__init__(
            f"Insufficient data: {samples_collected}/{samples_required} samples"
        )


class AttackFailedException(TimingAttackException):
    """Raised when attack fails at a specific position."""
    def __init__(self, position: int, reason: str):
        self.position = position
        self.reason = reason
        super().__init__(f"Attack failed at position {position}: {reason}")


class ConfigurationError(TimingAttackException):
    """Raised for configuration errors."""
    pass


# ============================================
# LOGGER
# ============================================

class Logger:
    """Simple logger with UTF-8 console support."""

    def __init__(
        self,
        name: str = "TimingAttack",
        level: str = "INFO",
        log_file: Optional[str] = None
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers.clear()

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Console handler with UTF-8 support
        utf8_stdout = io.TextIOWrapper(
            sys.stdout.buffer,
            encoding='utf-8',
            errors='replace',
            line_buffering=True
        )
        console_handler = logging.StreamHandler(utf8_stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message: str):
        self.logger.debug(message)

    def info(self, message: str):
        self.logger.info(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)


# ============================================
# CONFIGURATION
# ============================================

def load_config():
    """Load configuration from .env file."""
    load_dotenv()

    def get_bool(key: str, default: bool = False) -> bool:
        """Get boolean from env."""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes')

    def get_int(key: str, default: int) -> int:
        """Get integer from env."""
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            return default

    def get_float(key: str, default: float) -> float:
        """Get float from env."""
        try:
            return float(os.getenv(key, str(default)))
        except ValueError:
            return default

    return {
        # Required
        'target_username': os.getenv('TARGET_USERNAME', ''),

        # Server
        'use_local_server': get_bool('USE_LOCAL_SERVER', True),
        'server_timeout': get_int('SERVER_TIMEOUT', 10),
        'server_max_retries': get_int('SERVER_MAX_RETRIES', 3),

        # Attack
        'difficulty': get_int('ATTACK_DIFFICULTY', 1),
        'max_length': get_int('MAX_PASSWORD_LENGTH', 32),
        'charset': os.getenv('CHARSET', 'abcdefghijklmnopqrstuvwxyz'),

        # Performance
        'parallel_requests': get_bool('PARALLEL_REQUESTS', True),
        'max_workers': get_int('MAX_WORKERS', 10),
        'pool_size': get_int('POOL_SIZE', 10),

        # Sampling
        'initial_samples': get_int('INITIAL_SAMPLES', 10),
        'middle_samples': get_int('MIDDLE_SAMPLES', 8),
        'final_samples': get_int('FINAL_SAMPLES', 5),
        'min_samples': get_int('MIN_SAMPLES', 3),

        # Statistical
        'confidence_level': get_float('CONFIDENCE_LEVEL', 0.95),
        'min_time_difference': get_float('MIN_TIME_DIFFERENCE', 0.001),
        'outlier_std_dev': get_float('OUTLIER_STD_DEV', 3.0),

        # Logging
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),
        'log_to_file': get_bool('LOG_TO_FILE', True),
        'log_file': os.getenv('LOG_FILE', 'attack.log'),
    }
