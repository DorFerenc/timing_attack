"""
Custom exceptions for the timing attack system.

Provides specific, meaningful exceptions for different failure modes.
This improves debugging and error handling.

Author: Your Name
Date: 2025
"""


class TimingAttackException(Exception):
    """Base exception for all timing attack errors."""
    pass


class ConnectionFailedException(TimingAttackException):
    """Raised when unable to connect to the target server."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Failed to connect to {url}: {reason}")


class InsufficientDataException(TimingAttackException):
    """Raised when not enough timing data collected for reliable analysis."""

    def __init__(self, samples_collected: int, samples_required: int):
        self.samples_collected = samples_collected
        self.samples_required = samples_required
        super().__init__(
            f"Insufficient data: collected {samples_collected}, "
            f"need {samples_required}"
        )


class AttackFailedException(TimingAttackException):
    """Raised when the attack fails to recover the password."""

    def __init__(self, position: int, reason: str):
        self.position = position
        self.reason = reason
        super().__init__(
            f"Attack failed at position {position}: {reason}"
        )


class ConfigurationError(TimingAttackException):
    """Raised when configuration is invalid or missing."""
    pass