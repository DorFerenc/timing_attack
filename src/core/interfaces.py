"""
Abstract interfaces for the timing attack system.

This module defines the contracts (interfaces) that all concrete implementations
must follow. This adheres to the Dependency Inversion Principle (SOLID: D).

Author: Your Name
Date: 2025
"""

from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class TimingMeasurement:
    """
    Immutable data class representing a single timing measurement.

    Attributes:
        password: The password candidate that was tested
        elapsed_time: Time taken for the request in seconds
        success: Whether the request completed successfully
        is_correct: Whether this password was the correct one
    """
    password: str
    elapsed_time: float
    success: bool
    is_correct: bool = False


@dataclass
class CharacterAnalysis:
    """
    Result of analyzing timing data for a character guess.

    Attributes:
        character: The character that was tested
        mean_time: Average response time
        median_time: Median response time (more robust to outliers)
        std_dev: Standard deviation of measurements
        confidence_score: Statistical confidence in this result (0-1)
        sample_size: Number of measurements taken
    """
    character: str
    mean_time: float
    median_time: float
    std_dev: float
    confidence_score: float
    sample_size: int


class IHttpClient(ABC):
    """
    Interface for HTTP communication.

    This abstraction allows us to swap implementations (e.g., for testing)
    without changing the attack logic. (SOLID: D - Dependency Inversion)
    """

    @abstractmethod
    def send_request(self, password: str, username: str, difficulty: int) -> TimingMeasurement:
        """
        Send a single password verification request.

        Args:
            password: Password candidate to test
            username: Username for authentication
            difficulty: Difficulty level

        Returns:
            TimingMeasurement object with timing and result data

        Raises:
            ConnectionError: If unable to connect to server
            TimeoutError: If request times out
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Clean up resources (connections, sessions, etc.)."""
        pass


class ITimingAnalyzer(ABC):
    """
    Interface for statistical timing analysis.

    Separates the concern of measuring from analyzing. (SOLID: S)
    """

    @abstractmethod
    def analyze_measurements(self, measurements: List[TimingMeasurement]) -> CharacterAnalysis:
        """
        Analyze a collection of timing measurements.

        Args:
            measurements: List of timing measurements for a character

        Returns:
            CharacterAnalysis with statistical metrics
        """
        pass

    @abstractmethod
    def compare_candidates(
        self,
        analyses: List[CharacterAnalysis]
    ) -> Tuple[str, float]:
        """
        Compare multiple character analyses and select the best candidate.

        Args:
            analyses: List of character analyses to compare

        Returns:
            Tuple of (best_character, confidence_score)
        """
        pass


class IAttackStrategy(ABC):
    """
    Interface for different attack strategies.

    This allows us to implement different algorithms while keeping
    the same interface. (SOLID: O - Open/Closed Principle)
    """

    @abstractmethod
    def crack_password(
        self,
        username: str,
        difficulty: int,
        max_length: int
    ) -> str:
        """
        Execute the attack to recover the password.

        Args:
            username: Target username
            difficulty: Attack difficulty level
            max_length: Maximum password length to try

        Returns:
            The recovered password

        Raises:
            AttackFailedException: If unable to recover password
        """
        pass


class ILogger(ABC):
    """Interface for logging functionality."""

    @abstractmethod
    def debug(self, message: str) -> None:
        """Log debug message."""
        pass

    @abstractmethod
    def info(self, message: str) -> None:
        """Log info message."""
        pass

    @abstractmethod
    def warning(self, message: str) -> None:
        """Log warning message."""
        pass

    @abstractmethod
    def error(self, message: str) -> None:
        """Log error message."""
        pass