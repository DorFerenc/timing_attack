"""
Statistical analysis service for timing data.

Implements ITimingAnalyzer interface with robust statistical methods.

Author: Your Name
Date: 2025
"""

import statistics
from typing import List, Tuple

from src.core.interfaces import ITimingAnalyzer, TimingMeasurement, CharacterAnalysis
from src.utils.stats import (
    remove_outliers,
    calculate_confidence_interval,
    is_significantly_different,
    median_absolute_deviation
)
from src.utils.logger import Logger


class AnalysisService(ITimingAnalyzer):
    """
    Statistical analyzer for timing side-channel data.

    Uses robust statistical methods to handle:
    - Network jitter and noise
    - Outlier measurements
    - Small sample sizes
    - False positives

    Key insight: Correct characters take LONGER because the comparison
    continues to the next character position.

    Example:
        >>> analyzer = AnalysisService(confidence=0.95, logger=logger)
        >>> analysis = analyzer.analyze_measurements(measurements)
        >>> print(f"Character 'a': {analysis.median_time:.6f}s")
    """

    def __init__(
        self,
        confidence_level: float = 0.95,
        min_time_difference: float = 0.001,  # 1ms
        outlier_threshold: float = 3.0,
        logger: Logger = None
    ):
        """
        Initialize analysis service.

        Args:
            confidence_level: Statistical confidence (0-1)
            min_time_difference: Minimum detectable time difference (seconds)
            outlier_threshold: Standard deviations for outlier detection
            logger: Logger instance
        """
        self.confidence_level = confidence_level
        self.min_time_difference = min_time_difference
        self.outlier_threshold = outlier_threshold
        self.logger = logger or Logger()

    def analyze_measurements(
        self,
        measurements: List[TimingMeasurement]
    ) -> CharacterAnalysis:
        """
        Perform statistical analysis on timing measurements.

        Process:
        1. Extract timing data
        2. Remove outliers (network spikes)
        3. Calculate robust statistics
        4. Compute confidence score

        Args:
            measurements: List of timing measurements for one character

        Returns:
            CharacterAnalysis with statistical metrics
        """
        if not measurements:
            return CharacterAnalysis(
                character='',
                mean_time=0.0,
                median_time=0.0,
                std_dev=0.0,
                confidence_score=0.0,
                sample_size=0
            )

        # Extract character (should be same for all measurements)
        character = measurements[0].password[-1]

        # Extract timing data
        times = [m.elapsed_time for m in measurements if m.success]

        if not times:
            return CharacterAnalysis(
                character=character,
                mean_time=0.0,
                median_time=0.0,
                std_dev=0.0,
                confidence_score=0.0,
                sample_size=0
            )

        # Remove outliers for robust statistics
        cleaned_times = remove_outliers(times, self.outlier_threshold)

        # Calculate statistics
        mean_time = statistics.mean(cleaned_times)
        median_time = statistics.median(cleaned_times)
        std_dev = statistics.stdev(cleaned_times) if len(cleaned_times) > 1 else 0.0

        # Calculate confidence score based on:
        # 1. Sample size (more samples = higher confidence)
        # 2. Low variance (consistent measurements = higher confidence)
        # 3. Confidence interval width

        confidence_score = self._calculate_confidence(
            cleaned_times, std_dev
        )

        self.logger.debug(
            f"'{character}': mean={mean_time:.6f}s, median={median_time:.6f}s, "
            f"σ={std_dev:.6f}s, conf={confidence_score:.3f}"
        )

        return CharacterAnalysis(
            character=character,
            mean_time=mean_time,
            median_time=median_time,
            std_dev=std_dev,
            confidence_score=confidence_score,
            sample_size=len(cleaned_times)
        )

    def _calculate_confidence(
        self,
        times: List[float],
        std_dev: float
    ) -> float:
        """
        Calculate confidence score (0-1) for the measurements.

        Higher confidence when:
        - More samples collected
        - Lower variance (more consistent)
        - Tighter confidence interval

        Args:
            times: List of timing measurements
            std_dev: Standard deviation of measurements

        Returns:
            Confidence score between 0 and 1
        """
        if len(times) < 2:
            return 0.0

        # Factor 1: Sample size (normalized, capped at 20 samples)
        sample_factor = min(len(times) / 20.0, 1.0)

        # Factor 2: Consistency (inverse of coefficient of variation)
        mean_time = statistics.mean(times)
        if mean_time > 0:
            cv = std_dev / mean_time  # Coefficient of variation
            consistency_factor = 1.0 / (1.0 + cv)
        else:
            consistency_factor = 0.0

        # Factor 3: Confidence interval width
        ci_lower, ci_upper = calculate_confidence_interval(
            times, self.confidence_level
        )
        ci_width = ci_upper - ci_lower
        ci_factor = 1.0 / (1.0 + ci_width * 1000)  # Scale to reasonable range

        # Weighted combination
        confidence = (
            0.4 * sample_factor +
            0.4 * consistency_factor +
            0.2 * ci_factor
        )

        return confidence

    def compare_candidates(
        self,
        analyses: List[CharacterAnalysis]
    ) -> Tuple[str, float]:
        """
        Select the best character candidate from statistical analyses.

        Strategy:
        1. Primary criterion: LONGEST median time (correct char takes longer)
        2. Secondary criterion: Highest confidence score
        3. Validation: Check if timing difference is statistically significant

        Args:
            analyses: List of character analyses to compare

        Returns:
            Tuple of (best_character, confidence_score)

        Raises:
            ValueError: If no valid analyses provided
        """
        if not analyses:
            raise ValueError("No character analyses provided")

        # Filter out invalid analyses
        valid_analyses = [
            a for a in analyses
            if a.sample_size >= 2 and a.median_time > 0
        ]

        if not valid_analyses:
            self.logger.warning("No valid analyses, returning first character")
            return analyses[0].character, 0.0

        # Sort by median time (descending) - longest time is likely correct
        sorted_by_time = sorted(
            valid_analyses,
            key=lambda a: a.median_time,
            reverse=True
        )

        best = sorted_by_time[0]
        second_best = sorted_by_time[1] if len(sorted_by_time) > 1 else None

        # Log top candidates for debugging
        self.logger.info(
            f"Top candidate: '{best.character}' "
            f"({best.median_time:.6f}s, conf={best.confidence_score:.3f})"
        )

        if second_best:
            time_diff = best.median_time - second_best.median_time
            self.logger.info(
                f"Runner-up: '{second_best.character}' "
                f"({second_best.median_time:.6f}s, Δ={time_diff:.6f}s)"
            )

            # Check if difference is significant
            if time_diff < self.min_time_difference:
                self.logger.warning(
                    f"Small timing difference ({time_diff:.6f}s), "
                    "result may be unreliable"
                )

        return best.character, best.confidence_score