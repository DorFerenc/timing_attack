"""
Statistical utility functions for timing analysis.

Provides robust statistical methods that handle outliers and noise.

Author: Your Name
Date: 2025
"""

import statistics
from typing import List, Tuple
import numpy as np
from scipy import stats


def remove_outliers(data: List[float], std_dev_threshold: float = 3.0) -> List[float]:
    """
    Remove outliers using the Z-score method.

    Points more than `std_dev_threshold` standard deviations from
    the mean are considered outliers.

    Args:
        data: List of numerical values
        std_dev_threshold: Number of standard deviations for outlier detection

    Returns:
        List with outliers removed

    Example:
        >>> data = [1, 2, 2, 3, 2, 100]  # 100 is outlier
        >>> remove_outliers(data)
        [1, 2, 2, 3, 2]
    """
    if len(data) < 3:
        return data

    mean = statistics.mean(data)
    std_dev = statistics.stdev(data)

    if std_dev == 0:
        return data

    return [
        x for x in data
        if abs((x - mean) / std_dev) <= std_dev_threshold
    ]


def calculate_confidence_interval(
    data: List[float],
    confidence: float = 0.95
) -> Tuple[float, float]:
    """
    Calculate confidence interval for the mean.

    Uses t-distribution for small sample sizes.

    Args:
        data: List of numerical values
        confidence: Confidence level (0-1)

    Returns:
        Tuple of (lower_bound, upper_bound)
    """
    if len(data) < 2:
        return (0.0, 0.0)

    n = len(data)
    mean = np.mean(data)
    std_err = stats.sem(data)

    # Use t-distribution for small samples
    t_value = stats.t.ppf((1 + confidence) / 2, n - 1)
    margin_of_error = t_value * std_err

    return (mean - margin_of_error, mean + margin_of_error)


def is_significantly_different(
    data1: List[float],
    data2: List[float],
    alpha: float = 0.05
) -> Tuple[bool, float]:
    """
    Test if two datasets are significantly different using t-test.

    Args:
        data1: First dataset
        data2: Second dataset
        alpha: Significance level (typically 0.05)

    Returns:
        Tuple of (is_different, p_value)

    Example:
        >>> fast = [0.1, 0.11, 0.09, 0.1]
        >>> slow = [0.2, 0.21, 0.19, 0.2]
        >>> is_different, p = is_significantly_different(fast, slow)
        >>> is_different
        True
    """
    if len(data1) < 2 or len(data2) < 2:
        return False, 1.0

    # Perform Welch's t-test (doesn't assume equal variances)
    statistic, p_value = stats.ttest_ind(data1, data2, equal_var=False)

    return p_value < alpha, p_value


def robust_mean(data: List[float]) -> float:
    """
    Calculate mean after removing outliers.

    More robust than simple mean for noisy data.

    Args:
        data: List of numerical values

    Returns:
        Robust mean value
    """
    cleaned = remove_outliers(data)
    return statistics.mean(cleaned) if cleaned else 0.0


def median_absolute_deviation(data: List[float]) -> float:
    """
    Calculate Median Absolute Deviation (MAD).

    More robust measure of variability than standard deviation.

    Args:
        data: List of numerical values

    Returns:
        MAD value
    """
    if not data:
        return 0.0

    median = statistics.median(data)
    deviations = [abs(x - median) for x in data]
    return statistics.median(deviations)