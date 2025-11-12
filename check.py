"""
Quick comparison test for parallel vs sequential timing collection
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_SAMPLES = 15
MIN_SAMPLES = 4
# URL = "http://127.0.0.1/?user=316279942&password=baaaaaaaaaaaaaaa&difficulty=1"
# URL = "http://aoi-assignment1.oy.ne.ro:8080/?user=316279942&password=baaaaaaaaaaaaaaa&difficulty=1"
URL = "http://aoi-assignment1.oy.ne.ro:8080/?user=208145268&password=ndbmitipwidpnlll&difficulty=1"

def test_sequential(url, samples, max_retries=3):
    """Collect samples sequentially with retry and skip on failure"""
    total = 0.0
    success_count = 0
    for _ in range(samples):
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=5)
                total += response.elapsed.total_seconds()
                success_count += 1
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    print(f"[Sequential] Sample failed after {max_retries} attempts: {e}")
    if success_count == 0:
        return 0.0
    return total / success_count

def test_parallel(url, samples, workers, max_retries=3):
    """Collect samples in parallel with retry and skip on failure"""
    total = 0.0
    success_count = 0
    def safe_request():
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=5)
                return response.elapsed.total_seconds()
            except Exception as e:
                if attempt == max_retries - 1:
                    print(f"[Parallel] Sample failed after {max_retries} attempts: {e}")
        return None
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(safe_request) for _ in range(samples)]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                total += result
                success_count += 1
    if success_count == 0:
        return 0.0
    return total / success_count


def auto_search_best_config():
    print("=" * 60)
    print("Auto-searching best SAMPLES and WORKERS configuration...")
    print("=" * 60)
    SAFETY_THRESHOLD = 0.1  # 10% difference
    results = []

    # Warmup
    print("\nWarmup...")
    for _ in range(3):
        requests.get(URL)

    for samples in range(MIN_SAMPLES, MAX_SAMPLES + 1):
        for workers in range(1, samples + 1):
            # Sequential
            start = time.time()
            avg_seq = test_sequential(URL, samples)
            seq_elapsed = time.time() - start
            # Parallel
            start = time.time()
            avg_par = test_parallel(URL, samples, workers)
            par_elapsed = time.time() - start
            timing_diff = abs(avg_seq - avg_par)
            timing_diff_pct = timing_diff / avg_seq * 100 if avg_seq else 0
            is_safe = timing_diff / avg_seq < SAFETY_THRESHOLD if avg_seq else False
            speedup = seq_elapsed / par_elapsed if par_elapsed else 0
            efficiency = speedup / workers * 100 if workers else 0
            results.append({
                "samples": samples,
                "workers": workers,
                "avg_seq": avg_seq,
                "avg_par": avg_par,
                "seq_elapsed": seq_elapsed,
                "par_elapsed": par_elapsed,
                "timing_diff_pct": timing_diff_pct,
                "is_safe": is_safe,
                "speedup": speedup,
                "efficiency": efficiency
            })
            print(f"Tested: samples={samples}, workers={workers} | safe={'✓' if is_safe else '✗'} | speedup={speedup:.2f}x | efficiency={efficiency:.1f}% | diff={timing_diff_pct:.1f}%")

    # Find best config: safe, highest speedup
    safe_results = [r for r in results if r["is_safe"]]
    if safe_results:
        best = max(safe_results, key=lambda r: r["speedup"])
        print("\n" + "=" * 60)
        print("BEST CONFIGURATION (safe & fastest)")
        print("=" * 60)
        print(f"Samples: {best['samples']}")
        print(f"Workers: {best['workers']}")
        print(f"Speedup: {best['speedup']:.2f}x")
        print(f"Efficiency: {best['efficiency']:.1f}%")
        print(f"Timing diff: {best['timing_diff_pct']:.1f}%")
        print(f"Sequential time: {best['seq_elapsed']:.2f}s")
        print(f"Parallel time: {best['par_elapsed']:.2f}s")
        print("=" * 60)
    else:
        print("No safe configuration found (all parallel results differ too much from sequential)")

if __name__ == "__main__":
    auto_search_best_config()