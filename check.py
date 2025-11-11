"""
Quick comparison test for parallel vs sequential timing collection
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKERS = 13
SAMPLES = 12
# URL = "http://127.0.0.1/?user=316279942&password=baaaaaaaaaaaaaaa&difficulty=1"
URL = "http://aoi-assignment1.oy.ne.ro:8080/?user=316279942&password=baaaaaaaaaaaaaaa&difficulty=1"

def test_sequential(url, samples=SAMPLES):
    """Collect samples sequentially"""
    total = 0.0
    for _ in range(samples):
        response = requests.get(url)
        total += response.elapsed.total_seconds()
    return total / samples

def test_parallel(url, samples=SAMPLES, workers=WORKERS):
    """Collect samples in parallel"""
    total = 0.0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(requests.get, url) for _ in range(samples)]
        for future in as_completed(futures):
            response = future.result()
            total += response.elapsed.total_seconds()
    return total / samples

def main():


    print("=" * 60)
    print("Testing timing measurement methods")
    print("=" * 60)

    # Warmup
    print("\nWarmup...")
    for _ in range(3):
        requests.get(URL)

    # Sequential test
    print(f"\nSequential sample collection ({SAMPLES} samples):")
    start = time.time()
    avg_seq = test_sequential(URL, samples=SAMPLES)
    seq_elapsed = time.time() - start
    print(f"  Average response time: {avg_seq:.6f}s")
    print(f"  Total measurement time: {seq_elapsed:.2f}s")

    # Parallel test with workers
    print(f"\nParallel sample collection ({SAMPLES} samples, {WORKERS} workers):")
    start = time.time()
    avg_par = test_parallel(URL, samples=SAMPLES, workers=WORKERS)
    par_elapsed = time.time() - start
    print(f"  Average response time: {avg_par:.6f}s")
    print(f"  Total measurement time: {par_elapsed:.2f}s")
    print(f"  Speedup: {seq_elapsed/par_elapsed:.2f}x")

    # Result comparison
    print("\n" + "=" * 60)
    print("ANALYSIS")
    print("=" * 60)

    timing_diff = abs(avg_seq - avg_par)
    timing_diff_pct = timing_diff / avg_seq * 100
    print(f"\nTiming difference: {timing_diff:.6f}s ({timing_diff_pct:.1f}%)")

    # Safety check (accuracy)
    SAFETY_THRESHOLD = 0.1  # 10% difference
    is_safe = timing_diff / avg_seq < SAFETY_THRESHOLD
    print(f"\nSafety (accuracy): {'✓ PASS' if is_safe else '✗ FAIL'}")
    if is_safe:
        print(f"  Parallel results are within {SAFETY_THRESHOLD*100:.0f}% of sequential")
    else:
        print(f"  Parallel results differ by {timing_diff_pct:.1f}% - too much variance!")

    # Performance check (speed)
    speedup = seq_elapsed / par_elapsed
    efficiency = speedup / WORKERS * 100
    print(f"\nPerformance (speed): {speedup:.2f}x speedup")
    print(f"  Parallel time: {par_elapsed:.2f}s")
    print(f"  Sequential time: {seq_elapsed:.2f}s")
    print(f"  Efficiency: {efficiency:.1f}% (ideal: 100%)")

    # Overall recommendation
    print("\n" + "=" * 60)
    print("RECOMMENDATION")
    print("=" * 60)

    if is_safe and speedup > 1.5:
        print(f"✓ USE PARALLEL MODE")
        print(f"  - Results are accurate (within {SAFETY_THRESHOLD*100:.0f}% threshold)")
        print(f"  - Performance is {speedup:.2f}x faster than sequential")
    elif is_safe and speedup >= 1.0:
        print(f"~ PARALLEL IS SAFE BUT OFFERS LIMITED SPEEDUP")
        print(f"  - Results are accurate (within {SAFETY_THRESHOLD*100:.0f}% threshold)")
        print(f"  - Only {speedup:.2f}x faster - overhead may not justify complexity")
    elif is_safe:
        print(f"~ USE SEQUENTIAL MODE")
        print(f"  - Results are accurate")
        print(f"  - Parallel is slower ({speedup:.2f}x) - overhead exceeds benefits")
    else:
        print(f"✗ USE SEQUENTIAL MODE")
        print(f"  - Parallel results are unreliable (differ by {timing_diff_pct:.1f}%)")
        print(f"  - Accuracy is more important than speed")

    print("=" * 60)

if __name__ == "__main__":
    main()