"""
Quick comparison test for parallel vs sequential timing collection
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_sequential(url, samples=5):
    """Collect samples sequentially"""
    total = 0.0
    for _ in range(samples):
        response = requests.get(url)
        total += response.elapsed.total_seconds()
    return total / samples

def test_parallel(url, samples=5, workers=3):
    """Collect samples in parallel"""
    total = 0.0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(requests.get, url) for _ in range(samples)]
        for future in as_completed(futures):
            response = future.result()
            total += response.elapsed.total_seconds()
    return total / samples

def main():
    url = "http://127.0.0.1/?user=316279942&password=baaaaaaaaaaaaaaa&difficulty=1"

    print("=" * 60)
    print("Testing timing measurement methods")
    print("=" * 60)

    # Warmup
    print("\nWarmup...")
    for _ in range(3):
        requests.get(url)

    # Sequential test
    print("\nSequential sample collection (5 samples):")
    start = time.time()
    avg_seq = test_sequential(url, samples=5)
    seq_elapsed = time.time() - start
    print(f"  Average response time: {avg_seq:.6f}s")
    print(f"  Total measurement time: {seq_elapsed:.2f}s")

    # Parallel test with 3 workers
    workers = 3
    print(f"\nParallel sample collection (5 samples, {workers} workers):")
    start = time.time()
    avg_par = test_parallel(url, samples=5, workers=workers)
    par_elapsed = time.time() - start
    print(f"  Average response time: {avg_par:.6f}s")
    print(f"  Total measurement time: {par_elapsed:.2f}s")
    print(f"  Speedup: {seq_elapsed/par_elapsed:.2f}x")

    # Result comparison
    print("\n" + "=" * 60)
    print(f"Timing difference: {abs(avg_seq - avg_par):.6f}s ({abs(avg_seq - avg_par)/avg_seq*100:.1f}%)")

    if abs(avg_seq - avg_par) / avg_seq < 0.1:
        print("✓ Results are similar - parallel is safe to use")
    else:
        print("✗ Results differ significantly - use sequential mode")
    print("=" * 60)

if __name__ == "__main__":
    main()