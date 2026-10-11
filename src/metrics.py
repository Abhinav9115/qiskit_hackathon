"""
Benchmarking Metrics, Statistical Analysis, and Resource Profiling Engine for QSC.
Computes Mean, Median, StdDev, p95, and 95% Bootstrap Confidence Intervals.
Profiles peak RSS (psutil), Python heap (tracemalloc), and exact wire byte overhead.
"""

from __future__ import annotations

import gc
import math
import time
import random
import tracemalloc
import psutil
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional


def compute_statistics(values: List[float]) -> Dict[str, float]:
    """
    Computes Median, Mean, StdDev, p95, and 95% Bootstrap Confidence Intervals.
    """
    if not values:
        return {
            "count": 0,
            "mean": 0.0,
            "median": 0.0,
            "std": 0.0,
            "p95": 0.0,
            "ci_95_lower": 0.0,
            "ci_95_upper": 0.0,
        }

    n = len(values)
    s_vals = sorted(values)
    mean_val = sum(s_vals) / n
    median_val = s_vals[n // 2] if n % 2 != 0 else (s_vals[n // 2 - 1] + s_vals[n // 2]) / 2.0

    variance = sum((x - mean_val) ** 2 for x in s_vals) / max(1, n - 1)
    std_val = math.sqrt(variance)

    # 95th Percentile
    p95_idx = int(math.ceil(0.95 * n)) - 1
    p95_val = s_vals[min(max(0, p95_idx), n - 1)]

    # 95% Bootstrap Confidence Interval for Mean (1000 resamples)
    boot_means = []
    rng = random.Random(42)
    for _ in range(1000):
        sample = [rng.choice(values) for _ in range(n)]
        boot_means.append(sum(sample) / n)
    boot_means.sort()
    ci_lower = boot_means[int(0.025 * len(boot_means))]
    ci_upper = boot_means[int(0.975 * len(boot_means))]

    return {
        "count": n,
        "mean": mean_val,
        "median": median_val,
        "std": std_val,
        "p95": p95_val,
        "ci_95_lower": ci_lower,
        "ci_95_upper": ci_upper,
    }


class ResourceProfiler:
    """
    Tracks memory allocations (tracemalloc heap peak) and process RSS memory (psutil).
    """

    def __init__(self):
        self.process = psutil.Process()
        self.initial_rss = 0
        self.peak_rss = 0
        self.peak_heap_bytes = 0

    def start(self) -> None:
        gc.collect()
        self.initial_rss = self.process.memory_info().rss
        self.peak_rss = self.initial_rss
        tracemalloc.start()

    def update(self) -> None:
        current_rss = self.process.memory_info().rss
        if current_rss > self.peak_rss:
            self.peak_rss = current_rss

    def stop(self) -> Dict[str, Any]:
        self.update()
        current, peak_heap = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.peak_heap_bytes = peak_heap
        rss_delta = max(0, self.peak_rss - self.initial_rss)

        return {
            "initial_rss_bytes": self.initial_rss,
            "peak_rss_bytes": self.peak_rss,
            "rss_delta_bytes": rss_delta,
            "peak_heap_bytes": peak_heap,
            "peak_rss_mb": self.peak_rss / (1024 * 1024),
            "peak_heap_mb": peak_heap / (1024 * 1024),
        }


class WireByteTracker:
    """
    Accumulates exact wire byte transmissions broken down by message flight.
    """

    def __init__(self):
        self.records: Dict[str, int] = {}

    def record(self, flight_name: str, num_bytes: int) -> None:
        self.records[flight_name] = self.records.get(flight_name, 0) + num_bytes

    def total_handshake_bytes(self) -> int:
        return sum(v for k, v in self.records.items() if "payload" not in k.lower())

    def get_summary(self) -> Dict[str, int]:
        return dict(self.records)
