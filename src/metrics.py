"""
Benchmarking Metrics, Statistical Analysis, and Resource Profiling Engine for QSC.
Computes Mean, Median, StdDev, p95, and 95% Bootstrap Confidence Intervals.
Profiles peak RSS (psutil), Python heap (tracemalloc), and exact wire byte overhead.
"""

from __future__ import annotations

import os
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


try:
    import resource
except ImportError:
    resource = None

from pathlib import Path


def get_effective_affinity() -> set[int]:
    """
    Returns the set of CPU cores this process is effectively restricted to.
    """
    if hasattr(os, "sched_getaffinity"):
        try:
            return set(os.sched_getaffinity(0))
        except Exception:
            pass
    return set()


def get_cgroup_memory(cgroup_name: Optional[str] = None) -> Dict[str, Optional[int]]:
    """
    Reads cgroup v2 memory.current, memory.max, and memory.peak for the active process.
    First checks explicitly specified cgroup_name, then resolves from /proc/self/cgroup.
    """
    candidate_paths: List[Path] = []
    if cgroup_name:
        candidate_paths.append(Path(f"/sys/fs/cgroup/{cgroup_name}"))

    # Resolve from active process cgroup membership (/proc/self/cgroup)
    try:
        proc_cg = Path("/proc/self/cgroup")
        if proc_cg.exists():
            for line in proc_cg.read_text().splitlines():
                parts = line.split("::")
                if len(parts) == 2:
                    rel = parts[1].strip().lstrip("/")
                    if rel:
                        candidate_paths.append(Path("/sys/fs/cgroup") / rel)
    except Exception:
        pass

    candidate_paths.append(Path("/sys/fs/cgroup"))

    res: Dict[str, Optional[int]] = {
        "cgroup_current_bytes": None,
        "cgroup_peak_bytes": None,
        "cgroup_max_bytes": None,
    }

    for base in candidate_paths:
        cur_file = base / "memory.current"
        peak_file = base / "memory.peak"
        max_file = base / "memory.max"

        has_data = False
        if cur_file.exists():
            try:
                res["cgroup_current_bytes"] = int(cur_file.read_text().strip())
                has_data = True
            except Exception:
                pass
        if peak_file.exists():
            try:
                res["cgroup_peak_bytes"] = int(peak_file.read_text().strip())
                has_data = True
            except Exception:
                pass
        if max_file.exists():
            try:
                val = max_file.read_text().strip()
                res["cgroup_max_bytes"] = int(val) if val != "max" else None
                has_data = True
            except Exception:
                pass

        if has_data and (res["cgroup_max_bytes"] is not None or base.name != "cgroup"):
            break

    return res


def get_code_size(src_dir: str = "src") -> Dict[str, Any]:
    """
    Calculates source code size (SLOC, total lines, blank lines, bytes) for evaluation metrics.
    """
    src_path = Path(src_dir)
    file_stats = {}
    total_sloc = 0
    total_lines = 0
    total_bytes = 0

    for py_file in sorted(src_path.glob("*.py")):
        content = py_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        sloc = sum(1 for line in lines if line.strip() and not line.strip().startswith("#"))
        f_bytes = len(content.encode("utf-8"))
        file_stats[py_file.name] = {
            "sloc": sloc,
            "total_lines": len(lines),
            "bytes": f_bytes,
        }
        total_sloc += sloc
        total_lines += len(lines)
        total_bytes += f_bytes

    return {
        "files": file_stats,
        "total_sloc": total_sloc,
        "total_lines": total_lines,
        "total_bytes": total_bytes,
    }


class ResourceProfiler:
    """
    Tracks memory allocations (tracemalloc heap peak), process RSS (getrusage + psutil),
    and kernel cgroup v2 peak memory.
    """

    def __init__(self, cgroup_name: Optional[str] = None):
        self.process = psutil.Process()
        self.initial_rss = 0
        self.peak_rss = 0
        self.peak_heap_bytes = 0
        self.cgroup_name = cgroup_name
        self.cgroup_initial = {}

    def start(self) -> None:
        gc.collect()
        self.initial_rss = self.process.memory_info().rss
        self.peak_rss = self.initial_rss
        self.cgroup_initial = get_cgroup_memory(self.cgroup_name)
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

        # Linux getrusage reports ru_maxrss in kilobytes
        kernel_peak_rss_bytes = 0
        if resource is not None:
            ru = resource.getrusage(resource.RUSAGE_SELF)
            kernel_peak_rss_bytes = ru.ru_maxrss * 1024

        cgroup_final = get_cgroup_memory(self.cgroup_name)

        return {
            "initial_rss_bytes": self.initial_rss,
            "peak_rss_bytes": max(self.peak_rss, kernel_peak_rss_bytes),
            "kernel_peak_rss_bytes": kernel_peak_rss_bytes,
            "rss_delta_bytes": rss_delta,
            "peak_heap_bytes": peak_heap,
            "peak_rss_mb": max(self.peak_rss, kernel_peak_rss_bytes) / (1024 * 1024),
            "peak_heap_mb": peak_heap / (1024 * 1024),
            "cgroup_peak_bytes": cgroup_final.get("cgroup_peak_bytes"),
            "cgroup_max_bytes": cgroup_final.get("cgroup_max_bytes"),
        }


class WireByteTracker:
    """
    Accumulates exact wire byte transmissions broken down by message flight.
    Records actual byte counts measured at the transport write boundary.
    """

    def __init__(self):
        self.records: Dict[str, int] = {}

    def record(self, flight_name: str, num_bytes: int) -> None:
        self.records[flight_name] = self.records.get(flight_name, 0) + num_bytes

    def total_handshake_bytes(self) -> int:
        return sum(v for k, v in self.records.items() if "payload" not in k.lower() and "chunk" not in k.lower())

    def total_bytes(self) -> int:
        return sum(self.records.values())

    def get_summary(self) -> Dict[str, int]:
        return dict(self.records)

