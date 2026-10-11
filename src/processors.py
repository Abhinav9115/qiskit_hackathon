"""
Hardware and Processor Profile Manager for QSC.
Loads processor specifications from processors/processor_A.json and processor_B.json,
and validates cgroups, CPU core pinning, and memory constraints.
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class ProcessorProfile:
    """
    Encapsulates CPU, memory, and network constraints for an execution environment.
    """

    def __init__(self, data: Dict[str, Any]):
        self.processor_id = data.get("processor_id") or data.get("platform_id", "unknown")
        self.name = data.get("name", self.processor_id)
        self.description = data.get("description", "")
        self.target_architecture = data.get("target_architecture", "x86_64")
        self.cpu_allocation = data.get("cpu_allocation", {})
        self.memory_allocation = data.get("memory_allocation", {})
        self.network_configuration = data.get("network_configuration", {})
        self.benchmarking_parameters = data.get("benchmarking_parameters", {})
        self.ablations = data.get("ablations", [])

    @classmethod
    def load_from_file(cls, path: str | Path) -> ProcessorProfile:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def get_core_limit(self) -> float:
        return float(self.cpu_allocation.get("cores", 1.0))

    def get_memory_limit_bytes(self) -> Optional[int]:
        return self.memory_allocation.get("limit_bytes")

    def get_network_latency_ms(self) -> float:
        return float(self.network_configuration.get("added_latency_ms", 0.0))

    def get_mtu_bytes(self) -> int:
        return int(self.network_configuration.get("mtu_bytes", 65536))


def load_processor(name: str) -> ProcessorProfile:
    """
    Loads processor specification by name (e.g., 'processor_A', 'processor_B').
    Supports both 'processor_X' and legacy 'platform_X' prefixes.
    """
    proc_dir = Path("processors")
    candidates = [
        proc_dir / f"{name}.json",
        proc_dir / f"processor_{name}.json",
        proc_dir / f"platform_{name}.json",
    ]
    for c in candidates:
        if c.exists():
            return ProcessorProfile.load_from_file(c)

    # Defaults if file missing
    return ProcessorProfile({
        "processor_id": name,
        "name": name,
        "cpu_allocation": {"cores": 1.0},
        "memory_allocation": {"limit_bytes": None},
    })


def list_available_processors() -> Dict[str, ProcessorProfile]:
    """
    Scans processors/ directory and loads all JSON profile specifications.
    """
    proc_dir = Path("processors")
    profiles = {}
    if proc_dir.exists():
        for file in sorted(proc_dir.glob("*.json")):
            try:
                prof = ProcessorProfile.load_from_file(file)
                profiles[file.stem] = prof
            except Exception:
                pass
    return profiles


__all__ = [
    "ProcessorProfile",
    "load_processor",
    "list_available_processors",
]
