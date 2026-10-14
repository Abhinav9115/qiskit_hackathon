"""PS-P1 problem definition: identifiers, parameter sets, payloads and target platforms.

Nothing in this module implements cryptography. It only describes WHAT is built and measured.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PROBLEM_ID = "PS-P1"
PROBLEM_TITLE = "Quantum-Safe Secure Channel"
TRACK = "Post-Quantum Cryptography"

# Seed 42 is the kit's baseline seed. In this project it is used ONLY for stand-in payload
# bytes and benchmark ordering. It is NEVER used for keys, nonces or KEM/signature randomness:
# those always come from the OS CSPRNG inside the vetted libraries / the `secrets` module.
SEED = 42

ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
PROCESSORS_DIR = ROOT / "processors"
RESULTS_TABLES = ROOT / "results" / "tables"
RESULTS_FIGURES = ROOT / "results" / "figures"


@dataclass(frozen=True)
class ParameterSet:
    """One documented combination of primitives (the kit asks for exact parameter sets)."""

    name: str
    kem: str
    sig: str
    nist_category: str
    kdf: str = "HKDF-SHA256"
    aead: str = "AES-256-GCM"

    def describe(self) -> str:
        return f"{self.kem} + {self.sig} + {self.kdf} + {self.aead} (NIST category {self.nist_category})"


PARAMETER_SETS: dict[str, ParameterSet] = {
    # FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) parameter sets.
    "pqc-L3": ParameterSet("pqc-L3", "ML-KEM-768", "ML-DSA-65", "KEM 3 / SIG 3"),
    "pqc-L1": ParameterSet("pqc-L1", "ML-KEM-512", "ML-DSA-44", "KEM 1 / SIG 2"),
    "pqc-L5": ParameterSet("pqc-L5", "ML-KEM-1024", "ML-DSA-87", "KEM 5 / SIG 5"),
    # Classical baseline: same protocol, quantum-VULNERABLE primitives (broken by Shor's algorithm).
    "classical-p256": ParameterSet("classical-p256", "ECDH-P-256", "ECDSA-P-256", "n/a (quantum-vulnerable)"),
    # Hybrid key establishment: ECDH P-256 AND ML-KEM-768 run side by side and both shared secrets
    # feed HKDF, so the session key stays safe unless BOTH components are broken. Authentication
    # stays ML-DSA-65 as the kit requires.
    "hybrid-L3": ParameterSet("hybrid-L3", "ECDH-P-256+ML-KEM-768", "ML-DSA-65", "KEM 3 (hybrid) / SIG 3"),
}
DEFAULT_SET = "pqc-L3"
# Main three-way comparison requested for the benchmark (ECDH P-256 vs ML-KEM-768 vs hybrid):
COMPARISON_SETS = ["classical-p256", "pqc-L3", "hybrid-L3"]
# Extra parameter sets for the size / security-level trade-off table:
EXTRA_SETS = ["pqc-L1", "pqc-L5"]
PQC_SETS = ["pqc-L1", "pqc-L3", "pqc-L5"]

# Organizer payloads are "approximately" these sizes. If real files are placed in data/raw/ they
# are used instead of the stand-ins (file name must contain 1KB / 100KB / 10MB).
PAYLOAD_SIZES: dict[str, int] = {"1KB": 1024, "100KB": 100 * 1024, "10MB": 10 * 1024 * 1024}


@dataclass(frozen=True)
class Payload:
    label: str
    path: Path
    size: int
    source: str  # "organizer" or "stand-in (seed 42)"


def locate_payloads(generate_standins: bool = True) -> dict[str, Payload]:
    """Find organizer payloads in data/raw/, falling back to deterministic stand-ins."""
    import numpy as np  # lazy: keeps worker-process memory baselines small
    DATA_RAW.mkdir(parents=True, exist_ok=True)
    found: dict[str, Payload] = {}
    for label, nominal in PAYLOAD_SIZES.items():
        pat = re.compile(re.escape(label), re.IGNORECASE)
        cands = [
            p for p in sorted(DATA_RAW.iterdir())
            if p.is_file() and not p.name.startswith(("standin_", ".")) and pat.search(p.name)
        ]
        if cands:
            found[label] = Payload(label, cands[0], cands[0].stat().st_size, "organizer")
        elif generate_standins:
            path = DATA_RAW / f"standin_{label}.bin"
            if not path.exists() or path.stat().st_size != nominal:
                path.write_bytes(np.random.default_rng(SEED).bytes(nominal))
            found[label] = Payload(label, path, nominal, "stand-in (seed 42)")
    return found


@dataclass(frozen=True)
class Platform:
    """A classical target platform (NOT a quantum processor) - see processors/platform_*.json."""

    key: str
    name: str
    role: str
    status: str
    cpu_cores: Optional[int]
    mem_budget_mb: Optional[float]
    chunk_bytes: Optional[int]
    param_set: str
    description: str


def load_platform(key: str) -> Platform:
    data = json.loads((PROCESSORS_DIR / f"platform_{key}.json").read_text())
    return Platform(**{k: data[k] for k in Platform.__dataclass_fields__})


def load_platforms(keys=("A", "B", "C", "D")) -> dict[str, Platform]:
    return {k: load_platform(k) for k in keys}
