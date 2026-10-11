"""
NIST PQC Parameter Sweep Matrix for QSC.
Evaluates the cross-product of security levels:
  KEM: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5)
  x
  DSA: ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), ML-DSA-87 (Level 5)
"""

from __future__ import annotations

import time
import sys
import json
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    resolve_kem_algorithm,
    resolve_sig_algorithm,
    HAS_LIBOQS,
)


def run_parameter_sweep(trials: int = 20) -> Dict[str, Any]:
    kems = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    sigs = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

    results = {}

    for kem_name in kems:
        for sig_name in sigs:
            pair_key = f"{kem_name} x {sig_name}"
            print(f"Sweeping parameter pair: {pair_key}...")

            try:
                kem = PQCKeyEncapsulation(kem_name)
                sig = PQCSignature(sig_name)

                # Measure KEM keygen & encap/decap
                t0 = time.perf_counter_ns()
                pk_k, sk_k = kem.generate_keypair()
                kem_keygen_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

                t0 = time.perf_counter_ns()
                ct_k, ss_k = kem.encap_secret(pk_k)
                kem_encap_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

                t0 = time.perf_counter_ns()
                _ = kem.decap_secret(ct_k, sk_k)
                kem_decap_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

                # Measure DSA keygen & sign/verify
                t0 = time.perf_counter_ns()
                pk_s, sk_s = sig.generate_keypair()
                dsa_keygen_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

                sample_msg = b"Parameter Sweep Vector Message"
                t0 = time.perf_counter_ns()
                sig_bytes = sig.sign(sample_msg, sk_s)
                dsa_sign_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

                t0 = time.perf_counter_ns()
                _ = sig.verify(sample_msg, sig_bytes, pk_s)
                dsa_verify_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

                # Wire sizes
                total_handshake_bytes = (
                    len(pk_k)           # ClientHello PK
                    + len(ct_k)         # ServerHello CT
                    + len(pk_s) * 2     # Mutual identity PKs
                    + len(sig_bytes) * 2  # Mutual signatures
                    + 32 * 2            # Nonces
                    + 32                # MAC confirm
                )

                results[pair_key] = {
                    "kem": kem_name,
                    "sig": sig_name,
                    "kem_pk_bytes": len(pk_k),
                    "kem_ct_bytes": len(ct_k),
                    "sig_pk_bytes": len(pk_s),
                    "signature_bytes": len(sig_bytes),
                    "total_wire_bytes": total_handshake_bytes,
                    "timings_ms": {
                        "kem_keygen": kem_keygen_ms,
                        "kem_encap": kem_encap_ms,
                        "kem_decap": kem_decap_ms,
                        "dsa_keygen": dsa_keygen_ms,
                        "dsa_sign": dsa_sign_ms,
                        "dsa_verify": dsa_verify_ms,
                        "total_crypto_latency": (
                            kem_keygen_ms + kem_encap_ms + kem_decap_ms + dsa_sign_ms * 2 + dsa_verify_ms * 2
                        ),
                    },
                }
            except Exception as e:
                results[pair_key] = {"error": str(e)}

    # Export results
    out_dir = Path("results/tables")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "parameter_sweep.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("Parameter sweep complete. Saved to results/tables/parameter_sweep.json")
    return results


if __name__ == "__main__":
    run_parameter_sweep()
