"""Measurement harness for PS-P1.

Metrics required by the Challenge Kit: handshake correctness / interoperability, time, memory,
code size and bytes exchanged - measured on classical target Platforms A/B/C and custom Platform D.

Each (platform x parameter-set x payload) cell runs in a FRESH subprocess so that peak-RSS numbers
are clean. The worker pins itself to the platform's CPU-core budget (os.sched_setaffinity) and
streams the payload with the platform's record size. Both endpoints live in that one process
(real socket pair), so memory = sender + receiver together; see the report's limitations.

Usage:  python -m src.metrics all [--quick]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
try:
    import resource
except ImportError:
    resource = None
import statistics
import subprocess
import sys
import time
import tracemalloc
from dataclasses import replace
from pathlib import Path

from .problem import (COMPARISON_SETS, EXTRA_SETS, PARAMETER_SETS, PROBLEM_ID, RESULTS_TABLES, ROOT, SEED,
                      Platform, load_platforms, locate_payloads)

REPS = {"1KB": 100, "100KB": 50, "10MB": 10}          # full run
REPS_QUICK = {"1KB": 12, "100KB": 8, "10MB": 3}        # smoke run
RESULT_TAG = "RESULT_JSON:"


class _Lazy:
    """Import a heavy module on first use, so benchmark WORKER processes keep a small memory baseline."""

    def __init__(self, name: str):
        self._name, self._mod = name, None

    def __getattr__(self, item):
        if self._mod is None:
            self._mod = importlib.import_module(self._name)
        return getattr(self._mod, item)


np, pd, psutil = _Lazy("numpy"), _Lazy("pandas"), _Lazy("psutil")


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------

def summarize(xs) -> dict:
    a = np.asarray([x for x in xs if x == x], dtype=float)  # drop NaN
    if a.size == 0:
        return {"median": float("nan"), "p95": float("nan"), "mean": float("nan"), "std": float("nan"), "n": 0}
    return {"median": float(np.median(a)), "p95": float(np.percentile(a, 95)), "mean": float(a.mean()),
            "std": float(a.std(ddof=1)) if a.size > 1 else 0.0, "n": int(a.size)}


def rss_kb() -> float:
    return psutil.Process().memory_info().rss / 1024


def peak_rss_kb() -> float:
    if resource is not None:
        v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return v / 1024 if sys.platform == "darwin" else float(v)  # Linux reports KB, macOS bytes
    try:
        return float(psutil.Process().memory_info().peak_wset / 1024)
    except Exception:
        return rss_kb()


def file_digest(path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()


def code_size() -> pd.DataFrame:
    """Logical source lines (non-blank, non-comment) and bytes per module."""
    rows = []
    for p in sorted((ROOT / "src").glob("*.py")):
        text = p.read_text()
        loc = sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))
        rows.append({"module": p.name, "logical_lines": loc, "bytes": len(text.encode())})
    df = pd.DataFrame(rows)
    df.loc[len(df)] = {"module": "TOTAL", "logical_lines": df.logical_lines.sum(), "bytes": df.bytes.sum()}
    return df


def available_sets(candidates) -> tuple[list[str], dict]:
    """Return the parameter sets whose libraries are installed, and why others were skipped."""
    from .process import BackendUnavailable, get_backend
    ok, skipped = [], {}
    for key in candidates:
        try:
            get_backend(key)
            ok.append(key)
        except BackendUnavailable as exc:
            skipped[key] = str(exc)
    return ok, skipped


# --------------------------------------------------------------------------------------
# worker (runs inside a fresh subprocess)
# --------------------------------------------------------------------------------------

def _worker(cfg: dict) -> dict:
    cores = cfg.get("cpu_cores")
    if cores:
        if hasattr(os, "sched_setaffinity"):
            avail = sorted(os.sched_getaffinity(0))
            os.sched_setaffinity(0, set(avail[:cores]))
        else:
            try:
                proc = psutil.Process()
                avail = proc.cpu_affinity()
                proc.cpu_affinity(avail[:cores])
            except Exception:
                pass
    from .process import file_chunks, get_backend, make_identity, run_loopback_transfer

    backend = get_backend(cfg["param_set"])
    implementation = {
        "classical-p256": "cryptography",
        "hybrid-L3": "cryptography + liboqs-python",
    }.get(cfg["param_set"], "liboqs-python")
    cid, sid = make_identity(backend), make_identity(backend)
    path, chunk = cfg["payload_path"], cfg["chunk_bytes"]
    digest = file_digest(path)
    empty = hashlib.sha256(b"").digest()
    for _ in range(cfg["warmup"]):                       # load libraries, warm caches
        run_loopback_transfer(backend, cid, sid, [b""], empty)
    base_peak, base_rss = peak_rss_kb(), rss_kb()
    runs = [run_loopback_transfer(backend, cid, sid, file_chunks(path, chunk), digest) for _ in range(cfg["reps"])]
    end_peak = peak_rss_kb()
    tracemalloc.start()                                  # one extra, untimed run for the Python-heap peak
    run_loopback_transfer(backend, cid, sid, file_chunks(path, chunk), digest)
    _, tm_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    phase_keys = sorted({k for r in runs for k in r.info if k.endswith("_ns")})
    return {
        "crypto_implementation": implementation,
        "backend_name": backend.name,
        "handshake_ms": [r.handshake_ms for r in runs],
        "transfer_ms": [r.transfer_ms for r in runs],
        "encrypt_ms": [r.encrypt_ms for r in runs],
        "decrypt_ms": [r.decrypt_ms for r in runs],
        "phase_ms": {k[:-3]: statistics.median([r.info.get(k, 0) / 1e6 for r in runs]) for k in phase_keys},
        "sizes": {k: v for k, v in runs[0].info.items() if k.startswith("size_")},
        "bytes_handshake": runs[0].bytes_handshake, "bytes_records": runs[0].bytes_records,
        "bytes_total": runs[0].bytes_total, "payload_bytes": runs[0].payload_bytes,
        "n_records": runs[0].n_records,
        "handshake_ok": all(r.handshake_ok for r in runs), "payload_ok": all(r.payload_ok for r in runs),
        "errors": sorted({r.error for r in runs if r.error}),
        "peak_rss_delta_kb": max(0.0, end_peak - base_peak), "base_rss_kb": base_rss,
        "tracemalloc_peak_kb": tm_peak / 1024,
        "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (list(psutil.Process().cpu_affinity()) if hasattr(psutil.Process(), "cpu_affinity") else None),
    }


def bench_cell(platform: Platform, set_key: str, payload_label: str, payload_path: Path, reps: int,
               warmup: int = 2, timeout: int = 1800) -> dict:
    cfg = {"cpu_cores": platform.cpu_cores, "chunk_bytes": platform.chunk_bytes, "param_set": set_key,
           "payload_path": str(payload_path), "reps": reps, "warmup": warmup}
    proc = subprocess.run([sys.executable, "-m", "src.metrics", "--worker", json.dumps(cfg)], cwd=ROOT,
                          capture_output=True, text=True, timeout=timeout)
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith(RESULT_TAG)]
    if not lines:
        raise RuntimeError(f"worker failed ({platform.key}/{set_key}/{payload_label}): {proc.stderr[-1500:]}")
    return json.loads(lines[-1][len(RESULT_TAG):])


# --------------------------------------------------------------------------------------
# benchmarks
# --------------------------------------------------------------------------------------

def run_benchmark(sets=None, platform_keys=("A", "B", "C", "D"), labels=("1KB", "100KB", "10MB"),
                  quick: bool = False, out_dir: Path = RESULTS_TABLES) -> pd.DataFrame:
    out_dir.mkdir(parents=True, exist_ok=True)
    sets, skipped = available_sets(sets or COMPARISON_SETS)
    if skipped:
        print("SKIPPED (library not available):", json.dumps(skipped, indent=2))
    platforms = load_platforms(tuple(platform_keys))
    payloads = locate_payloads()
    reps_map = REPS_QUICK if quick else REPS
    loc = int(code_size().set_index("module").loc["process.py", "logical_lines"])
    rows, raw = [], []
    for pk, plat in platforms.items():
        for set_key in sets:
            for label in labels:
                pl = payloads[label]
                print(f"  platform {pk} | {set_key:15s} | {label:5s} ...", flush=True)
                r = bench_cell(plat, set_key, label, pl.path, reps_map[label])
                raw.append({"platform": pk, "param_set": set_key, "payload": label, **r})
                hs, tr = summarize(r["handshake_ms"]), summarize(r["transfer_ms"])
                en, de = summarize(r["encrypt_ms"]), summarize(r["decrypt_ms"])
                budget = plat.mem_budget_mb
                ps = PARAMETER_SETS[set_key]
                rows.append({
                    "problem_id": PROBLEM_ID, "instance_id": label, "platform": pk, "backend": set_key,
                    "crypto_implementation": r["crypto_implementation"],
                    "kem": ps.kem, "sig": ps.sig, "payload_bytes": r["payload_bytes"], "payload_source": pl.source,
                    "chunk_bytes": plat.chunk_bytes if plat.chunk_bytes else "single-record",
                    "cpu_cores": plat.cpu_cores if plat.cpu_cores else "all", "mem_budget_mb": budget if budget else "none",
                    "reps": reps_map[label],
                    "handshake_ms_median": hs["median"], "handshake_ms_p95": hs["p95"], "handshake_ms_std": hs["std"],
                    "transfer_ms_median": tr["median"], "transfer_ms_p95": tr["p95"],
                    "encrypt_ms_median": en["median"], "decrypt_ms_median": de["median"],
                    "throughput_MBps": (r["payload_bytes"] / 1e6) / (tr["median"] / 1e3) if tr["median"] == tr["median"] and tr["median"] > 0 else float("nan"),
                    "peak_rss_delta_kb": r["peak_rss_delta_kb"], "tracemalloc_peak_kb": r["tracemalloc_peak_kb"],
                    "within_mem_budget": (max(r["peak_rss_delta_kb"], r["tracemalloc_peak_kb"]) / 1024 <= budget) if budget else True,
                    "bytes_handshake": r["bytes_handshake"], "bytes_records": r["bytes_records"], "bytes_total": r["bytes_total"],
                    "record_overhead_pct": 100 * (r["bytes_records"] - r["payload_bytes"]) / max(1, r["payload_bytes"]),
                    "n_records": r["n_records"], "code_size_loc": loc,
                    "handshake_correct": r["handshake_ok"], "payload_integrity_ok": r["payload_ok"],
                })
    df = pd.DataFrame(rows)
    ref = df[df.backend == "classical-p256"].set_index(["platform", "instance_id"])
    if not ref.empty:  # the classical (ECDH/ECDSA P-256) run is the kit's "classical reference"
        df["classical_ref_handshake_ms"] = [ref.handshake_ms_median.get((p, i), float("nan")) for p, i in zip(df.platform, df.instance_id)]
        df["classical_ref_bytes_handshake"] = [ref.bytes_handshake.get((p, i), float("nan")) for p, i in zip(df.platform, df.instance_id)]
    df.to_csv(out_dir / "pqc_benchmark.csv", index=False)
    (out_dir / "benchmark_raw.json").write_text(json.dumps(raw, indent=1))
    (out_dir / "benchmark_status.json").write_text(json.dumps(
        {"measured_sets": sets, "skipped_sets": skipped, "quick": quick, "seed_payloads_only": SEED,
         "backend_policy": "PQC requires vetted liboqs-python; no simulated or homemade fallback"}, indent=1))
    # per-phase breakdown of the handshake (ms, median) and message sizes, platform A / smallest payload
    phase = []
    for item in raw:
        if item["payload"] == labels[0]:
            phase.append({"platform": item["platform"], "backend": item["param_set"], **item["phase_ms"], **item["sizes"]})
    pd.DataFrame(phase).to_csv(out_dir / "handshake_breakdown.csv", index=False)
    return df


def run_primitive_ops(sets=None, reps: int = 100, out_dir: Path = RESULTS_TABLES) -> pd.DataFrame:
    """Key / ciphertext / signature sizes and single-operation timings per parameter set."""
    from .process import get_backend
    sets, skipped = available_sets(sets or (COMPARISON_SETS + EXTRA_SETS))
    rows = []
    msg = b"m" * 64
    for key in sets:
        b = get_backend(key)
        pk, sk = b.kem_keygen()
        ct, ss = b.kem_encaps(pk)
        spk, ssk = b.sig_keygen()
        sg = b.sign(ssk, msg)

        def t(fn):
            xs = []
            for _ in range(reps):
                t0 = time.perf_counter_ns()
                fn()
                xs.append((time.perf_counter_ns() - t0) / 1e6)
            return statistics.median(xs)
        ps = PARAMETER_SETS[key]
        rows.append({"param_set": key, "kem": ps.kem, "sig": ps.sig, "nist_category": ps.nist_category,
                     "kem_public_key_B": len(pk), "kem_ciphertext_B": len(ct), "shared_secret_B": len(ss),
                     "sig_public_key_B": len(spk), "signature_B": len(sg),
                     "kem_keygen_ms": t(b.kem_keygen), "kem_encaps_ms": t(lambda: b.kem_encaps(pk)),
                     "kem_decaps_ms": t(lambda: b.kem_decaps(sk, ct)), "sig_keygen_ms": t(b.sig_keygen),
                     "sign_ms": t(lambda: b.sign(ssk, msg)), "verify_ms": t(lambda: b.verify(spk, msg, sg)), "reps": reps})
    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "primitive_sizes_and_ops.csv", index=False)
    return df


def run_chunk_sweep(label: str = "10MB", chunk_sizes=(1024, 4096, 16384, 65536, 262144, 1048576, None),
                    cores: int = 1, reps: int = 15, out_dir: Path = RESULTS_TABLES) -> pd.DataFrame:
    """Record-size trade-off (memory vs overhead vs time). The record layer does not depend on the
    KEM/signature choice, so the classical backend is used - it runs everywhere."""
    pl = locate_payloads()[label]
    rows = []
    for ch in chunk_sizes:
        plat = Platform("sweep", "sweep", "sweep", "sweep", cores, None, ch, "classical-p256", "")
        print(f"  chunk {ch} ...", flush=True)
        r = bench_cell(plat, "classical-p256", label, pl.path, reps)
        tr = summarize(r["transfer_ms"])
        rows.append({"chunk_bytes": ch if ch else "single-record", "n_records": r["n_records"],
                     "transfer_ms_median": tr["median"], "transfer_ms_p95": tr["p95"],
                     "throughput_MBps": (r["payload_bytes"] / 1e6) / (tr["median"] / 1e3),
                     "peak_rss_delta_kb": r["peak_rss_delta_kb"], "tracemalloc_peak_kb": r["tracemalloc_peak_kb"],
                     "record_overhead_pct": 100 * (r["bytes_records"] - r["payload_bytes"]) / r["payload_bytes"],
                     "payload_integrity_ok": r["payload_ok"], "cores": cores, "reps": reps})
    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "chunk_sweep.csv", index=False)
    return df


def recommend_chunk(sweep: "pd.DataFrame", budget_mb: float, frac: float = 0.90):
    """Platform D rule (fixed in advance): among record sizes whose Python-heap working set fits the
    memory budget, pick the SMALLEST one that reaches >= `frac` of the best in-budget throughput.
    Smaller records mean a smaller working set and a smaller retransmission unit."""
    s = sweep[sweep.chunk_bytes != "single-record"].copy()
    s["chunk_bytes"] = s.chunk_bytes.astype(int)
    s = s[s.tracemalloc_peak_kb / 1024 <= budget_mb]
    if s.empty:
        return None
    ok = s[s.throughput_MBps >= frac * s.throughput_MBps.max()]
    return int(ok.chunk_bytes.min())


# Standardized object sizes in bytes (FIPS 203 ML-KEM, FIPS 204 ML-DSA, SEC1 uncompressed P-256 point,
# typical DER ECDSA P-256 signature). Used ONLY to PREDICT wire sizes; measured values come from the run.
STANDARD_SIZES = {
    "ECDH-P-256": {"pk": 65, "ct": 65}, "ML-KEM-512": {"pk": 800, "ct": 768},
    "ML-KEM-768": {"pk": 1184, "ct": 1088}, "ML-KEM-1024": {"pk": 1568, "ct": 1568},
    "ECDSA-P-256": {"sig": 71}, "ML-DSA-44": {"sig": 2420}, "ML-DSA-65": {"sig": 3309}, "ML-DSA-87": {"sig": 4627},
}


def predicted_handshake_bytes(set_key: str) -> dict:
    """Wire bytes of the 4-message handshake, computed from the message format in process.py."""
    ps = PARAMETER_SETS[set_key]
    parts = ps.kem.split("+")
    pk = sum(STANDARD_SIZES[p]["pk"] for p in parts)
    ct = sum(STANDARD_SIZES[p]["ct"] for p in parts)
    sig = STANDARD_SIZES[ps.sig]["sig"]
    f = lambda n: 4 + n                                              # one length-prefixed field
    hello = f(12) + f(len(ps.kem)) + f(len(ps.sig)) + f(32) + f(pk)  # magic, algs, nonce_c, KEM pk
    client = f(hello) + f(sig)
    server = f(f(32) + f(ct)) + f(sig)
    finished = 2 * (4 + 1 + 32 + 16)                                 # two AES-GCM Finished records
    total = f(client) + f(server) + finished
    return {"param_set": set_key, "kem_public_key_B": pk, "kem_ciphertext_B": ct, "signature_B": sig,
            "client_hello_frame_B": f(client), "server_hello_frame_B": f(server), "finished_B": finished,
            "predicted_handshake_bytes": total}


def build_headline(out_dir: Path = RESULTS_TABLES) -> "pd.DataFrame":
    """Headline comparison: laptop (Platform A) vs edge device (Platform C) for ECDH P-256 vs ML-KEM-768
    vs hybrid ECDH+ML-KEM-768 - handshake time, key / ciphertext sizes, bytes on the wire, RAM."""
    bench = pd.read_csv(out_dir / "pqc_benchmark.csv")
    prim = pd.read_csv(out_dir / "primitive_sizes_and_ops.csv")
    rows = []
    for plat in ("A", "C"):
        for key in COMPARISON_SETS:
            sub = bench[(bench.platform == plat) & (bench.backend == key)]
            pr = prim[prim.param_set == key]
            if sub.empty or pr.empty:
                continue
            small, big = sub[sub.instance_id == "1KB"].iloc[0], sub[sub.instance_id == "10MB"].iloc[0]
            rows.append({
                "platform": plat, "environment": "laptop" if plat == "A" else "edge (limited CPU/RAM)",
                "param_set": key, "kem": PARAMETER_SETS[key].kem, "sig": PARAMETER_SETS[key].sig,
                "handshake_ms_median": small.handshake_ms_median, "handshake_ms_p95": small.handshake_ms_p95,
                "kem_public_key_B": int(pr.kem_public_key_B.iloc[0]), "kem_ciphertext_B": int(pr.kem_ciphertext_B.iloc[0]),
                "signature_B": int(pr.signature_B.iloc[0]), "handshake_bytes_on_wire": int(small.bytes_handshake),
                "ram_heap_peak_kb_10MB": big.tracemalloc_peak_kb, "ram_rss_delta_kb_10MB": big.peak_rss_delta_kb,
                "within_mem_budget_10MB": bool(big.within_mem_budget), "reps_1KB": int(small.reps)})
    df = pd.DataFrame(rows)
    if not df.empty and (df.param_set == "classical-p256").any():
        base = df[df.param_set == "classical-p256"].set_index("platform")
        df["handshake_slowdown_vs_ecdh"] = [r.handshake_ms_median / base.handshake_ms_median[r.platform] for r in df.itertuples()]
        df["handshake_bytes_ratio_vs_ecdh"] = [r.handshake_bytes_on_wire / base.handshake_bytes_on_wire[r.platform] for r in df.itertuples()]
    df.to_csv(out_dir / "headline_comparison.csv", index=False)
    return df


def run_mitm_table(sets=None, out_dir: Path = RESULTS_TABLES) -> pd.DataFrame:
    from .process import get_backend, mitm_scenarios
    sets, _ = available_sets(sets or COMPARISON_SETS)
    rows = []
    for key in sets:
        for row in mitm_scenarios(get_backend(key)):
            implementation = "cryptography" if key == "classical-p256" else (
                "cryptography + liboqs-python" if key == "hybrid-L3" else "liboqs-python"
            )
            rows.append({"param_set": key, "crypto_implementation": implementation, **row})
    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "mitm_demo.csv", index=False)
    return df


def run_all(quick: bool = False, sets=None, platform_keys=("A", "B", "C", "D")) -> None:
    from .routing import processor_graph_table
    RESULTS_TABLES.mkdir(parents=True, exist_ok=True)
    print("[1/7] platform specs");  pd.DataFrame([vars(p) for p in load_platforms().values()]).to_csv(RESULTS_TABLES / "platform_specs.csv", index=False)
    print("[2/7] code size");       code_size().to_csv(RESULTS_TABLES / "code_size.csv", index=False)
    print("[3/7] processor graphs (optional quantum module)"); processor_graph_table().to_csv(RESULTS_TABLES / "processor_graph_metrics.csv", index=False)
    print("[4/7] primitive sizes + ops"); run_primitive_ops(sets, reps=20 if quick else 100)
    print("[5/7] MITM scenarios");  run_mitm_table(sets)
    print("[6/7] chunk-size sweep (Platform D design)")
    sweep = run_chunk_sweep(reps=3 if quick else 15)
    d = load_platforms(("D",))["D"]
    rec = recommend_chunk(sweep, d.mem_budget_mb or 8)
    (RESULTS_TABLES / "chunk_sweep_recommendation.json").write_text(json.dumps(
        {"rule": "smallest record size reaching >=90% of best in-budget throughput", "budget_mb": d.mem_budget_mb,
         "recommended_chunk_bytes": rec, "platform_D_json_chunk_bytes": d.chunk_bytes, "match": rec == d.chunk_bytes}, indent=1))
    print(f"      recommended Platform D record size = {rec}; processors/platform_D.json has {d.chunk_bytes}"
          + ("" if rec == d.chunk_bytes else "  <-- update platform_D.json and re-run to keep them consistent"))
    print("[7/7] platform benchmark"); run_benchmark(sets, platform_keys, quick=quick)
    if {"A", "C"} <= set(platform_keys):
        build_headline()
    from .routing import routing_estimate_table
    routing_estimate_table().to_csv(RESULTS_TABLES / "routing_estimate.csv", index=False)
    pd.DataFrame([predicted_handshake_bytes(k) for k in PARAMETER_SETS]).to_csv(
        RESULTS_TABLES / "predicted_handshake_bytes.csv", index=False)
    print("done -> results/tables/")


def main(argv=None):
    ap = argparse.ArgumentParser(description="PS-P1 measurement harness")
    ap.add_argument("command", nargs="?", default="all",
                    choices=["all", "bench", "primitives", "sweep", "mitm", "code-size", "headline"])
    ap.add_argument("--quick", action="store_true", help="few repetitions (smoke test)")
    ap.add_argument("--sets", nargs="*", default=None, help="parameter sets (default: classical-p256 pqc-L3 hybrid-L3)")
    ap.add_argument("--platforms", nargs="*", default=["A", "B", "C", "D"])
    ap.add_argument("--worker", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.worker:
        print(RESULT_TAG + json.dumps(_worker(json.loads(a.worker))))
        return
    if a.command == "all":
        run_all(a.quick, a.sets, tuple(a.platforms))
    elif a.command == "bench":
        print(run_benchmark(a.sets, tuple(a.platforms), quick=a.quick).to_string())
    elif a.command == "primitives":
        print(run_primitive_ops(a.sets).to_string())
    elif a.command == "sweep":
        print(run_chunk_sweep(reps=3 if a.quick else 5).to_string())
    elif a.command == "mitm":
        print(run_mitm_table(a.sets).to_string())
    elif a.command == "headline":
        print(build_headline().to_string())
    else:
        print(code_size().to_string())


if __name__ == "__main__":
    main()
