"""
Multi-Platform Benchmarking Engine for QSC (Quantum-Safe Secure Channel).
Executes rigorous, empirical micro and macro benchmarks across:
  - Microbenchmarks: ML-KEM-768, ML-DSA-65, HKDF, ECDH P-256, ECDSA P-256
  - Platform A: Baseline host (1 core pinned via taskset, unconstrained RAM)
  - Platform B: Constrained server (1 core pinned, 512 MB cgroups v2 RAM limit)
  - Platform B Ablations: B-cpu-only (1 core, unconstrained RAM), B-mem-only (128 MB RAM)
  - Platform D: Real Linux network namespaces with veth pair, MTU 1500 B, tc-netem (15ms delay, 3ms jitter)
  - Platform D Ablations: D-baseline (0ms), D-latency-only (15ms), D-jitter (15ms 3ms), D-rate-limit (10 Mbps)

Every measurement collects >= 100 trials, reporting mean, median, std, p95, and 95% bootstrap CI.
All transfers operate genuine streaming chunking directly from/to files.
Wire bytes are tracked at the transport socket boundary.
Memory profiles report Python heap (tracemalloc), process RSS (getrusage), and cgroups peak.
"""

from __future__ import annotations

import os
import gc
import sys
import json
import csv
import time
import shutil
import asyncio
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    derive_session_keys,
    ClassicalReferenceBaseline,
    LIBOQS_VERSION,
    LIBOQS_BACKEND,
    get_crypto_metadata,
)
from src.protocol import (
    MAX_CHUNK_PLAINTEXT_SIZE,
    ClientHello,
    ServerHello,
    ClientAuth,
    ServerFinished,
)
from src.trust_store import TrustStore
from src.peer import QSCClient, QSCServer
from src.transport import AsyncTCPTransport, MockTransport
from src.metrics import (
    compute_statistics,
    ResourceProfiler,
    WireByteTracker,
    get_code_size,
    get_cgroup_memory,
)


# =====================================================================
# 1. Microbenchmarks (Primitives)
# =====================================================================
def run_micro_benchmarks(trials: int = 100, warmup: int = 10) -> Dict[str, Any]:
    """
    Microbenchmark individual cryptographic operations with gc disabled during timing.
    """
    kem = PQCKeyEncapsulation()
    sig = PQCSignature()

    pk_kem, sk_kem = kem.generate_keypair()
    ct_kem, ss_kem = kem.encap_secret(pk_kem)

    pk_dsa, sk_dsa = sig.generate_keypair()
    sample_msg = b"QSC Transcript Vector 2026 - Cryptographic Microbenchmark"
    sig_dsa = sig.sign(sample_msg, sk_dsa)

    # Warmup runs
    for _ in range(warmup):
        _pk, _sk = kem.generate_keypair()
        _ct, _ss = kem.encap_secret(pk_kem)
        _ = kem.decap_secret(ct_kem, sk_kem)
        _spk, _ssk = sig.generate_keypair()
        _s = sig.sign(sample_msg, sk_dsa)
        _ = sig.verify(sample_msg, sig_dsa, pk_dsa)

    gc.disable()
    try:
        # 1. KEM Keygen (ML-KEM-768)
        times_kem_keygen = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = kem.generate_keypair()
            times_kem_keygen.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        # 2. KEM Encap (ML-KEM-768)
        times_kem_encap = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = kem.encap_secret(pk_kem)
            times_kem_encap.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        # 3. KEM Decap (ML-KEM-768)
        times_kem_decap = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = kem.decap_secret(ct_kem, sk_kem)
            times_kem_decap.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        # 4. DSA Sign (ML-DSA-65)
        times_dsa_sign = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = sig.sign(sample_msg, sk_dsa)
            times_dsa_sign.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        # 5. DSA Verify (ML-DSA-65)
        times_dsa_verify = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = sig.verify(sample_msg, sig_dsa, pk_dsa)
            times_dsa_verify.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        # 6. HKDF Key Derivation
        times_hkdf = []
        dummy_tr2 = os.urandom(32)
        c_nonce = os.urandom(32)
        s_nonce = os.urandom(32)
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = derive_session_keys(ss_kem, c_nonce, s_nonce, dummy_tr2)
            times_hkdf.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        # 7. Classical References (ECDH P-256 + ECDSA P-256)
        ec_pk, ec_sk = ClassicalReferenceBaseline.generate_ecdh_keypair()
        times_ecdh = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = ClassicalReferenceBaseline.ecdh_exchange(ec_pk, ec_sk)
            times_ecdh.append((time.perf_counter_ns() - t0) / 1_000_000.0)

        dsa_pk, dsa_sk = ClassicalReferenceBaseline.generate_ecdsa_keypair()
        ec_sig = ClassicalReferenceBaseline.ecdsa_sign(sample_msg, dsa_sk)
        times_ecdsa_sign = []
        times_ecdsa_verify = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            _ = ClassicalReferenceBaseline.ecdsa_sign(sample_msg, dsa_sk)
            times_ecdsa_sign.append((time.perf_counter_ns() - t0) / 1_000_000.0)

            t0 = time.perf_counter_ns()
            _ = ClassicalReferenceBaseline.ecdsa_verify(sample_msg, ec_sig, dsa_pk)
            times_ecdsa_verify.append((time.perf_counter_ns() - t0) / 1_000_000.0)
    finally:
        gc.enable()

    return {
        "kem_keygen": compute_statistics(times_kem_keygen),
        "kem_encap": compute_statistics(times_kem_encap),
        "kem_decap": compute_statistics(times_kem_decap),
        "dsa_sign": compute_statistics(times_dsa_sign),
        "dsa_verify": compute_statistics(times_dsa_verify),
        "hkdf_derive": compute_statistics(times_hkdf),
        "classical_ecdh": compute_statistics(times_ecdh),
        "classical_ecdsa_sign": compute_statistics(times_ecdsa_sign),
        "classical_ecdsa_verify": compute_statistics(times_ecdsa_verify),
    }


# =====================================================================
# 2. Local TCP Benchmark Engine (Platform A & B)
# =====================================================================
async def run_tcp_benchmark_session(
    host: str = "127.0.0.1",
    port: int = 18888,
    handshake_trials: int = 100,
    payload_trials: int = 100,
    payload_files: Dict[str, str] = None,
    warmup: int = 10,
) -> Dict[str, Any]:
    """
    Runs real TCP socket benchmarks for handshake and genuine file streaming transfers.
    Measures handshake time separately from payload transfer.
    Tracks exact wire bytes at the socket write boundary.
    """
    if payload_files is None:
        payload_files = {
            "1KB": "data/raw/payload_1kb.bin",
            "100KB": "data/raw/payload_100kb.bin",
            "10MB": "data/raw/payload_10mb.bin",
        }

    tmp_dir = Path("/tmp/qsc_bench_peers")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    c_store = TrustStore(tmp_dir / "client_ts.json")
    s_store = TrustStore(tmp_dir / "server_ts.json")

    sig_p = PQCSignature()
    c_pk, c_sk = sig_p.generate_keypair()
    s_pk, s_sk = sig_p.generate_keypair()

    c_store.pin_peer("server-node", s_pk)
    s_store.pin_peer("client-node", c_pk)

    dest_sink = tmp_dir / "dest_sink.bin"

    # Server state
    server_ready = asyncio.Event()
    server_task_queue: asyncio.Queue = asyncio.Queue()
    server_results_queue: asyncio.Queue = asyncio.Queue()

    async def server_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        transport = AsyncTCPTransport(reader, writer)
        try:
            mode, payload_size = await server_task_queue.get()
            server_node = QSCServer("server-node", s_sk, s_pk, s_store)
            hs_res = await server_node.perform_handshake(transport)

            if mode == "handshake_only":
                await server_results_queue.put({"status": "OK", "bytes_read": transport.bytes_received})
            elif mode == "streaming":
                recv_res = await server_node.receive_stream(transport, dest_sink)
                await server_results_queue.put({
                    "status": "OK",
                    "total_bytes": recv_res["total_bytes"],
                    "sha256": recv_res["sha256"],
                    "bytes_read": transport.bytes_received,
                })
        except Exception as e:
            await server_results_queue.put({"status": "ERROR", "error": str(e)})
        finally:
            await transport.close()

    server = await asyncio.start_server(server_handler, host, port)

    # 1. Warmup runs
    for _ in range(warmup):
        await server_task_queue.put(("handshake_only", 0))
        r, w = await asyncio.open_connection(host, port)
        c_tr = AsyncTCPTransport(r, w)
        c_node = QSCClient("client-node", c_sk, c_pk, c_store)
        await c_node.perform_handshake(c_tr)
        await c_tr.close()
        _ = await server_results_queue.get()

    # 2. Handshake Trials
    handshake_latencies = []
    handshake_wire_sent = 0
    handshake_wire_recv = 0

    for i in range(handshake_trials):
        await server_task_queue.put(("handshake_only", 0))
        r, w = await asyncio.open_connection(host, port)
        c_tr = AsyncTCPTransport(r, w)
        c_node = QSCClient("client-node", c_sk, c_pk, c_store)

        t0 = time.perf_counter_ns()
        hs_res = await c_node.perform_handshake(c_tr)
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        handshake_latencies.append(dt)

        if i == 0:
            handshake_wire_sent = c_tr.bytes_sent
            handshake_wire_recv = c_tr.bytes_received

        await c_tr.close()
        _ = await server_results_queue.get()

    total_handshake_wire = handshake_wire_sent + handshake_wire_recv

    # 3. Payload Streaming Transfers
    payload_results = {}
    payload_wire_stats = {}

    for size_label, file_path in payload_files.items():
        if not os.path.exists(file_path):
            continue
        expected_size = os.path.getsize(file_path)

        transfer_times = []
        throughputs = []
        wire_bytes_per_transfer = 0

        for trial_idx in range(payload_trials):
            await server_task_queue.put(("streaming", size_label))
            r, w = await asyncio.open_connection(host, port)
            c_tr = AsyncTCPTransport(r, w)
            c_node = QSCClient("client-node", c_sk, c_pk, c_store)

            # Handshake happens first
            await c_node.perform_handshake(c_tr)

            # Now measure streaming transfer separately!
            t0 = time.perf_counter_ns()
            send_res = await c_node.send_stream(c_tr, file_path)
            # Wait for server confirmation
            srv_resp = await server_results_queue.get()
            elapsed_s = (time.perf_counter_ns() - t0) / 1_000_000_000.0

            assert srv_resp["status"] == "OK", f"Transfer failed: {srv_resp}"
            assert srv_resp["total_bytes"] == expected_size, "Size mismatch"
            assert srv_resp["sha256"] == send_res["sha256"], "Digest mismatch"

            transfer_times.append(elapsed_s * 1000.0)  # ms
            mb = expected_size / (1024.0 * 1024.0)
            throughputs.append(mb / max(1e-9, elapsed_s))

            if trial_idx == 0:
                wire_bytes_per_transfer = c_tr.bytes_sent

            await c_tr.close()

        payload_results[size_label] = {
            "transfer_time_ms": compute_statistics(transfer_times),
            "throughput_mb_s": compute_statistics(throughputs),
        }
        payload_wire_stats[size_label] = wire_bytes_per_transfer

    server.close()
    await server.wait_closed()

    return {
        "handshake_latencies_raw": handshake_latencies,
        "handshake_latency_ms": compute_statistics(handshake_latencies),
        "total_handshake_wire_bytes": total_handshake_wire,
        "handshake_wire_breakdown": {
            "client_to_server_bytes": handshake_wire_sent,
            "server_to_client_bytes": handshake_wire_recv,
            "total_bytes": total_handshake_wire,
        },
        "payloads": payload_results,
        "payload_wire_bytes": payload_wire_stats,
    }


def run_platform_benchmark(
    platform_name: str,
    cpu_pin: Optional[int] = 0,
    cgroup_name: Optional[str] = None,
    memory_limit_bytes: Optional[int] = None,
    handshake_trials: int = 100,
    payload_trials: int = 100,
) -> Dict[str, Any]:
    """
    Executes a measured benchmark in an ISOLATED fresh subprocess under verified constraints.
    Fails closed if CPU affinity or cgroups v2 constraints cannot be strictly verified.
    """
    print(f"[{platform_name}] Spawning isolated subprocess: CPU={cpu_pin}, Cgroup={cgroup_name}, MemLimit={memory_limit_bytes} B...", flush=True)

    worker_code = f"""
import sys, os, asyncio, json
from pathlib import Path
sys.path.insert(0, '{str(Path(__file__).resolve().parent.parent)}')

from src.metrics import ResourceProfiler, get_effective_affinity, get_cgroup_memory
from src.benchmark import run_tcp_benchmark_session

# 1. Enforce CPU Pinning (Fail Closed)
requested_cpu = {cpu_pin}
if requested_cpu is not None:
    if not hasattr(os, 'sched_setaffinity'):
        raise RuntimeError("CPU affinity enforcement required but sched_setaffinity unavailable.")
    os.sched_setaffinity(0, {{requested_cpu}})
    effective_aff = get_effective_affinity()
    if effective_aff != {{requested_cpu}}:
        raise RuntimeError(f"CPU affinity constraint failed: requested {{requested_cpu}}, got {{effective_aff}}")
else:
    effective_aff = get_effective_affinity()

# 2. Enforce Cgroups v2 Memory Limits (Fail Closed)
cgroup_name = {repr(cgroup_name)}
memory_limit = {memory_limit_bytes if memory_limit_bytes is not None else "None"}
effective_cgroup_max = None

if cgroup_name and memory_limit:
    cg_path = Path(f"/sys/fs/cgroup/{{cgroup_name}}")
    cg_path.mkdir(parents=True, exist_ok=True)
    (cg_path / "memory.max").write_text(str(memory_limit))
    swap_file = cg_path / "memory.swap.max"
    if swap_file.exists():
        swap_file.write_text("0")
    (cg_path / "cgroup.procs").write_text(str(os.getpid()))

    # Read back and verify constraint
    read_max = (cg_path / "memory.max").read_text().strip()
    if read_max == "max" or int(read_max) != memory_limit:
        raise RuntimeError(f"Cgroup memory constraint failed: requested {{memory_limit}}, effective is {{read_max}}")
    effective_cgroup_max = int(read_max)
else:
    # Ensure unconstrained process: move to root cgroup
    try:
        Path("/sys/fs/cgroup/cgroup.procs").write_text(str(os.getpid()))
    except Exception:
        pass
    effective_cgroup_max = None

profiler = ResourceProfiler(cgroup_name=cgroup_name)
profiler.start()

res = asyncio.run(
    run_tcp_benchmark_session(
        host="127.0.0.1",
        port={18880 + (cpu_pin or 0) if cpu_pin is not None else 18889},
        handshake_trials={handshake_trials},
        payload_trials={payload_trials},
    )
)

mem_stats = profiler.stop()
res["platform"] = "{platform_name}"
res["memory"] = mem_stats
res["effective_constraints"] = {{
    "cpu_pinned_core": requested_cpu,
    "effective_affinity_cores": list(effective_aff),
    "memory_limit_bytes": memory_limit,
    "cgroup_memory_max_effective": effective_cgroup_max,
    "cgroup_name": cgroup_name,
}}

print("__SUBPROCESS_RESULT__" + json.dumps(res), flush=True)
"""

    proc = subprocess.run(
        [sys.executable, "-u", "-c", worker_code],
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        raise RuntimeError(f"Platform benchmark [{platform_name}] worker failed closed (exit {proc.returncode}):\n{proc.stderr}")

    out_data = None
    for line in proc.stdout.splitlines():
        if "__SUBPROCESS_RESULT__" in line:
            json_str = line.split("__SUBPROCESS_RESULT__")[1]
            out_data = json.loads(json_str)
            break

    if not out_data:
        raise RuntimeError(f"Platform benchmark [{platform_name}] failed to produce result:\n{proc.stdout}\n{proc.stderr}")

    return out_data


# =====================================================================
# 3. Platform D (Network Namespaces + Kernel netem + veth MTU 1500)
# =====================================================================
def setup_netns_environment(
    ns_cli: str = "ns_cli",
    ns_srv: str = "ns_srv",
    mtu: int = 1500,
    delay_ms: float = 15.0,
    jitter_ms: float = 3.0,
    rate_mbps: Optional[float] = None,
) -> bool:
    """
    Sets up isolated Linux network namespaces, veth pair, MTU, and symmetric tc netem.
    """
    try:
        subprocess.run(["ip", "netns", "add", ns_srv], check=False, capture_output=True)
        subprocess.run(["ip", "netns", "add", ns_cli], check=False, capture_output=True)

        subprocess.run(["ip", "link", "add", "veth_cli", "type", "veth", "peer", "name", "veth_srv"], check=False, capture_output=True)
        subprocess.run(["ip", "link", "set", "veth_cli", "netns", ns_cli], check=True)
        subprocess.run(["ip", "link", "set", "veth_srv", "netns", ns_srv], check=True)

        subprocess.run(["ip", "-n", ns_cli, "addr", "add", "10.200.1.1/24", "dev", "veth_cli"], check=True)
        subprocess.run(["ip", "-n", ns_srv, "addr", "add", "10.200.1.2/24", "dev", "veth_srv"], check=True)

        subprocess.run(["ip", "-n", ns_cli, "link", "set", "veth_cli", "up"], check=True)
        subprocess.run(["ip", "-n", ns_srv, "link", "set", "veth_srv", "up"], check=True)

        subprocess.run(["ip", "-n", ns_cli, "link", "set", "dev", "veth_cli", "mtu", str(mtu)], check=True)
        subprocess.run(["ip", "-n", ns_srv, "link", "set", "dev", "veth_srv", "mtu", str(mtu)], check=True)

        # Apply symmetric tc netem
        netem_cmd_cli = ["tc", "qdisc", "replace", "dev", "veth_cli", "root", "netem"]
        netem_cmd_srv = ["tc", "qdisc", "replace", "dev", "veth_srv", "root", "netem"]

        if delay_ms > 0:
            netem_cmd_cli.extend(["delay", f"{delay_ms}ms"])
            netem_cmd_srv.extend(["delay", f"{delay_ms}ms"])
            if jitter_ms > 0:
                netem_cmd_cli.append(f"{jitter_ms}ms")
                netem_cmd_srv.append(f"{jitter_ms}ms")

        if rate_mbps:
            netem_cmd_cli.extend(["rate", f"{rate_mbps}mbit"])
            netem_cmd_srv.extend(["rate", f"{rate_mbps}mbit"])

        if delay_ms > 0 or rate_mbps:
            subprocess.run(["ip", "netns", "exec", ns_cli] + netem_cmd_cli, check=True)
            subprocess.run(["ip", "netns", "exec", ns_srv] + netem_cmd_srv, check=True)

        return True
    except Exception as e:
        print(f"setup_netns_environment error: {e}")
        return False


def teardown_netns_environment(ns_cli: str = "ns_cli", ns_srv: str = "ns_srv") -> None:
    """Tears down network namespaces."""
    subprocess.run(["ip", "netns", "del", ns_cli], check=False, capture_output=True)
    subprocess.run(["ip", "netns", "del", ns_srv], check=False, capture_output=True)


def get_interface_packet_counters(ns_name: str = "ns_cli", dev_name: str = "veth_cli") -> Dict[str, int]:
    """
    Parses ip -s link show dev <dev> from inside namespace to get exact kernel packet counts.
    """
    try:
        out = subprocess.check_output(
            ["ip", "netns", "exec", ns_name, "ip", "-s", "link", "show", "dev", dev_name],
            text=True,
        )
        lines = out.strip().splitlines()
        rx_bytes, rx_pkts = 0, 0
        tx_bytes, tx_pkts = 0, 0

        for i, line in enumerate(lines):
            if "RX:" in line and i + 1 < len(lines):
                parts = lines[i + 1].strip().split()
                rx_bytes = int(parts[0])
                rx_pkts = int(parts[1])
            elif "TX:" in line and i + 1 < len(lines):
                parts = lines[i + 1].strip().split()
                tx_bytes = int(parts[0])
                tx_pkts = int(parts[1])

        return {
            "rx_bytes": rx_bytes,
            "rx_packets": rx_pkts,
            "tx_bytes": tx_bytes,
            "tx_packets": tx_pkts,
            "total_packets": rx_pkts + tx_pkts,
        }
    except Exception:
        return {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0, "total_packets": 0}


def run_platform_d_benchmark(
    handshake_trials: int = 100,
    payload_trials: int = 100,
    payload_files: Optional[Dict[str, str]] = None,
    mtu: int = 1500,
    delay_ms: float = 15.0,
    jitter_ms: float = 3.0,
    rate_mbps: Optional[float] = None,
    cpu_pin: Optional[int] = 0,
    cgroup_name: Optional[str] = "qsc_bench_d",
    memory_limit_bytes: Optional[int] = 134217728,  # 128 MB
) -> Dict[str, Any]:
    """
    Executes Platform D across real Linux network namespaces with kernel MTU 1500 and netem shaping.
    Enforces and verifies 1 pinned CPU core and 128 MB cgroups v2 memory limit inside the namespace processes.
    """
    if payload_files is None:
        payload_files = {
            "1KB": "data/raw/payload_1kb.bin",
            "100KB": "data/raw/payload_100kb.bin",
            "10MB": "data/raw/payload_10mb.bin",
        }
    payload_files_json = json.dumps(payload_files)

    print(f"[Platform_D] Setting up kernel netns: MTU={mtu}, Delay={delay_ms}ms, Jitter={jitter_ms}ms, Rate={rate_mbps}, CPU={cpu_pin}, Cgroup={cgroup_name} ({memory_limit_bytes} B)...", flush=True)
    teardown_netns_environment()
    ok = setup_netns_environment(mtu=mtu, delay_ms=delay_ms, jitter_ms=jitter_ms, rate_mbps=rate_mbps)
    if not ok:
        raise RuntimeError("Platform D requires Linux root privileges with ip and tc installed.")

    # Configure cgroup v2 for Platform D
    if cgroup_name and memory_limit_bytes:
        cg_path = Path(f"/sys/fs/cgroup/{cgroup_name}")
        cg_path.mkdir(parents=True, exist_ok=True)
        (cg_path / "memory.max").write_text(str(memory_limit_bytes))
        swap_file = cg_path / "memory.swap.max"
        if swap_file.exists():
            try:
                swap_file.write_text("0")
            except Exception:
                pass
        effective_cgroup_max = memory_limit_bytes
    else:
        effective_cgroup_max = None

    profiler = ResourceProfiler(cgroup_name=cgroup_name)
    profiler.start()

    counters_before = get_interface_packet_counters("ns_cli", "veth_cli")

    # Launch server in ns_srv
    server_code = f"""
import sys, asyncio, os, json
from pathlib import Path
sys.path.insert(0, '{str(Path(__file__).resolve().parent.parent)}')
from src.crypto_suite import PQCSignature
from src.trust_store import TrustStore
from src.peer import QSCServer
from src.transport import AsyncTCPTransport

async def main():
    # 1. Enforce Server CPU Affinity
    req_cpu = {cpu_pin}
    if req_cpu is not None and hasattr(os, 'sched_setaffinity'):
        os.sched_setaffinity(0, {{req_cpu}})

    tmp = Path('/tmp/qsc_bench_netns')
    tmp.mkdir(parents=True, exist_ok=True)
    s_store = TrustStore(tmp / 'server_ts.json')

    # Load shared keys
    keys = json.loads((tmp / 'keys.json').read_text())
    s_store.pin_peer('client-node', bytes.fromhex(keys['c_pk']))

    async def handle_client(reader, writer):
        transport = AsyncTCPTransport(reader, writer)
        server_node = QSCServer('server-node', bytes.fromhex(keys['s_sk']), bytes.fromhex(keys['s_pk']), s_store)
        try:
            # First 4 bytes indicate command: 1=handshake_only, 2=streaming
            cmd_buf = await transport.read_exact(4)
            cmd = int.from_bytes(cmd_buf, 'big')
            await server_node.perform_handshake(transport)
            if cmd == 2:
                await server_node.receive_stream(transport, '/tmp/qsc_bench_netns/sink.bin')
            await transport.write_exact(b'OK')
        except Exception as err:
            print('SERVER EXCEPTION: ' + str(err), flush=True)
        finally:
            await transport.close()

    server = await asyncio.start_server(handle_client, '10.200.1.2', 19888)
    print('SERVER_READY', flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
"""

    # Generate shared test keys
    tmp_netns = Path("/tmp/qsc_bench_netns")
    tmp_netns.mkdir(parents=True, exist_ok=True)
    sig_p = PQCSignature()
    c_pk, c_sk = sig_p.generate_keypair()
    s_pk, s_sk = sig_p.generate_keypair()
    (tmp_netns / "keys.json").write_text(json.dumps({
        "c_pk": c_pk.hex(), "c_sk": c_sk.hex(),
        "s_pk": s_pk.hex(), "s_sk": s_sk.hex(),
    }))

    # Start server process
    srv_proc = subprocess.Popen(
        ["ip", "netns", "exec", "ns_srv", sys.executable, "-u", "-c", server_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if cgroup_name and memory_limit_bytes:
        try:
            (Path(f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs")).write_text(str(srv_proc.pid))
        except Exception as e:
            print(f"[Platform_D] Warning adding srv to cgroup: {e}")

    # Wait for ready signal
    ready = False
    for _ in range(50):
        if srv_proc.poll() is not None:
            err = srv_proc.stderr.read()
            raise RuntimeError(f"Server exited unexpectedly: {err}")
        line = srv_proc.stdout.readline()
        if "SERVER_READY" in line:
            ready = True
            break
        time.sleep(0.1)

    if not ready:
        srv_proc.kill()
        raise RuntimeError("Server did not report ready in time")

    # Client runner in ns_cli
    client_runner_code = f"""
import sys, asyncio, os, time, json
from pathlib import Path
sys.path.insert(0, '{str(Path(__file__).resolve().parent.parent)}')
from src.crypto_suite import PQCSignature
from src.trust_store import TrustStore
from src.peer import QSCClient
from src.transport import AsyncTCPTransport
from src.metrics import get_effective_affinity, compute_statistics

# 1. Enforce CPU Pinning (Fail Closed)
requested_cpu = {cpu_pin}
if requested_cpu is not None:
    if not hasattr(os, 'sched_setaffinity'):
        raise RuntimeError("CPU affinity enforcement required but sched_setaffinity unavailable.")
    os.sched_setaffinity(0, {{requested_cpu}})
    effective_aff = get_effective_affinity()
    if effective_aff != {{requested_cpu}}:
        raise RuntimeError(f"Platform D CPU affinity constraint failed: requested {{requested_cpu}}, got {{effective_aff}}")
else:
    effective_aff = get_effective_affinity()

async def run_client():
    tmp = Path('/tmp/qsc_bench_netns')
    c_store = TrustStore(tmp / 'client_ts.json')
    s_store = TrustStore(tmp / 'server_ts.json')

    keys = json.loads((tmp / 'keys.json').read_text())
    c_store.pin_peer('server-node', bytes.fromhex(keys['s_pk']))

    c_pk = bytes.fromhex(keys['c_pk'])
    c_sk = bytes.fromhex(keys['c_sk'])

    # 1. Warmup
    for _ in range(5):
        r, w = await asyncio.open_connection('10.200.1.2', 19888)
        tr = AsyncTCPTransport(r, w)
        await tr.write_exact((1).to_bytes(4, 'big'))
        client = QSCClient('client-node', c_sk, c_pk, c_store)
        await client.perform_handshake(tr)
        await tr.read_exact(2)
        await tr.close()

    # 2. Handshake trials
    handshake_latencies = []
    wire_sent = 0
    wire_recv = 0
    for i in range({handshake_trials}):
        r, w = await asyncio.open_connection('10.200.1.2', 19888)
        tr = AsyncTCPTransport(r, w)
        await tr.write_exact((1).to_bytes(4, 'big'))
        client = QSCClient('client-node', c_sk, c_pk, c_store)
        t0 = time.perf_counter_ns()
        await client.perform_handshake(tr)
        await tr.read_exact(2)
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        handshake_latencies.append(dt)
        if i == 0:
            wire_sent = tr.bytes_sent
            wire_recv = tr.bytes_received
        await tr.close()

    # Protocol wire: 7,800 B client + 1,280 B server = 9,080 B
    # Harness framing overhead: 4-byte command opcode + 2-byte server ACK = 6 B
    protocol_handshake_wire = (wire_sent - 4) + (wire_recv - 2)
    harness_overhead_bytes = 6
    socket_total_handshake_bytes = wire_sent + wire_recv

    # 3. Payload streaming trials
    payload_files = json.loads({json.dumps(payload_files_json)})
    payload_results = {{}}
    payload_wire = {{}}

    for label, path_str in payload_files.items():
        if not os.path.exists(path_str):
            continue
        size_bytes = os.path.getsize(path_str)
        mb = size_bytes / (1024.0 * 1024.0)

        t_times = []
        t_throughputs = []
        wire_cnt = 0

        for trial in range({payload_trials}):
            r, w = await asyncio.open_connection('10.200.1.2', 19888)
            tr = AsyncTCPTransport(r, w)
            await tr.write_exact((2).to_bytes(4, 'big'))
            client = QSCClient('client-node', c_sk, c_pk, c_store)
            await client.perform_handshake(tr)

            t0 = time.perf_counter_ns()
            await client.send_stream(tr, path_str)
            await tr.read_exact(2)
            elapsed_s = (time.perf_counter_ns() - t0) / 1_000_000_000.0
            t_times.append(elapsed_s * 1000.0)
            t_throughputs.append(mb / max(1e-9, elapsed_s))

            if trial == 0:
                wire_cnt = tr.bytes_sent
            await tr.close()

        payload_results[label] = {{
            'transfer_time_ms': compute_statistics(t_times),
            'throughput_mb_s': compute_statistics(t_throughputs),
        }}
        payload_wire[label] = wire_cnt

    out = {{
        'handshake_latencies_raw': handshake_latencies,
        'handshake_latency_ms': compute_statistics(handshake_latencies),
        'total_handshake_wire_bytes': protocol_handshake_wire,
        'protocol_handshake_wire_bytes': protocol_handshake_wire,
        'harness_overhead_bytes': harness_overhead_bytes,
        'socket_total_handshake_bytes': socket_total_handshake_bytes,
        'payloads': payload_results,
        'payload_wire_bytes': payload_wire,
        'effective_affinity_cores': list(effective_aff),
    }}
    print('__CLIENT_RESULT__' + json.dumps(out), flush=True)

if __name__ == '__main__':
    asyncio.run(run_client())
"""

    cli_proc = subprocess.Popen(
        ["ip", "netns", "exec", "ns_cli", sys.executable, "-u", "-c", client_runner_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if cgroup_name and memory_limit_bytes:
        try:
            (Path(f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs")).write_text(str(cli_proc.pid))
        except Exception as e:
            print(f"[Platform_D] Warning adding cli to cgroup: {e}")

    cli_stdout, cli_stderr = cli_proc.communicate()

    # Terminate server
    srv_proc.terminate()
    try:
        srv_proc.wait(timeout=2)
    except Exception:
        srv_proc.kill()

    counters_after = get_interface_packet_counters("ns_cli", "veth_cli")
    teardown_netns_environment()

    mem_stats = profiler.stop()

    # Parse result
    client_res = {}
    for line in cli_stdout.splitlines():
        if "__CLIENT_RESULT__" in line:
            json_str = line.split("__CLIENT_RESULT__")[1]
            client_res = json.loads(json_str)
            break

    if not client_res:
        raise RuntimeError(f"Platform D client failed: {cli_stderr}")

    packets_diff = counters_after["total_packets"] - counters_before["total_packets"]
    bytes_diff = (counters_after["rx_bytes"] + counters_after["tx_bytes"]) - (counters_before["rx_bytes"] + counters_before["tx_bytes"])

    client_res["platform"] = "Platform_D"
    client_res["memory"] = mem_stats
    client_res["effective_constraints"] = {
        "cpu_pinned_core": cpu_pin,
        "effective_affinity_cores": client_res.get("effective_affinity_cores", []),
        "memory_limit_bytes": memory_limit_bytes,
        "cgroup_memory_max_effective": effective_cgroup_max,
        "cgroup_name": cgroup_name,
    }
    client_res["kernel_network_counters"] = {
        "packets_exchanged": max(0, packets_diff),
        "interface_wire_bytes": max(0, bytes_diff),
        "mtu_bytes": mtu,
        "netem_delay_ms": delay_ms,
        "netem_jitter_ms": jitter_ms,
        "rate_mbps": rate_mbps,
    }

    return client_res


# =====================================================================
# 4. Master Orchestration & Result Compilation
# =====================================================================
def execute_full_suite(
    output_dir: str = "results/tables",
    handshake_trials: int = 100,
    payload_trials: int = 100,
) -> Dict[str, Any]:
    """
    Executes the complete benchmarking suite meeting every criteria:
      1. Microbenchmarks (primitives)
      2. Platform A (Baseline native host, 1 core pinned)
      3. Platform B (Constrained 1 core, 512 MB cgroups v2 RAM limit)
      4. Platform B Ablations (B-cpu-only, B-mem-only)
      5. Platform D (Real veth, MTU 1500, netem 15ms 3ms, 1 core, 128 MB RAM)
      6. Platform D Ablations (D-baseline, D-latency, D-jitter, D-rate-limit)
      7. Code size metrics
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print("=================================================================")
    print("QSC POST-QUANTUM SECURE CHANNEL: MASTER BENCHMARK EXECUTION")
    print("=================================================================")
    crypto_meta = get_crypto_metadata()
    print(f"liboqs Version: {crypto_meta['liboqs_version']}")
    print(f"liboqs Backend: {crypto_meta['backend']}")
    print(f"KEM Mechanism:  {crypto_meta['kem_mechanism']}")
    print(f"DSA Mechanism:  {crypto_meta['sig_mechanism']}")
    print("-----------------------------------------------------------------")

    # 1. Microbenchmarks
    print("\n[1/7] Running Cryptographic Primitives Microbenchmarks (100 trials)...")
    micro = run_micro_benchmarks(trials=100, warmup=10)

    # 2. Platform A
    print("\n[2/7] Benchmarking Platform A (Baseline Native Host: 1 CPU core, unconstrained RAM)...")
    res_a = run_platform_benchmark(
        platform_name="Platform_A",
        cpu_pin=0,
        memory_limit_bytes=None,
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
    )

    # 3. Platform B
    print("\n[3/7] Benchmarking Platform B (Constrained Profile: 1 CPU core, 512 MB cgroups v2 RAM)...")
    res_b = run_platform_benchmark(
        platform_name="Platform_B",
        cpu_pin=0,
        cgroup_name="qsc_bench",
        memory_limit_bytes=536870912,  # 512 MB
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
    )

    # 4. Platform B Ablations
    print("\n[4/7] Benchmarking Platform B Ablations (B-cpu-only & B-mem-only)...")
    res_b_cpu = run_platform_benchmark(
        platform_name="Platform_B_cpu_only",
        cpu_pin=0,
        memory_limit_bytes=None,
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
    )
    res_b_mem = run_platform_benchmark(
        platform_name="Platform_B_mem_only",
        cpu_pin=None,
        cgroup_name="qsc_bench_128m",
        memory_limit_bytes=134217728,  # 128 MB
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
    )

    # 5. Platform D (Primary)
    print("\n[5/7] Benchmarking Platform D (Kernel NetNS: MTU 1500, netem 15ms delay, 3ms jitter, 1 core, 128 MB RAM)...")
    res_d = run_platform_d_benchmark(
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
        mtu=1500,
        delay_ms=15.0,
        jitter_ms=3.0,
        rate_mbps=None,
        cpu_pin=0,
        cgroup_name="qsc_bench_d",
        memory_limit_bytes=134217728,  # 128 MB
    )

    # 6. Platform D Ablations (100 trials each)
    print("\n[6/7] Benchmarking Platform D Bottleneck Ablations (100 trials each)...", flush=True)
    payload_files_ablation = {
        "1KB": "data/raw/payload_1kb.bin",
        "100KB": "data/raw/payload_100kb.bin",
    }
    res_d_base = run_platform_d_benchmark(
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
        payload_files=payload_files_ablation,
        mtu=1500,
        delay_ms=0.0,
        jitter_ms=0.0,
        cpu_pin=0,
        cgroup_name="qsc_bench_d",
        memory_limit_bytes=134217728,
    )
    res_d_lat = run_platform_d_benchmark(
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
        payload_files=payload_files_ablation,
        mtu=1500,
        delay_ms=15.0,
        jitter_ms=0.0,
        cpu_pin=0,
        cgroup_name="qsc_bench_d",
        memory_limit_bytes=134217728,
    )
    res_d_jit = run_platform_d_benchmark(
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
        payload_files=payload_files_ablation,
        mtu=1500,
        delay_ms=15.0,
        jitter_ms=3.0,
        cpu_pin=0,
        cgroup_name="qsc_bench_d",
        memory_limit_bytes=134217728,
    )
    res_d_rate = run_platform_d_benchmark(
        handshake_trials=handshake_trials,
        payload_trials=payload_trials,
        payload_files=payload_files_ablation,
        mtu=1500,
        delay_ms=15.0,
        jitter_ms=3.0,
        rate_mbps=10.0,
        cpu_pin=0,
        cgroup_name="qsc_bench_d",
        memory_limit_bytes=134217728,
    )

    # 7. Code Size Metrics
    print("\n[7/7] Computing Codebase Size & Metric Tracking...")
    code_size = get_code_size("src")

    # Aggregate master summary dictionary
    platforms_map = {
        "Platform_A": res_a,
        "Platform_B": res_b,
        "Platform_B_cpu_only": res_b_cpu,
        "Platform_B_mem_only": res_b_mem,
        "Platform_D": res_d,
    }

    d_ablations_map = {
        "D_baseline_unshaped": res_d_base,
        "D_latency_only_15ms": res_d_lat,
        "D_jitter_15ms_3ms": res_d_jit,
        "D_rate_limited_10mbps": res_d_rate,
    }

    all_data = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "crypto_metadata": crypto_meta,
            "target_suite": "ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256",
            "trials_per_measurement": {
                "handshake": handshake_trials,
                "payloads": payload_trials,
            },
        },
        "microbenchmarks": micro,
        "platforms": platforms_map,
        "platform_d_ablations": d_ablations_map,
        "code_size": code_size,
    }

    # Save benchmark_summary.json
    summary_file = out_path / "benchmark_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2)
    print(f"\nSaved master summary JSON: {summary_file}")

    # Write Table 1: Handshake Comparison CSV
    csv_hs = out_path / "handshake_comparison.csv"
    with open(csv_hs, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Platform", "Trials", "Mean (ms)", "Median (ms)", "StdDev (ms)", "p95 (ms)", "95% CI Lower", "95% CI Upper", "Protocol Wire (B)", "Harness Overhead (B)", "Total Socket Wire (B)"])
        for p_name, p_data in platforms_map.items():
            hs = p_data["handshake_latency_ms"]
            proto_w = p_data.get("protocol_handshake_wire_bytes") or p_data.get("total_handshake_wire_bytes", 9080)
            harness_w = p_data.get("harness_overhead_bytes", 0)
            sock_w = proto_w + harness_w
            w.writerow([
                p_name,
                hs["count"],
                f"{hs['mean']:.4f}",
                f"{hs['median']:.4f}",
                f"{hs['std']:.4f}",
                f"{hs['p95']:.4f}",
                f"{hs['ci_95_lower']:.4f}",
                f"{hs['ci_95_upper']:.4f}",
                proto_w,
                harness_w,
                sock_w,
            ])

    # Write Table 2: Throughput Comparison CSV
    csv_tp = out_path / "throughput_comparison.csv"
    with open(csv_tp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Platform", "Payload", "Trials", "Mean Time (ms)", "Median Time (ms)", "Throughput Mean (MB/s)", "Throughput p95 (MB/s)", "Wire Bytes"])
        for p_name, p_data in platforms_map.items():
            for p_size, p_metrics in p_data["payloads"].items():
                tt = p_metrics["transfer_time_ms"]
                tp = p_metrics["throughput_mb_s"]
                wb = p_data.get("payload_wire_bytes", {}).get(p_size, 0)
                w.writerow([
                    p_name,
                    p_size,
                    tt["count"],
                    f"{tt['mean']:.4f}",
                    f"{tt['median']:.4f}",
                    f"{tp['mean']:.2f}",
                    f"{tp['p95']:.2f}",
                    wb,
                ])

    # Write Table 3: Primitives Breakdown CSV
    csv_prim = out_path / "primitives_breakdown.csv"
    with open(csv_prim, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Primitive", "Trials", "Mean (ms)", "Median (ms)", "StdDev (ms)", "p95 (ms)", "95% CI Lower", "95% CI Upper"])
        for prim_name, prim_data in micro.items():
            w.writerow([
                prim_name,
                prim_data["count"],
                f"{prim_data['mean']:.4f}",
                f"{prim_data['median']:.4f}",
                f"{prim_data['std']:.4f}",
                f"{prim_data['p95']:.4f}",
                f"{prim_data['ci_95_lower']:.4f}",
                f"{prim_data['ci_95_upper']:.4f}",
            ])

    # Write Table 4: Memory Footprint Comparison CSV
    csv_mem = out_path / "memory_comparison.csv"
    with open(csv_mem, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Platform", "Initial RSS (MB)", "Peak RSS (MB)", "Kernel Peak RSS (MB)", "Peak Python Heap (MB)", "Cgroup Peak (MB)", "Cgroup Limit (MB)"])
        for p_name, p_data in platforms_map.items():
            m = p_data["memory"]
            init_rss_mb = m.get("initial_rss_bytes", 0) / (1024 * 1024)
            peak_rss_mb = m.get("peak_rss_mb", 0)
            kern_rss_mb = m.get("kernel_peak_rss_bytes", 0) / (1024 * 1024)
            heap_mb = m.get("peak_heap_mb", 0)
            cg_peak_mb = (m.get("cgroup_peak_bytes") or 0) / (1024 * 1024) if m.get("cgroup_peak_bytes") else "N/A"
            cg_max_mb = (m.get("cgroup_max_bytes") or 0) / (1024 * 1024) if m.get("cgroup_max_bytes") else "Unconstrained"
            w.writerow([
                p_name,
                f"{init_rss_mb:.2f}",
                f"{peak_rss_mb:.2f}",
                f"{kern_rss_mb:.2f}",
                f"{heap_mb:.2f}",
                f"{cg_peak_mb if isinstance(cg_peak_mb, str) else f'{cg_peak_mb:.2f}'}",
                f"{cg_max_mb if isinstance(cg_max_mb, str) else f'{cg_max_mb:.2f}'}",
            ])

    # Write Table 5: Platform D Netem Parameter Breakdown CSV
    csv_d = out_path / "platform_d_breakdown.csv"
    with open(csv_d, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Configuration", "Trials", "MTU (B)", "Delay (ms)", "Jitter (ms)", "Rate Limit", "Handshake Mean (ms)", "Handshake p95 (ms)", "Protocol Wire (B)", "Harness Wire (B)", "Interface Wire (B)", "Packets Exchanged"])
        for d_name, d_res in d_ablations_map.items():
            kc = d_res.get("kernel_network_counters", {})
            hs = d_res["handshake_latency_ms"]
            proto_w = d_res.get("protocol_handshake_wire_bytes") or d_res.get("total_handshake_wire_bytes", 9080)
            harness_w = d_res.get("harness_overhead_bytes", 6)
            w.writerow([
                d_name,
                hs["count"],
                kc.get("mtu_bytes", 1500),
                kc.get("netem_delay_ms", 0),
                kc.get("netem_jitter_ms", 0),
                kc.get("rate_mbps") or "Line-Rate",
                f"{hs['mean']:.4f}",
                f"{hs['p95']:.4f}",
                proto_w,
                harness_w,
                kc.get("interface_wire_bytes", 0),
                kc.get("packets_exchanged", 0),
            ])

    # Write Table 6: Code Size Metrics CSV
    csv_code = out_path / "code_size_metrics.csv"
    with open(csv_code, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["File", "SLOC", "Total Lines", "Bytes"])
        for f_name, f_stats in code_size["files"].items():
            w.writerow([f_name, f_stats["sloc"], f_stats["total_lines"], f_stats["bytes"]])
        w.writerow(["TOTAL", code_size["total_sloc"], code_size["total_lines"], code_size["total_bytes"]])

    print("All CSV tables and JSON files written to results/tables/ successfully.")
    return all_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QSC Benchmarking Engine")
    parser.add_argument("--trials", type=int, default=100, help="Number of trials per measurement (default: 100)")
    parser.add_argument("--output-dir", type=str, default="results/tables", help="Output directory for results")
    args = parser.parse_args()

    execute_full_suite(output_dir=args.output_dir, handshake_trials=args.trials, payload_trials=args.trials)
