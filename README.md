# QSC: Production-Grade Post-Quantum Secure Channel
**Qiskit Fall Fest 2026 (QFF 2026) — Track 5: Post-Quantum Cryptography**  
**Problem Statement P1: "Quantum-Safe Secure Channel"**  
**Codename:** `QSC — Quantum-Safe Channel`

[![Tests](https://img.shields.io/badge/pytest-25%20passed-brightgreen.svg)](tests/)
[![NIST FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM--768-blue.svg)](docs/PROTOCOL.md)
[![NIST FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA--65-blue.svg)](docs/PROTOCOL.md)
[![AEAD](https://img.shields.io/badge/AEAD-AES--256--GCM-success.svg)](docs/PROTOCOL.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey.svg)](LICENSE)

---

## 1. Executive Overview

**QSC (Quantum-Safe Channel)** is a submission-ready, production-grade secure communication channel engineered strictly under classical execution rules for **Qiskit Fall Fest 2026 (Track 5, Problem Statement P1)**.

### Core Cryptographic Standards
* **Key Encapsulation:** **NIST FIPS 203 (ML-KEM-768)** via `liboqs` ($PK = 1,184\text{ B}$, $CT = 1,088\text{ B}$, $SS = 32\text{ B}$).
* **Mutual Authentication:** **NIST FIPS 204 (ML-DSA-65)** via `liboqs` ($PK = 1,952\text{ B}$, $Sig = 3,309\text{ B}$).
* **Key Derivation:** **RFC 5869 HKDF-SHA256** with domain-separated context expansion.
* **Bulk Encryption:** **NIST SP 800-38D AES-256-GCM** streaming in 64 KB authenticated chunks with strictly monotonic 64-bit counter replay defenses and incremental end-to-end SHA-256 verification.
* **Classical Baseline:** Benchmarked side-by-side against an **ECDH P-256 + ECDSA P-256** reference baseline (*labeled clearly as broken by Shor's algorithm on a CRQC*) to isolate post-quantum overheads.

---

## 2. Repository Structure

This repository strictly matches the official hackathon submission template:

```text
project/
├── README.md                          # Executive overview, usage, and results summary
├── main.ipynb                         # Interactive notebook walking through the full pipeline
├── requirements.txt                   # Pinned dependency specifications
├── data/
│   ├── raw/                           # Deterministically seeded payloads (1kb, 100kb, 10mb)
│   └── processed/                     # Normalized test vectors and checksum metadata
├── processors/
│   ├── processor_A.json               # Baseline Native Host single-core specification
│   └── processor_B.json               # Constrained Server (1 core, 512 MB RAM) specification
├── src/
│   ├── __init__.py                    # Package initialization
│   ├── problem.py                     # Problem Statement P1 solver engine & session runner
│   ├── processors.py                  # Hardware/processor profile manager
│   ├── routing.py                     # Transport routing, chunk framing, and MitM proxy routing
│   ├── metrics.py                     # Nanosecond timing, RSS/heap memory profiler, bootstrap CIs
│   └── visualization.py               # Publication-grade chart generation
├── results/
│   ├── tables/                        # Raw & summarized benchmark tables (CSV/JSON)
│   └── figures/                       # Publication-quality generated figures
├── report.md                          # Comprehensive judging evaluation report
└── assets/
    └── qff_phase1_latex_images/       # High-resolution LaTeX mathematical equation assets
        ├── eq_qubit_state.png
        ├── eq_bell_state.png
        ├── eq_graph.png
        ├── eq_bell_fidelity.png
        ├── eq_zz_expectation.png
        └── eq_standard_error.png
```

---

## 3. Handshake Architecture & Wire Framing

```
       Client Node                                                    Server Node
       ===========                                                    ===========
[Ephemeral ML-KEM-768 Keygen]
       |
       |  ----------------- 1. ClientHello (1,232 B Wire) ------------>  [Verify Version & Ciphersuite]
       |     {version, suite_id, N_c, PK_kem_eph, timestamp}             [Generate N_s (32B)]
       |                                                                 [SS, CT_kem = Encaps(PK_kem_eph)]
       |                                                                 [Compute Transcript_1]
       |                                                                 [Sig_server = Sign(SK_dsa_server, Transcript_1)]
       |  <---------------- 2. ServerHello (4,453 B Wire) ------------   [Derive PRK = HKDF-Extract(N_c || N_s, SS)]
       |     {CT_kem, N_s, ID_server, Sig_server, timestamp}             [Derive Session Keys & K_finished]
[Verify Server Identity Pin]
[Compute Transcript_1 & Verify Sig_server]
[SS = Decaps(SK_kem_eph, CT_kem)]
[Derive PRK & Session Keys: K_c2s, K_s2c, IVs, K_finished]
[Compute Transcript_2]
[Sig_client = Sign(SK_dsa_client, Transcript_2)]
[MAC_c = HMAC(K_finished, "CLIENT" || Transcript_2)]
       |
       |  ----------------- 3. ClientAuth (3,359 B Wire) ------------->  [Verify Client Identity Pin]
       |     {ID_client, Sig_client, MAC_confirm}                        [Verify Sig_client over Transcript_2]
       |                                                                 [Verify MAC_c Token]
       |                                                                 [Compute Transcript_3]
       |                                                                 [MAC_s = HMAC(K_finished, "SERVER" || Transcript_3)]
       |  <---------------- 4. ServerFinished (36 B Wire) ------------  [Send Server Finished Confirmation]
       |     {MAC_confirm}
[Compute Transcript_3]
[Verify MAC_s Token]
[CHANNEL ESTABLISHED]                                              [CHANNEL ESTABLISHED]
```

### Measured Wire Flight Sizes (Socket Boundary)
* **Flight 1 (`ClientHello`):** $1,228\text{ B}$ payload $+ 4\text{ B}$ length prefix $= \mathbf{1,232\text{ B}}$
* **Flight 2 (`ServerHello`):** $4,449\text{ B}$ payload $+ 4\text{ B}$ length prefix $= \mathbf{4,453\text{ B}}$
* **Flight 3 (`ClientAuth`):** $3,355\text{ B}$ payload $+ 4\text{ B}$ length prefix $= \mathbf{3,359\text{ B}}$
* **Flight 4 (`ServerFinished`):** $32\text{ B}$ payload $+ 4\text{ B}$ length prefix $= \mathbf{36\text{ B}}$
* **Total Handshake Wire:** $9,064\text{ B}$ payload / $\mathbf{9,080\text{ B}}$ wire framing ($+6\text{ B}$ routing prefix across netns).

> [!NOTE]
> **Cryptographic Freshness vs. Timestamps:** Timestamps are included in message headers for logging and diagnostic telemetry. However, protocol freshness and replay immunity are strictly established by fresh 256-bit cryptographically secure random nonces ($N_c, N_s$), ephemeral KEM key generation per session, and transcript binding—not by wall-clock time—preventing denial-of-service or vulnerabilities under clock drift.

### Binary Chunk Framing (64 KB Authenticated Chunks)
```
+-----------------------------------------------------------------------------+
| Chunk Length N  | Monotonic Counter |        IV         | Ciphertext ...    | GCM Tag  |
|    (4 Bytes)    |     (8 Bytes)     |    (12 Bytes)     |    (N-16 Bytes)   | (16 B)   |
+-----------------------------------------------------------------------------+
```
* **Nonce Derivation:** $IV_{\text{chunk}} = IV_{\text{base}} \oplus \text{ZeroPad}_{12}(\text{Counter})$
* **Replay Protection:** Strictly monotonic counter initialized to 1; out-of-order, replayed, or duplicate packets are dropped immediately.
* **Associated Data Binding:** $AAD = \text{SessionID} \,(32\text{B}) \parallel \text{Direction} \,(1\text{B}) \parallel \text{Counter} \,(8\text{B}) \parallel \text{FinalFlag} \,(1\text{B})$.

---

## 3. Quickstart & Installation

### Option A: Native Linux / WSL (Recommended)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run automated test suite (24/24 passing)
make test

# 3. Run headline MitM attack demonstration
make demo

# 4. Execute multi-platform benchmarks & render figures
make bench
```

### Option B: Docker Container
```bash
docker compose up platform-a
docker compose up platform-b
docker compose up platform-d
```

---

## 4. CLI Usage Guide (`qsc`)

The unified CLI provides comprehensive identity management, server/client streaming, and adversary attack demos:

```bash
# 1. Generate ML-DSA-65 identity keypair
qsc keygen --identity alice
qsc keygen --identity bob

# 2. Pin peer public keys in out-of-band trust stores
qsc trust --identity bob --pubkey ~/.qsc/identities/bob.pub
qsc trust --identity alice --pubkey ~/.qsc/identities/alice.pub

# 3. Start authenticated receiver server
qsc serve --port 8443 --identity bob

# 4. Stream an encrypted file (authenticated client)
qsc send --target 127.0.0.1:8443 --file data/raw/payload_10mb.bin --identity alice

# 5. Run headline active MitM proxy demonstration
qsc attack-demo
```

---

## 5. Headline Attack Demonstration (`qsc attack-demo`)

Side-by-side proof of post-quantum security hardening:
* **Scenario A (Unauthenticated KEM):** An active proxy intercepts `ClientHello`, swaps the ephemeral KEM key, establishes two separate sessions, and transparently decrypts the payload without either peer detecting it (**VULNERABLE**).
* **Scenario B (QSC Authenticated):** The same proxy attempts ephemeral key substitution. The server signs the cryptographic transcript binding containing the client's public key using its pinned long-term `ML-DSA-65` identity key. The client signature check fails, terminating the session immediately with **zero plaintext leakage** (**SECURE**).

---

## 6. Empirical Benchmark Results

Measured on Linux/WSL classical x86_64 hardware (100 trials for every handshake and payload size, nanosecond resolution):

### Handshake Latency & Wire Bloat (100 Trials Each)
| Platform | Environment Profile | Mean (ms) | Median (ms) | StdDev (ms) | p95 (ms) | 95% Bootstrap CI (ms) | Protocol Wire | Harness Wire | Total Socket |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Platform A** | Native Host Baseline (1 core pinned via sched_setaffinity) | **1.1734** | 1.1010 | 0.2181 | 1.6005 | [1.1336, 1.2208] | 9,080 B | 0 B | 9,080 B |
| **Platform B** | Constrained Server (1 core pinned, 512 MB cgroups v2) | **1.1841** | 1.1123 | 0.2548 | 1.7470 | [1.1374, 1.2353] | 9,080 B | 0 B | 9,080 B |
| **Platform B (cpu)** | Ablation: 1 core pinned, unconstrained RAM | **1.0812** | 1.0301 | 0.1869 | 1.4556 | [1.0463, 1.1190] | 9,080 B | 0 B | 9,080 B |
| **Platform B (mem)** | Ablation: Host CPUs, 128 MB cgroups v2 RAM | **1.0825** | 1.0479 | 0.1399 | 1.3037 | [1.0566, 1.1115] | 9,080 B | 0 B | 9,080 B |
| **Platform D** | Kernel NetNS (1 core, 128 MB cgroups, MTU 1500, 15ms/3ms) | **65.9747** | 66.1105 | 2.6180 | 69.9835 | [65.4185, 66.5371] | 9,080 B | 6 B | 9,086 B |

*Note on A vs. B:* Both Platform A and B allocate 1 dedicated CPU core (`sched_setaffinity(0, {0})`). Handshake CPU latencies are statistically indistinguishable (1.173 ms vs 1.184 ms), confirming that the primary difference is the 512 MB cgroups v2 memory constraint, under which QSC operates well below the memory ceiling. Sequential cgroup isolation is guaranteed by fresh child process execution.

### Streaming AEAD Throughput vs. Payload Size (100 Trials Each)
| Platform | 1 KB Payload | 100 KB Payload | 10 MB Payload |
| :--- | :--- | :--- | :--- |
| **Platform A** | 0.42 MB/s (2.37 ms) | 32.11 MB/s (3.11 ms) | **133.22 MB/s (75.14 ms)** |
| **Platform B** | 0.45 MB/s (2.24 ms) | 32.87 MB/s (3.01 ms) | **134.13 MB/s (74.76 ms)** |
| **Platform D** | 0.03 MB/s (34.34 ms) | 0.82 MB/s (119.24 ms) | **30.03 MB/s (343.78 ms)** |

### Peak Memory Footprint During 10 MB Transfer
* **Platform A:** Peak Process RSS: **39.53 MB** | Peak Python Heap (`tracemalloc`): **1.75 MB** | Cgroup Limit: **Unconstrained**
* **Platform B:** Peak Process RSS: **39.53 MB** | Peak Python Heap: **1.75 MB** | Cgroup Peak: **23.58 MB** | Cgroup Limit: **512.00 MB**
* **Platform B (mem-only):** Peak Process RSS: **39.53 MB** | Peak Python Heap: **1.75 MB** | Cgroup Peak: **24.24 MB** | Cgroup Limit: **128.00 MB**
* **Platform D:** Peak Process RSS: **39.84 MB** | Peak Python Heap: **0.66 MB** | Cgroup Peak: **46.21 MB** | Cgroup Limit: **128.00 MB**

### Cryptographic Micro-benchmark Breakdown (100 Trials)
* `ML-KEM-768 Keygen`: **17.0 us**
* `ML-KEM-768 Encap`: **15.2 us** (vs. Classical ECDH P-256: 61.3 us)
* `ML-KEM-768 Decap`: **18.9 us**
* `ML-DSA-65 Sign`: **102.6 us**
* `ML-DSA-65 Verify`: **38.8 us** (vs. Classical ECDSA P-256 Verify: 71.2 us)
* `HKDF-SHA256 Derive`: **12.8 us**
* `Classical ECDSA P-256 Sign`: **22.6 us**

---

## 7. Platform D Innovation: Kernel NetNS MTU Segmentation & Jitter Analysis

Platform D executes across isolated Linux network namespaces (`ns_cli`, `ns_srv`) over a virtual Ethernet (`veth`) pair shaped via kernel `tc netem`. Both client and server processes are strictly constrained to 1 pinned CPU core and 128 MB RAM in cgroup `qsc_bench_d`:
* **Standard Ethernet MTU:** 1,500 bytes (TCP MSS = 1,460 bytes).
* **Classical ECDH + ECDSA Handshake:** ~336 bytes (fits completely in a single 1,460 B TCP segment without segmentation).
* **Post-Quantum ML-KEM-768 + ML-DSA-65 Handshake:** **9,080 bytes** protocol wire (plus 6 bytes netns multiplexing control framing). Exceeds the 1,460-byte TCP MSS by $6.22\times$, inducing multi-segment TCP packetization.
* **TCP Segmentation vs. IP Fragmentation:** Because the TCP stack packetizes the stream within the MSS boundary prior to submitting packets to the IP layer, **no Layer-3 IP fragmentation occurs**. Instead, the performance penalty is governed by **multi-segment TCP transmission, sliding-window acknowledgment serialization, and jitter-induced reassembly latency**.
* **Measured Netem Ablation Results (Table 5: 100 Trials Each):**
  * `D_baseline_unshaped` (MTU 1500, 0ms delay): **0.9105 ms** (6,642 kernel packets exchanged)
  * `D_latency_only_15ms` (MTU 1500, 15ms delay): **62.4694 ms** (10,622 packets)
  * `D_jitter_15ms_3ms` (MTU 1500, 15ms delay, 3ms jitter): **66.0228 ms** (p95: 71.05 ms, 14,554 packets)
  * `D_rate_limited_10mbps` (MTU 1500, 15ms delay, 3ms jitter, 10 Mbps): **74.7957 ms** (13,406 packets)
* **Finding:** While handshake latency is dominated by network round-trips and TCP segmentation reassembly across MTU boundaries (+7,150% increase over local baseline), 10 Mbps bandwidth throttling introduces only modest additional delay (~8.8 ms) on handshakes, proving that round-trip serialization and jitter—not raw link bandwidth—form the critical bottleneck for post-quantum handshakes.

---

## 8. Artifact Locations

* **Final Technical Judging Report:** [`report.md`](report.md)
* **Cryptographic Protocol Spec:** [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
* **Adversary Threat Model:** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
* **AI Tooling Disclosure:** [`AI_USAGE.md`](AI_USAGE.md)
* **Generated High-Res Figures:** [`results/figures/`](results/figures/)
* **Raw Benchmark Datasets:** [`results/tables/`](results/tables/)
* **Platform JSON Specs:** [`processors/`](processors/)

---

## 9. Assumptions & Compliance Disclosures
1. **Classical Execution Boundary:** Zero quantum circuits or simulations were executed; PQC algorithms run strictly on classical x86/ARM processors.
2. **Phase Discrepancies:** Handled transparently by placing experimental extensions in `optional/` without perturbing the Platform A/B common baseline.
3. **AI Assistance Disclosure:** Fully documented in [`AI_USAGE.md`](AI_USAGE.md).
