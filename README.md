# QSC: Production-Grade Post-Quantum Secure Channel
**Qiskit Fall Fest 2026 (QFF 2026) — Track 5: Post-Quantum Cryptography**  
**Problem Statement P1: "Quantum-Safe Secure Channel"**  
**Codename:** `QSC — Quantum-Safe Channel`

[![Tests](https://img.shields.io/badge/pytest-24%20passed-brightgreen.svg)](tests/)
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
       |  ----------------- 1. ClientHello (1,228 B) --------------->  [Verify Version & Ciphersuite]
       |     {version, suite_id, N_c, PK_kem_eph, timestamp}             [Generate N_s (32B)]
       |                                                                 [SS, CT_kem = Encaps(PK_kem_eph)]
       |                                                                 [Compute Transcript_1]
       |                                                                 [Sig_server = Sign(SK_dsa_server, Transcript_1)]
       |  <---------------- 2. ServerHello (4,449 B) -----------------   [Derive PRK = HKDF-Extract(N_c || N_s, SS)]
       |     {CT_kem, N_s, ID_server, Sig_server, timestamp}
[Verify Server Identity Pin]
[Compute Transcript_1 & Verify Sig_server]
[SS = Decaps(SK_kem_eph, CT_kem)]
[Derive PRK & Session Keys: K_c2s, K_s2c, IVs]
[Compute Transcript_2]
[Sig_client = Sign(SK_dsa_client, Transcript_2)]
       |
       |  ----------------- 3. ClientAuth (3,355 B) ---------------->  [Verify Client Identity Pin]
       |     {ID_client, Sig_client, MAC_confirm}                        [Verify Sig_client over Transcript_2]
       |                                                                 [Derive Session Keys]
       |                                                                 [Verify MAC_confirm Token]
[CHANNEL ESTABLISHED]                                              [CHANNEL ESTABLISHED]
```

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

Measured on classical x86_64 hardware ($\ge 100$ handshake runs, $\ge 30$ transfer trials per payload, with nanosecond resolution):

### Handshake Latency & Wire Bloat
| Platform | Environment Profile | Mean (ms) | Median (ms) | p95 (ms) | 95% Bootstrap CI (ms) | Handshake Wire Bytes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Platform A** | Native Host Baseline (1 core) | **0.7801** | 0.7336 | 1.0719 | [0.7506, 0.8122] | 9,032 B |
| **Platform B** | Constrained Server (1 core, 512 MB) | **0.7538** | 0.7153 | 1.0659 | [0.7272, 0.7811] | 9,032 B |
| **Platform B (cpu)** | Ablation: 1 core, unconstrained RAM | **0.7773** | 0.7541 | 1.0604 | [0.7501, 0.8066] | 9,032 B |
| **Platform B (mem)** | Ablation: Host CPUs, 128 MB RAM | **0.7826** | 0.7303 | 1.0986 | [0.7437, 0.8326] | 9,032 B |
| **Platform D** | Network Emulator (1500B MTU + 15ms Jitter) | **47.2964** | 47.2675 | 47.8437 | [47.2482, 47.3479] | 9,032 B |

### Streaming AEAD Throughput vs. Payload Size
| Platform | 1 KB Payload | 100 KB Payload | 10 MB Payload |
| :--- | :--- | :--- | :--- |
| **Platform A** | 6.02 MB/s (0.17 ms) | 242.32 MB/s (0.42 ms) | **394.56 MB/s (25.72 ms)** |
| **Platform B** | 4.92 MB/s (0.21 ms) | 247.13 MB/s (0.41 ms) | **364.47 MB/s (27.70 ms)** |
| **Platform D** | 0.03 MB/s (30.98 ms) | 2.10 MB/s (46.59 ms) | **3.99 MB/s (2,506 ms)** |

### Cryptographic Micro-benchmark Breakdown
* `ML-KEM-768 Encap`: **15.0 $\mu$s** (vs. Classical ECDH P-256: 65.0 $\mu$s)
* `ML-KEM-768 Decap`: **16.8 $\mu$s**
* `ML-DSA-65 Sign`: **96.1 $\mu$s**
* `ML-DSA-65 Verify`: **35.8 $\mu$s** (vs. Classical ECDSA P-256 Verify: 69.7 $\mu$s)
* `HKDF-SHA256 Derive`: **12.4 $\mu$s**

---

## 7. Platform D Innovation: Post-Quantum Wire Bloat & MTU Fragmentation

While post-quantum primitives are computationally faster than classical elliptic curve math, they suffer from **wire bloat**:
* Classical ECDH + ECDSA handshake wire size: **~336 bytes** (fits completely within a single standard 1,500-byte Ethernet MTU).
* Post-Quantum ML-KEM-768 + ML-DSA-65 handshake wire size: **9,032 bytes** (requires multiple IP packet fragmentations and TCP segment reassemblies).
* Under Platform D's network conditions (1,500 B MTU with 15ms jitter), the 9 KB wire footprint causes a **+5,960% latency inflation** (from 0.78 ms to 47.30 ms), proving that wire bloat—not CPU execution—is the primary bottleneck in production PQC deployment.

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
