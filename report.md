# QSC: Production-Grade Post-Quantum Secure Channel
## Final Technical Evaluation Report & Systems Analysis
**Competition:** Qiskit Fall Fest 2026 (QFF 2026)  
**Track:** Track 5 — Post-Quantum Cryptography  
**Problem Statement:** P1 — "Quantum-Safe Secure Channel"  
**System Codename:** `QSC` (Quantum-Safe Channel v1.0)  
**Evaluation Rubric Alignment:** Solution Correctness & Security (40 pts) | Platform & Systems Analysis (30 pts) | Innovation & Custom Design (30 pts)

---

## 1. Executive Summary & Threat Model

### 1.1 Mission & Architectural Principles
The advent of Cryptanalytically Relevant Quantum Computers (CRQCs) presents an existential threat to classical public-key cryptography. Under Shor's algorithm, integer factorization and discrete logarithm problems execute in polynomial time, rendering RSA, ECDH, and ECDSA obsolete. To counter the urgent threat of **Harvest-Now, Decrypt-Later (HNDL)**—where adversarial state actors record classical encrypted traffic today to decrypt retroactively—we designed, implemented, and empirically benchmarked **QSC (Quantum-Safe Channel)**.

QSC is an end-to-end, mutually authenticated, 1-RTT post-quantum secure transport protocol built strictly without hand-rolled primitives. It binds:
1. **Key Encapsulation:** **NIST FIPS 203 (ML-KEM-768)** for quantum-resistant ephemeral secret establishment.
2. **Mutual Authentication:** **NIST FIPS 204 (ML-DSA-65)** for post-quantum digital identity verification.
3. **Key Derivation:** **RFC 5869 HKDF-SHA256** with strict domain separation.
4. **Bulk Symmetric AEAD:** **NIST SP 800-38D AES-256-GCM** with strictly monotonic 64-bit frame counters and authenticated 64 KB chunk streaming.

```
+---------------------------------------------------------------------------------------------------+
|                                       QSC PROTOCOL STACK                                          |
+---------------------------------------------------------------------------------------------------+
| Application Layer      | Streaming Payloads (1 KB, 100 KB, 10 MB) with SHA-256 EOF Verification   |
+------------------------+--------------------------------------------------------------------------+
| Symmetric Framing      | 64 KB Authenticated Chunks | AES-256-GCM | IV = IV_base ^ Counter        |
+------------------------+--------------------------------------------------------------------------+
| Key Derivation         | RFC 5869 HKDF-SHA256 Extract-and-Expand (PRK, K_c2s, K_s2c, IVs, MAC)    |
+------------------------+--------------------------------------------------------------------------+
| Handshake Layer        | 1-RTT Mutually Authenticated Transcript Binding (Transcript_1, Transc_2) |
+------------------------+--------------------------------------------------------------------------+
| Asymmetric Primitives  | ML-KEM-768 (FIPS 203) Ephemeral KEM | ML-DSA-65 (FIPS 204) Identity DSA  |
+------------------------+--------------------------------------------------------------------------+
| Transport Layer        | Non-blocking Asyncio TCP Stream / Socket Framing Engine                  |
+---------------------------------------------------------------------------------------------------+
```

### 1.2 Adversary Models and Security Boundaries
QSC evaluates resistance across two rigorous adversarial tiers:
* **Classical Dolev-Yao Adversary ($\mathcal{A}_{\text{classical}}$):** Operates on the communication link with full active control: intercepting, modifying, injecting, dropping, and replaying packets.
* **Quantum Adversary ($\mathcal{A}_{\text{quantum}}$):** Possesses passive wiretaps capable of perpetual storage and eventual decryption using Shor's algorithm on a CRQC.

### 1.3 Scope Boundaries & Discrepancy Transparency
In accordance with official hackathon policies:
* **Purely Classical Execution:** Post-quantum algorithms are classical mathematical constructs executed entirely on classical CPU architectures. Zero quantum circuits or simulations were executed.
* **Problem Scope Isolation:** The implementation strictly addresses Problem Statement P1 ("Quantum-Safe Secure Channel"), actively rejecting scope creep into P2 or P3.
* **Platform Discrepancies:** While hackathon documentation varied regarding whether Platform D belonged to Phase 1 or Phase 2, we engineered Platform D as an independent, fully reproducible experiment in `processors/platform_D.json` and `results/` without disrupting the common Platform A/B baseline.

---

## 2. Protocol Architecture & Cryptographic Security Arguments

### 2.1 Handshake Sequence and FIPS Wire Sizes
QSC establishes mutual authentication and shared secrets in a single round-trip (1-RTT). Exact primitive wire sizes are asserted at initialization:
* **ML-KEM-768:** Public Key = $1,184\text{ B}$; Ciphertext = $1,088\text{ B}$; Shared Secret = $32\text{ B}$.
* **ML-DSA-65:** Public Key = $1,952\text{ B}$; Secret Key = $4,032\text{ B}$; Signature = $3,309\text{ B}$.

```
       Client Node                                                      Server Node
       ===========                                                      ===========
[Generate Ephemeral ML-KEM-768 Keypair]
       |
       |  ------------------ 1. ClientHello (1,228 B) ---------------->  [Validate Version (0x0100) & Suite (0x0001)]
       |     {version, suite_id, N_c, PK_kem_eph, timestamp}              [Generate Server Nonce N_s (32B)]
       |                                                                  [SS, CT_kem = Encaps(PK_kem_eph)]
       |                                                                  [Compute Transcript_1]
       |                                                                  [Sig_server = Sign(SK_dsa_server, Transcript_1)]
       |  <----------------- 2. ServerHello (4,449 B) -----------------   [Extract PRK = HKDF-Extract(N_c || N_s, SS)]
       |     {CT_kem, N_s, ID_server, Sig_server, timestamp}
[Verify Server Identity Pin in TrustStore]
[Compute Transcript_1 & Verify Sig_server]
[SS = Decaps(SK_kem_eph, CT_kem)]
[Extract PRK & Expand Session Keys: K_c2s, K_s2c, IVs]
[Compute Transcript_2]
[Sig_client = Sign(SK_dsa_client, Transcript_2)]
       |
       |  ------------------ 3. ClientAuth (3,355 B) ----------------->  [Verify Client Identity Pin in TrustStore]
       |     {ID_client, Sig_client, MAC_confirm}                         [Verify Sig_client over Transcript_2]
       |                                                                  [Derive Session Keys]
       |                                                                  [Verify MAC_confirm == Expected MAC]
[CHANNEL ESTABLISHED]                                               [CHANNEL ESTABLISHED]
```

### 2.2 Formal Transcript Binding & MitM Elimination Proof
In an unauthenticated ephemeral KEM, an active man-in-the-middle proxy $\mathcal{M}$ intercepts `ClientHello`, swaps the client's public key with its own, completes two independent key exchanges, and transparently decrypts the channel.

QSC formally eliminates MitM attacks through **cryptographic transcript binding**:
1. **Server Binding ($\text{Transcript}_1$):**
   $$\text{Transcript}_1 = \text{SHA-256}\left(\text{"QSC-v1-SERVER-BIND"} \,\|\, \text{Wire}(ClientHello) \,\|\, CT_{KEM} \,\|\, N_s \,\|\, \text{LenPre}(\text{ID}_{server})\right)$$
   $$\text{Sig}_{server} = \text{Sign}_{SK_{DSA\_server}}(\text{Transcript}_1)$$
   Because $\text{Wire}(ClientHello)$ includes the client's ephemeral public key $PK_{KEM\_eph}$, any modification by $\mathcal{M}$ alters $\text{Transcript}_1$. Because $\mathcal{M}$ does not possess the server's pinned private key $SK_{DSA\_server}$, $\mathcal{M}$ cannot forge $\text{Sig}_{server}$. The client's signature check fails, terminating the session immediately.
2. **Client Binding ($\text{Transcript}_2$):**
   $$\text{Transcript}_2 = \text{SHA-256}\left(\text{"QSC-v1-CLIENT-BIND"} \,\|\, \text{Transcript}_1 \,\|\, \text{Wire}(ServerHello) \,\|\, \text{LenPre}(\text{ID}_{client})\right)$$
   $$\text{Sig}_{client} = \text{Sign}_{SK_{DSA\_client}}(\text{Transcript}_2)$$
   $\text{Transcript}_2$ binds the entire bidirectional handshake history, guaranteeing agreement on session identity.

### 2.3 Key Derivation Architecture (RFC 5869 HKDF-SHA256)
* **PRK Extraction:**
  $$\text{PRK} = \text{HKDF-Extract}(\text{salt} = N_c \,\|\, N_s, \text{IKM} = SS)$$
* **Context-Separated Expansion:**
  * $K_{c2s} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-AES-256-GCM-C2S"} \,\|\, \text{Transcript}_2, 32)$
  * $K_{s2c} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-AES-256-GCM-S2C"} \,\|\, \text{Transcript}_2, 32)$
  * $IV_{c2s\_base} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-IV-BASE-C2S"} \,\|\, \text{Transcript}_2, 12)$
  * $IV_{s2c\_base} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-IV-BASE-S2C"} \,\|\, \text{Transcript}_2, 12)$
  * $\text{MAC}_{confirm} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-FINISHED-CONFIRM"}, 32)$
  * $\text{SessionID} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-SESSION-ID"} \,\|\, \text{Transcript}_2, 32)$

### 2.4 Streaming Symmetric Framing & Replay Defense
To transfer arbitrary payloads (1 KB, 100 KB, 10 MB) without memory blowup, data is framed into 64 KB authenticated chunks:
```
+------------------------------------------------------------------------------------+
| Length (4B, BE) | Counter (8B, BE) | IV (12B) | Encrypted Payload (NB) | Tag (16B) |
+------------------------------------------------------------------------------------+
```
* **Nonce Construction:** $IV = IV_{\text{base}} \oplus \text{ZeroPad}_{12}(\text{Counter})$.
* **Replay & Reordering Defense:** Monotonic counters strictly enforce $Counter = Counter_{\text{expected}}$. Packets with $Counter \le Counter_{\text{last}}$ are rejected as replays; packets with $Counter > Counter_{\text{expected}}$ are rejected as out-of-order gaps.
* **Associated Authenticated Data (AAD):**
  $$AAD = \text{SessionID} \,(32\text{B}) \parallel \text{Direction} \,(1\text{B}) \parallel \text{Counter} \,(8\text{B}) \parallel \text{FinalFlag} \,(1\text{B})$$
  Directional binding prevents reflection attacks.
* **End-to-End Verification:** Senders compute a running SHA-256 digest of unencrypted plaintext. The terminal chunk encapsulates an authenticated trailer:
  $$\text{EOF\_Payload} = \text{"QSC-EOF"} \,(7\text{B}) \parallel \text{TotalBytes} \,(8\text{B}) \parallel \text{SHA256}(\text{RawPlaintext}) \,(32\text{B})$$

---

## 3. Implementation & System Hardening

### 3.1 Python Runtime Security Realities
While `liboqs` C primitives implement constant-time algorithms for polynomial arithmetic, executing cryptographic state machines in higher-level languages introduces architectural nuances:
1. **Memory Sanitization Caveat:** Python strings and bytes are immutable, managed by the CPython memory allocator (`pymalloc`). Standard explicit zeroization (`memset`) cannot guarantee immediate clearing of physical RAM pages before garbage collection sweeps. In production C environments, `oqs_mem_cleanse` is applied to secret keys; in Python, we isolate keys in restricted ephemeral process scopes and enforce strict file permissions (`0600`) for identity keystores.
2. **Side-Channel Timing:** Interpreter branch execution and bytecode dispatch are not constant-time at the macro layer. QSC isolates all variable-sensitive operations inside vetted C-bindings (`liboqs` for lattice operations, OpenSSL via `cryptography` for AES-NI and SHA-256).

### 3.2 Wire Framing and Fail-Closed Semantics
The channel enforces strict fail-closed invariants:
* Any tampered byte in public keys, ciphertexts, signatures, nonces, or tags immediately raises a typed exception (`QSCTamperError`, `QSCReplayError`, `QSCAuthenticationError`) and severs the TCP connection.
* Unauthenticated or unpinned identities are aborted before symmetric key derivation begins.

---

## 4. Empirical Benchmarks (Platform A vs. Platform B)

All benchmarks were executed on an AMD Ryzen 7 5800H host running Ubuntu Linux (x86_64) using `time.perf_counter_ns` timing, $\ge 100$ timed handshake trials, and $\ge 30$ timed transfer trials per payload with Python garbage collection disabled during micro-benchmarks.

### 4.1 Handshake Latency Breakdown
| Platform Profile | CPU / RAM Specification | Mean (ms) | Median (ms) | StdDev (ms) | p95 (ms) | 95% Bootstrap CI | Handshake Wire Size |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Platform A** *(Baseline)* | 1 Core (`taskset -c 0`), Unconstrained RAM | **0.7801** | 0.7336 | 0.1619 | 1.0719 | [0.7506, 0.8122] | 9,032 Bytes |
| **Platform B** *(Constrained)* | 1 Core Cgroup, 512 MB RAM | **0.7538** | 0.7153 | 0.1418 | 1.0659 | [0.7272, 0.7811] | 9,032 Bytes |
| **Platform B (cpu-only)** | 1 Core Cgroup, Unconstrained RAM | **0.7773** | 0.7541 | 0.1482 | 1.0604 | [0.7501, 0.8066] | 9,032 Bytes |
| **Platform B (mem-only)** | Host CPUs, 128 MB RAM Cap | **0.7826** | 0.7303 | 0.2409 | 1.0986 | [0.7437, 0.8326] | 9,032 Bytes |
| **Platform D** *(Innovation)* | 1 Core, 128MB RAM, 1500B MTU + 15ms Jitter | **47.2964** | 47.2675 | 0.2741 | 47.8437 | [47.2482, 47.3479] | 9,032 Bytes |

### 4.2 Cryptographic Primitive Micro-benchmarks
Comparing NIST PQC standards against the classical reference baseline (broken by Shor's algorithm):

| Primitive | Operation | Mean Latency ($\mu$s) | Median ($\mu$s) | StdDev ($\mu$s) | p95 ($\mu$s) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-768** | Key Generation | 15.3 $\mu$s | 13.5 $\mu$s | 13.0 $\mu$s | 17.6 $\mu$s |
| **ML-KEM-768** | Encapsulation | **15.0 $\mu$s** | 14.1 $\mu$s | 4.7 $\mu$s | 20.5 $\mu$s |
| **ML-KEM-768** | Decapsulation | 16.8 $\mu$s | 16.1 $\mu$s | 5.7 $\mu$s | 17.3 $\mu$s |
| **ML-DSA-65** | Signature Generation | 96.1 $\mu$s | 80.0 $\mu$s | 63.6 $\mu$s | 204.8 $\mu$s |
| **ML-DSA-65** | Signature Verification | **35.8 $\mu$s** | 34.1 $\mu$s | 6.8 $\mu$s | 41.1 $\mu$s |
| **HKDF-SHA256** | Key Extraction & Expansion | 12.4 $\mu$s | 9.9 $\mu$s | 19.3 $\mu$s | 12.4 $\mu$s |
| *Classical Reference* | ECDH P-256 Key Exchange | 65.0 $\mu$s | 54.7 $\mu$s | 34.8 $\mu$s | 120.5 $\mu$s |
| *Classical Reference* | ECDSA P-256 Sign | 21.9 $\mu$s | 19.6 $\mu$s | 9.1 $\mu$s | 29.2 $\mu$s |
| *Classical Reference* | ECDSA P-256 Verify | 69.7 $\mu$s | 65.7 $\mu$s | 12.4 $\mu$s | 88.2 $\mu$s |

> [!NOTE]
> **Key Finding:** Post-quantum key encapsulation with `ML-KEM-768` ($15.0\,\mu\text{s}$) is **$4.3\times$ faster** than classical ECDH P-256 ($65.0\,\mu\text{s}$). Similarly, `ML-DSA-65` signature verification ($35.8\,\mu\text{s}$) is **$1.9\times$ faster** than classical ECDSA P-256 verification ($69.7\,\mu\text{s}$). The computational complexity of lattice arithmetic is significantly lower than modular elliptic curve scalar multiplications on modern hardware.

### 4.3 Streaming Payload Throughput (AES-256-GCM 64 KB Chunks)
| Payload Size | Metric | Platform A | Platform B | Platform D (Netem) |
| :--- | :--- | :--- | :--- | :--- |
| **1 KB** | Transfer Time (ms)<br>Throughput (MB/s) | 0.17 ms<br>6.02 MB/s | 0.21 ms<br>4.92 MB/s | 30.98 ms<br>0.03 MB/s |
| **100 KB** | Transfer Time (ms)<br>Throughput (MB/s) | 0.42 ms<br>242.32 MB/s | 0.41 ms<br>247.13 MB/s | 46.59 ms<br>2.10 MB/s |
| **10 MB** | Transfer Time (ms)<br>Throughput (MB/s) | **25.72 ms**<br>**394.56 MB/s** | **27.70 ms**<br>**364.47 MB/s** | **2,506.16 ms**<br>**3.99 MB/s** |

---

## 5. Platform B Ablation Analysis: Isolating CPU vs. Memory Bottlenecks

To isolate the root causes of server throttling, we executed controlled ablation benchmarks across two independent axes:
1. **B-cpu-only:** Single CPU core quota (1.0 core) with unconstrained physical RAM.
2. **B-mem-only:** Host multi-core CPU capacity with strict 128 MB RAM capping.

### Empirical Findings
* **Handshake Invariance:** Handshake latency remained identical across all ablations:
  * Platform A: $0.7801\text{ ms}$
  * B-cpu-only: $0.7773\text{ ms}$
  * B-mem-only: $0.7826\text{ ms}$
* **Memory Headroom:** Peak resident set size (RSS) across the full session lifecycle peaked at **41.2 MB**, with Python heap allocations (`tracemalloc`) peaking at **10.6 MB** even during active 10 MB payload streaming. Because QSC streams in 64 KB authenticated chunks, the memory footprint is $O(1)$ with respect to payload size.
* **Conclusion:** Constraining RAM to 128 MB or 512 MB exerts **zero allocation pressure or paging thrashing** on QSC. The protocol's CPU footprint is dominated by OpenSSL's AES-NI instructions, which saturate at ~395 MB/s on a single core.

---

## 6. Platform D Innovation Analysis: Post-Quantum Wire Bloat & MTU Fragmentation

### 6.1 The Engineering Hypothesis
Standard Ethernet networks operate with a Maximum Transmission Unit (MTU) of **1,500 bytes**.
* In classical TLS/channels (ECDH P-256 + ECDSA P-256), public keys (64 B) and signatures (72 B) fit comfortably within a single MTU frame ($< 400\text{ bytes}$ total handshake).
* In post-quantum channels, primitive sizes expand dramatically:
  * ML-KEM-768 Public Key: $1,184\text{ bytes}$
  * ML-KEM-768 Ciphertext: $1,088\text{ bytes}$
  * ML-DSA-65 Public Key: $1,952\text{ bytes}$
  * ML-DSA-65 Signature: $3,309\text{ bytes}$
  * **Total QSC Handshake Wire Size:** **9,032 bytes**

```
+-----------------------------------------------------------------------------------------+
| HANDSHAKE WIRE BLOAT COMPARISON                                                         |
+-----------------------------------------------------------------------------------------+
| Classical (ECDH + ECDSA):  [ 336 B ] ===> FITS IN SINGLE 1,500 B ETHERNET FRAME         |
+-----------------------------------------------------------------------------------------+
| Post-Quantum (QSC v1.0):   [====================== 9,032 B ======================]      |
|                            ===> FORCES 7x TCP SEGMENT REASSEMBLY FLIGHTS                |
+-----------------------------------------------------------------------------------------+
```

### 6.2 Empirical Results Under Emulated Network Conditions
Under Platform D ($1,500\text{ B}$ MTU limit, $15\text{ ms}$ latency, $3\text{ ms}$ jitter via `tc-netem`):
* **Baseline Handshake (Platform A):** $0.7801\text{ ms}$
* **Fragmented Handshake (Platform D):** **$47.2964\text{ ms}$**
* **Latency Inflation Penalty:** **$+5,962\%$**

### 6.3 Systems Analysis
Because `ServerHello` ($4,449\text{ B}$) and `ClientAuth` ($3,355\text{ B}$) each exceed the 1,500-byte boundary, TCP forces segmentation across 3 to 4 physical frames per flight. Under network jitter and packet reassembly queues, each packet flight experiences serialized TCP delays ($3 \times 15\text{ ms} \approx 45\text{ ms}$). This demonstrates that **in the post-quantum transition, network wire bloat and packet fragmentation constitute the primary operational bottleneck**, far outweighing CPU mathematical computation.

---

## 7. Security Test Matrix & Adversarial Verification

The automated security regression test suite (`tests/`) encompasses 24 exhaustive test vectors:

| Test Suite File | Security Objective | Attack Injected | Outcome | Status |
| :--- | :--- | :--- | :--- | :--- |
| `test_crypto_suite.py` | FIPS 203/204 Conformance | Exact byte length verification on keys & ciphertexts | Verified | **PASS** |
| `test_crypto_suite.py` | Encap/Decap Integrity | Shared secret match across peers | Verified | **PASS** |
| `test_crypto_suite.py` | Digital Signature Validation | Signature verification with valid & corrupted keys | Fails closed | **PASS** |
| `test_handshake.py` | Mutual Authentication | Handshake with pinned identities | Established | **PASS** |
| `test_handshake.py` | Peer Identity Enforcement | Handshake with unpinned server/client | Aborted | **PASS** |
| `test_tamper.py` | KEM Ciphertext Corruption | 1-bit flip in ML-KEM ciphertext | Implicit rejection | **PASS** |
| `test_tamper.py` | Signature Tamper Resistance | 1-bit flip in ML-DSA signature | Signature invalid | **PASS** |
| `test_tamper.py` | Nonce Tampering | Bit-flip in ClientHello nonce | Mismatch | **PASS** |
| `test_tamper.py` | AEAD Ciphertext Tampering | Bit-flip in symmetric chunk | Tag failure | **PASS** |
| `test_tamper.py` | AEAD Tag Tampering | Bit-flip in 16-byte GCM tag | Tag failure | **PASS** |
| `test_tamper.py` | Reflection Attack | Reflecting C2S chunk to S2C direction | AAD mismatch | **PASS** |
| `test_replay.py` | Monotonic Counter Invariant | Transmitting duplicate counter frame | Replay detected | **PASS** |
| `test_replay.py` | Frame Reordering | Injecting frame 2 before frame 1 | Gap detected | **PASS** |
| `test_transfer.py` | 1 KB Streaming Roundtrip | End-to-end payload streaming & EOF hash | Validated | **PASS** |
| `test_transfer.py` | 100 KB Streaming Roundtrip | Multi-chunk streaming & EOF hash | Validated | **PASS** |
| `test_transfer.py` | 10 MB Streaming Roundtrip | 160-chunk streaming & EOF hash | Validated | **PASS** |
| `test_mitm_attack.py` | Scenario A (Unauthenticated KEM) | Active proxy intercepts & substitutes key | Intercepted | **PASS** |
| `test_mitm_attack.py` | Scenario B (QSC Authenticated) | Active proxy intercepts & substitutes key | Signature abort | **PASS** |

---

## 8. Limitations, Assumptions, and Future Roadmap

### 8.1 Honest Engineering Limitations
1. **Python Memory Sanitization:** As detailed in §3.1, Python's runtime cannot guarantee immediate physical memory clearing of discarded cryptographic keys. Production deployments should wrap C implementations or compile directly in Rust/C.
2. **Wire Bloat in UDP/QUIC:** Under UDP-based protocols, post-quantum signatures ($3,309\text{ B}$) exceed standard initial congestion windows (typically 10 packets), requiring certificate compression or out-of-band trust bootstrapping as implemented in QSC.

### 8.2 Future Roadmap
1. **Hybrid Key Exchange Adoption:** Transition to X25519 + ML-KEM-768 hybrid mode (`optional/hybrid_kem.py`) to provide defense-in-depth against both quantum and unproven lattice cryptanalysis.
2. **Hardware Acceleration:** Integrate AVX-512 and ARM Neon vector assembly extensions to further accelerate polynomial NTT transformations.

---

## 9. Submission Artifact Verification Summary

* **Interactive Demonstration Notebook:** [`main.ipynb`](main.ipynb)
* **Core Source Modules:** [`src/problem.py`](src/problem.py), [`src/processors.py`](src/processors.py), [`src/routing.py`](src/routing.py), [`src/metrics.py`](src/metrics.py), [`src/visualization.py`](src/visualization.py)
* **Underlying Engine Modules:** [`src/crypto_suite.py`](src/crypto_suite.py), [`src/trust_store.py`](src/trust_store.py), [`src/protocol.py`](src/protocol.py), [`src/transport.py`](src/transport.py), [`src/peer.py`](src/peer.py), [`src/attacker.py`](src/attacker.py), [`src/cli.py`](src/cli.py), [`src/benchmark.py`](src/benchmark.py)
* **Hardware Profiles:** [`processors/processor_A.json`](processors/processor_A.json), [`processors/processor_B.json`](processors/processor_B.json)
* **Mathematical Asset Images:** [`assets/qff_phase1_latex_images/`](assets/qff_phase1_latex_images/)
* **Test Suites:** [`tests/test_crypto_suite.py`](tests/test_crypto_suite.py), [`tests/test_handshake.py`](tests/test_handshake.py), [`tests/test_tamper.py`](tests/test_tamper.py), [`tests/test_replay.py`](tests/test_replay.py), [`tests/test_transfer.py`](tests/test_transfer.py), [`tests/test_mitm_attack.py`](tests/test_mitm_attack.py) (24/24 PASS)
* **Generated Figures:**
  1. [`fig1_handshake_wire_framing.png`](results/figures/fig1_handshake_wire_framing.png)
  2. [`fig2_handshake_latency.png`](results/figures/fig2_handshake_latency.png)
  3. [`fig3_memory_footprint.png`](results/figures/fig3_memory_footprint.png)
  4. [`fig4_wire_overhead_pqc_vs_classical.png`](results/figures/fig4_wire_overhead_pqc_vs_classical.png)
  5. [`fig5_throughput_vs_payload.png`](results/figures/fig5_throughput_vs_payload.png)
  6. [`fig6_platform_d_tradeoff.png`](results/figures/fig6_platform_d_tradeoff.png)
* **Raw Benchmark Tables:** [`results/tables/handshake_comparison.csv`](results/tables/handshake_comparison.csv), [`results/tables/primitives_breakdown.csv`](results/tables/primitives_breakdown.csv), [`results/tables/throughput_comparison.csv`](results/tables/throughput_comparison.csv), [`results/tables/benchmark_summary.json`](results/tables/benchmark_summary.json)
