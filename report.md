# PS-P1 Report - Quantum-Safe Secure Channel

Qiskit Fall Fest 2026, Phase 1, Post-Quantum Cryptography track.

## 0. Status at a glance

| Item | Status |
|---|---|
| Secure channel (mutual authentication, KEM key establishment, HKDF-SHA256, AES-256-GCM records) | Protocol code is present. The saved PQC run used a non-standard fallback and is not valid cryptographic verification. |
| ML-KEM-768, ML-DSA-65 and hybrid ECDH+ML-KEM-768 | Revised backend requires vetted `liboqs`; PQC performance and security results must be rerun with that backend. |
| Man-in-the-middle demonstration | Six attack cases plus a no-attacker control are defined. Historical PQC outcomes used the fallback and are unverified. |
| Platform A/B/C/D benchmark harness | Harness and historical data are present. The saved status is a quick run; PQC measurements are unverified. |
| Laptop vs edge comparison | Historical comparison is retained for audit, not as a validated real-PQC result. |
| Processors A and B (qualification) | Required files use the final-kit 5-qubit chain and 9-qubit sparse graph. Ring/grid analyses are optional comparisons. |
| AI collaboration & decision records | Prompt log and decision records are documented under `docs/ai/`; the final kit supersedes earlier topology guidance. |

## 1. Threat model and security goals

* **Shor's algorithm** breaks RSA and elliptic-curve (ECDH/ECDSA) cryptography on a large fault-tolerant quantum computer.
  An attacker can record today's ECDH handshakes and decrypt them later (*harvest now, decrypt later*).
* **Grover's algorithm** gives only a quadratic speed-up against symmetric keys, so AES-256 keeps roughly 128-bit
  quantum security; this is why records use AES-256-GCM.
* **Post-quantum primitives.** ML-KEM (FIPS 203) replaces key agreement and ML-DSA (FIPS 204) replaces signatures.
  Both rest on lattice problems and run on ordinary CPUs; they do not use quantum hardware.
* **Hybrid design goal.** The hybrid set combines ECDH P-256 and ML-KEM-768 shared secrets as HKDF input. This is a project protocol design choice, not a standardized TLS codepoint or a security proof.

**Man-in-the-middle (MITM).** An on-path attacker can forward, alter, replay or drop messages. Against an *unauthenticated*
key exchange it can run one exchange with each side and read everything. Here:

1. Both ends hold the other's pinned long-term ML-DSA public key (the trust anchor, distributed out of band).
2. Each side signs a transcript hash that covers the KEM public key, ciphertext, nonces and algorithm names, so swapping
   a KEM key or ciphertext invalidates a signature (also stops algorithm downgrade).
3. Records are AES-256-GCM with the sequence number and an end-of-stream flag as associated data, so bit flips, replays,
   reordering and truncation fail the tag check.

Not defended: a stolen signing key, a wrong pinned key, traffic analysis, denial of service.

## 2. Design

* **Handshake** (see `results/figures/handshake_flow.png`): ClientHello (nonce, ephemeral KEM public key, algorithm names, signature),
  ServerHello (nonce, KEM ciphertext, signature over the transcript hash), then a Finished record each way as key confirmation.
* **Keys:** `HKDF-SHA256(ikm = KEM secret, salt = nonce_c || nonce_s, info = label || transcript hash)` -> 64 bytes,
  split into one AES-256 key per direction. Nonces and keys come from the OS CSPRNG; seed 42 is used only for stand-in payload bytes.
* **No homemade cryptography:** ML-KEM/ML-DSA from liboqs, HKDF/AES-GCM/ECDH/ECDSA from `cryptography`.
* **Parameter sets** (exact, as the kit requires):

| key | KEM | signature | NIST category |
|---|---|---|---|
| `classical-p256` | ECDH P-256 | ECDSA P-256 | quantum-vulnerable baseline |
| `pqc-L3` (default) | ML-KEM-768 | ML-DSA-65 | KEM 3 / SIG 3 |
| `hybrid-L3` | ECDH P-256 + ML-KEM-768 | ML-DSA-65 | KEM 3 (hybrid) / SIG 3 |
| `pqc-L1`, `pqc-L5` | ML-KEM-512 / 1024 | ML-DSA-44 / 87 | size trade-off table |

The hybrid combiner (concatenate both secrets, then HKDF with the transcript) follows the same idea as hybrid TLS key exchange but is
**not** a standardized codepoint; it is a project design choice.

## 3. Method

* Target platforms are **classical CPU/memory budgets**, not quantum processors (Challenge Kit, section 10).
  The final kit identifies A/B/C as fixed target platforms and requires a custom D. The supplied PS-P1 entry does not state numeric CPU/RAM budgets; the values below are the project's local configuration and must be checked against the released platform specification before being called official:

| platform | role | CPU cores | memory budget (MB) | record size | status |
|---|---|---|---|---|---|
| A | normal laptop environment (resource-rich reference) | all | none | single record | Project setting - verify against released spec |
| B | constrained mid-range (small VM / gateway style) | 1 | 128 | 1 MiB | Project setting - verify against released spec |
| C | edge device (limited CPU and memory) | 1 | 8 | 16 KiB | Project setting - verify against released spec |
| D | embedded gateway with a tuned record size | 1 | 8 | 64 KiB | Custom project design - preliminary 3-repetition sweep |

* Each (platform x parameter set x payload) cell is intended to run in a fresh subprocess pinned to the configured core budget; both endpoints run in that process over a local socket pair. The checked-in status file marks the saved run as `quick`; its recorded repetition counts are not the 100/50/10 counts previously described. Treat the tables below as historical until a single verified run regenerates the report and artifacts.
* **Handshake time:** wall time from client start until both sides have verified the Finished messages.
* **Bytes exchanged:** every byte the client sends and receives, including 4-byte frame headers.
* **RAM:** Python-heap peak (`tracemalloc`) while moving the payload, plus process RSS growth. The heap peak is the primary number because
  RSS growth hides small working sets when the allocator reuses pages.
* **Code size:** logical (non-blank, non-comment) lines per module; regenerated after the backend and topology updates: `process.py` has 645 lines and `src/` totals 1,569 lines (`results/tables/code_size.csv`).
* Payloads: organizer files in `data/raw/` are used if present; otherwise deterministic stand-ins of 1 KB, 100 KB and 10 MB (seed 42).

## 4. Results

### Evidence status

The checked-in benchmark status is a quick run, and the saved notebook output records that the native `liboqs` dependency was unavailable. The earlier code silently used a locally implemented, standard-sized simulator in that case. Those historical PQC handshake timings, benchmark rows, and PQC MITM outcomes are not valid ML-KEM/ML-DSA measurements or security verification. The revised code now requires the vetted backend and fails closed. Re-run the PQC suite with `liboqs` available, then regenerate the result tables, figures, and report before treating PQC performance results as final. Existing numerical PQC artifacts are retained for audit, not as evidence.

### 4.1 Predicted sizes (from the standards - NOT measured)

Sizes come from FIPS 203/204 and SEC1; the handshake total is computed with the exact wire format in `process.py`.
The formula predicts 527 bytes for the ECDH handshake. DER-encoded ECDSA signatures can vary by a byte or two. The PQC totals below are protocol-size estimates based on standardized object lengths, not measurements of an executed PQC library.

| parameter set | KEM pk (B) | KEM ct (B) | signature (B) | handshake bytes (predicted) | vs ECDH |
|---|---|---|---|---|---|
| classical-p256 | 65 | 65 | 71 | 527 | 1.0x |
| pqc-L1 | 800 | 768 | 2420 | 6661 | 12.6x |
| pqc-L3 | 1184 | 1088 | 3309 | 9143 | 17.3x |
| pqc-L5 | 1568 | 1568 | 4627 | 12644 | 24.0x |
| hybrid-L3 | 1249 | 1153 | 3309 | 9284 | 17.6x |

The cost of PQC in this protocol is overwhelmingly **bytes**, driven by the ML-DSA signatures (two of them) and the larger KEM objects.

### 4.2 Measured baseline: ECDH P-256 / ECDSA P-256 on Platforms A-D

Historical classical-backend measurements in the authoring sandbox (1 CPU core, loopback, stand-in payloads). The values below are not synchronized with the checked-in quick-run CSV and should be regenerated before final submission.

| platform | payload | chunk | handshake ms (median) | handshake ms (p95) | transfer ms (median) | MB/s | heap peak KB | handshake bytes | record overhead % | payload OK |
|---|---|---|---|---|---|---|---|---|---|---|
| A | 1KB | single record | 1.06 | 1.16 | 0.06 | 18 | 12 | 528 | 2.051 | True |
| A | 100KB | single record | 1.10 | 1.31 | 0.18 | 570 | 407 | 528 | 0.021 | True |
| A | 10MB | single record | 5.87 | 6.86 | 25.34 | 414 | 30727 | 526 | 0.000 | True |
| B | 1KB | 1 MiB | 1.46 | 1.87 | 0.07 | 16 | 1036 | 527 | 2.051 | True |
| B | 100KB | 1 MiB | 1.15 | 1.76 | 0.19 | 540 | 1135 | 527 | 0.021 | True |
| B | 10MB | 1 MiB | 1.22 | 2.04 | 18.31 | 573 | 6156 | 525 | 0.002 | True |
| C | 1KB | 16 KiB | 1.06 | 1.17 | 0.06 | 18 | 28 | 527 | 2.051 | True |
| C | 100KB | 16 KiB | 1.17 | 1.29 | 0.24 | 421 | 107 | 525 | 0.144 | True |
| C | 10MB | 16 KiB | 1.21 | 1.46 | 22.28 | 471 | 108 | 529 | 0.128 | True |
| D | 1KB | 64 KiB | 1.05 | 1.15 | 0.06 | 18 | 76 | 529 | 2.051 | True |
| D | 100KB | 64 KiB | 1.13 | 1.21 | 0.20 | 510 | 207 | 527 | 0.041 | True |
| D | 10MB | 64 KiB | 1.24 | 1.29 | 14.65 | 716 | 396 | 526 | 0.032 | True |

Reading it:
* **Memory is governed by the record-size policy.** One record for a 10 MB payload needs about 30.0 MB of Python heap
  (Platform A); 16 KiB records need about 108 KB (Platform C) - a factor of roughly 285.
  A single record would exceed Platform C's 8 MB budget, which is the practical reason an edge device must stream.
* **Handshake bytes are the same on every platform** apart from +/-2 bytes of ECDSA signature length (the platform changes the budget, not the protocol).
* Handshake times on the 1 KB and 100 KB rows are within noise of each other across A-D, because the sandbox has one core and no way to slow the clock (see limitations). Platform A's 10 MB row shows a higher median (5.87 ms) and a heavy tail (p95 6.9 ms); the cause was not investigated.

### 4.3 PQC timing comparison — pending verified run

The previously published laptop/edge timing comparison has been removed from the claim set because its PQC and hybrid rows were produced through the non-standard fallback described above. The byte-size estimates in Section 4.1 remain estimates. No real-liboqs PQC latency, memory, or hybrid comparison is claimed until the revised benchmark is run with the vetted library and its backend provenance is recorded.

### 4.4 Man-in-the-middle scenarios (historical classical-backend run)

The table contains six attack cases plus a no-attacker control. The historical classical-backend outcomes are separate from PQC verification. Earlier PQC rows used the simulator and are not evidence that ML-KEM/ML-DSA protects the channel.

| scenario | expected defence | attack detected | result |
|---|---|---|---|
| no attacker (control) | handshake + transfer succeed | False | PASS |
| attacker swaps client KEM key and re-signs | server rejects client signature | True | PASS |
| attacker corrupts server KEM ciphertext | client rejects server signature | True | PASS |
| attacker forges ServerHello with own key | client rejects server signature | True | PASS |
| attacker flips a bit in an encrypted record | AES-GCM tag check fails | True | PASS |
| attacker replays an encrypted record | AES-GCM tag check fails (sequence number) | True | PASS |
| attacker truncates the stream | stream ends without authenticated final record | True | PASS |

## 5. Platform D (custom)

**Goal:** a custom edge-class target that uses its configured memory budget deliberately instead of simply adding resources. The 1-core/8-MB values are the project's local settings and must be reconciled with the organizer's platform specification.
**Knob:** the AES-GCM record size. **Rule:** among record sizes whose Python-heap peak fits the configured budget, choose the smallest that reaches at least 90% of the best in-budget throughput. The checked-in sweep is a quick ECDH-baseline run with 3 repetitions per size; it is preliminary, not a final PQC benchmark:

| record size | records | MB/s | heap peak KB | overhead % |
|---|---|---|---|---|
| 1 KiB | 10241 | 48.4 | 23 | 2.051 |
| 4 KiB | 2561 | 156.9 | 41 | 0.513 |
| 16 KiB | 641 | 394.2 | 113 | 0.128 |
| 64 KiB | 161 | 558.4 | 401 | 0.032 |
| 256 KiB | 41 | 377.5 | 1553 | 0.008 |
| 1 MiB | 11 | 400.8 | 6161 | 0.002 |
| single record | 2 | 495.4 | 20490 | 0.000 |

The checked-in quick sweep selects **64 KiB**: it is the smallest setting reaching at least 90% of the best in-budget throughput (558.4 MB/s at 64 KiB). At 64 KiB, measured Python-heap peak was about 401 KB and record overhead was 0.032%. The 16-KiB setting measured 394.2 MB/s in this same quick run.

**Trade-off:** larger records reduce per-record overhead but increase the working set and the amount retransmitted after record loss. The 3-repetition quick sweep is not enough to establish a stable performance ranking. Re-run the sweep with the organizer-confirmed platform configuration and fuller sampling before presenting the choice as final. Platform D remains a custom classical target; it does not run PQC on a quantum processor.

## 6. Processor A/B architecture qualification artifacts

The PQC channel benchmark runs on classical target platforms. Processor A and B are separate Phase 1 architecture artifacts. The final Challenge Kit defines the required maps, so those maps are used in the required JSON files and validation; alternative graphs are supplemental comparisons only.

### 6.1 Required architectures from the final Challenge Kit

| Processor | Qubits | Required topology | Undirected coupling edges |
|---|---:|---|---|
| A | 5 | Nearest-neighbor chain | (0,1), (1,2), (2,3), (3,4) |
| B | 9 | Heavy-hex-inspired sparse graph | (0,1), (1,2), (2,3), (2,4), (4,5), (5,6), (4,7), (7,8) |

The exact maps are defined in `src/routing.py` and serialized in `processors/processor_A.json` and `processors/processor_B.json`. The validator checks qubit count and the exact undirected edge set. Processor C is a 13-qubit study/reference topology only; this project does not claim a required C implementation or execution.

### 6.2 Graph metrics and optional topology exploration

The required chain and sparse graph have graph-derived metrics of 4/8 edges, diameters 4/5, and average shortest paths 2.000/2.611 for A/B respectively. These are topology metrics, not Qiskit execution results. The previously explored 5-qubit ring and 9-qubit grid are retained as optional candidate comparisons. Their lower routing estimates do not replace the final-kit A/B benchmark maps.

### 6.3 Routing evidence status

The pure-Python routing table uses an identity initial layout and greedy shortest-path SWAP insertion; it is an illustrative estimate. The final-kit Qiskit baseline is optimization level 1 with SABRE layout/routing and seed 42. The optional Qiskit noisy A/B experiment has not been run in this project snapshot, so no transpiled-circuit or noisy-execution result is claimed here. For PS-P1, these quantum architecture artifacts remain separate from the classical PQC performance benchmark.

## 7. Limitations (read before trusting any number)

1. **PQC backend provenance**: The saved notebook indicates that native `liboqs` was unavailable and the prior implementation used a homemade simulator. That simulator has been removed. Historical PQC latency and attack results are unverified and must not be described as ML-KEM/ML-DSA measurements. The revised code fails closed without the vetted backend.
2. **Platform emulation**: The harness pins CPU affinity where supported and tracks working-set/heap measurements; it does not impose a hard memory cap or emulate CPU clock speeds. The numeric A/B/C settings in this project must be checked against the organizer's released platform specification, which is not numerically stated in the supplied PS-P1 section of the final kit.
3. The authoring sandbox had **one CPU core**, so Platform A (all cores) and B/C/D (one core) were identical in compute.
4. Both endpoints share one process, so memory covers sender and receiver together; timings are loopback compute with no network latency.
5. `tracemalloc` sees Python-heap allocations only; native liboqs buffers are small but uncounted. RSS growth is reported too but is insensitive to small working sets.
6. Payloads are stand-ins unless the organizer files are placed in `data/raw/`.
7. Not production code: no key storage or rotation, no session resumption, no formal verification. liboqs timings include the Python wrapper overhead.
8. Qiskit A/B experiment is untested (see section 6).

## 8. Reproduce

```
pip install -r requirements.txt
python -m src.process selftest --param-set hybrid-L3
python -m src.metrics all            # add --quick for a smoke run
python -m src.visualization
```
