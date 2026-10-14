# Architecture Decision Records (ADRs)

Project: **PS-P1 - Quantum-Safe Secure Channel**  
Track: **Post-Quantum Cryptography Track, Qiskit Fall Fest 2026 (Phase 1)**

---

## ADR-001: Separation of Classical PQC Benchmarking and Quantum Processor Modeling

### Status
Accepted & Aligned with Admin Guidance.

### Context
Phase 1 challenge materials initially created ambiguity regarding whether the A/B/C/D labels in Track 5 referred to quantum processor architectures or computing environments. Section 10 of the Challenge Kit and organizer communications explicitly clarified:
> *"IMPORTANT: PQC DOES NOT USE QUANTUM PROCESSORS. For this track, the A/B/C/D labels refer to target computing platforms, not quantum processor models."*

### Decision
1. The **primary secure channel benchmark** (handshake, key agreement, encryption, memory, MITM defenses) executes on classical microprocessors. The current project JSON contains local A/B/C resource settings that must be checked against the organizer's released platform specification; Platform D is the custom Track 5 target.
2. **Processors A (5-qubit) and B (9-qubit)** are maintained as universal Phase 1 qualification hardware models, conceptually mapped to the quantum threat model (demonstrating why AES-256 and PQC are required against Grover's and Shor's algorithms, and demonstrating compiler routing overhead).

### Consequences
- Clean scientific fidelity: No false claims that PQC runs on quantum circuits.
- Fulfills both Track 5 deliverables and the universal Phase 1 qualification requirements.

---

## ADR-002: Selection of Hybrid Key Encapsulation (ECDH P-256 + ML-KEM-768) and ML-DSA-65 Authentication

### Status
Accepted.

### Context
NIST standardized FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). However, real-world deployment guidelines (IETF TLS 1.3 drafts, NIST SP 800-227, Google, Cloudflare) recommend a hybrid key exchange mechanism ($K = \text{HKDF}(SS_{\text{classical}} \parallel SS_{\text{PQC}})$) to guard against potential cryptanalytic breakthroughs in early lattice cryptography.

### Decision
1. Default to NIST Security Category 3 primitives: **ML-KEM-768** for post-quantum key encapsulation and **ML-DSA-65** for post-quantum signatures.
2. Implement **`hybrid-L3`**: Concatenate 65-byte uncompressed P-256 public key + 1184-byte ML-KEM-768 public key on the wire; concatenate both 32-byte shared secrets and derive traffic keys via HKDF-SHA256 with full transcript hashing.

### Consequences
- Quantum resistance against Shor's algorithm for retroactive decryption.
- Fallback classical security if lattice mathematics encounters unanticipated algebraic vulnerabilities.
- Handshake size on wire increases from ~528 bytes (classical) to ~9,284 bytes (hybrid), a 17.6x increase.

---

## ADR-003: Processor A Required Map — 5-Qubit Chain

### Status
Accepted — final Challenge Kit configuration.

### Context
An earlier organizer message encouraged topology exploration. The final Challenge Kit subsequently fixed the required Processor A benchmark map as the 5-qubit nearest-neighbor chain.

### Decision
Use the required **5-qubit chain** with edges (0,1), (1,2), (2,3), and (3,4) in `processor_A.json`. Keep the ring and other topologies only as separately labeled optional comparisons.

### Consequences
The required chain has diameter 4 and average shortest path 2.0. Ring metrics are optional candidate-analysis results and must not be reported as the required Processor A benchmark.

---

## ADR-004: Processor B Required Map — 9-Qubit Sparse Graph

### Status
Accepted — final Challenge Kit configuration.

### Context
The final Challenge Kit fixes Processor B at 9 qubits and specifies its heavy-hex-inspired sparse coupling map. That map is authoritative for the required benchmark.

### Decision
Use the required edges (0,1), (1,2), (2,3), (2,4), (4,5), (5,6), (4,7), and (7,8) in `processor_B.json`. Keep the 3×3 grid and other topologies only as separately labeled optional comparisons.

### Consequences
The required sparse graph has diameter 5 and average shortest path 2.611. Grid metrics are candidate-analysis results and do not replace the required Processor B benchmark map.

---

## ADR-005: Platform D Design — 64 KiB AES-GCM Record Chunking Candidate

### Status
Accepted.

### Context
The Challenge Kit requires a custom Platform D that exposes a resource/performance trade-off. The project currently uses a local 1-core/8-MB configuration; confirm that budget against the organizer's platform specification.

### Decision
Platform D keeps the project's local resource budget and uses a **64 KiB AES-256-GCM record chunk**. In the checked-in quick ECDH sweep (3 repetitions), 64 KiB is the smallest size reaching 90% of the best in-budget throughput. Treat this as preliminary until rerun with fuller sampling and the organizer-confirmed target profile.

### Consequences
- In the checked-in quick sweep, Platform C's 16 KiB record setting measured 394.2 MB/s and about 113 KB Python-heap peak; the 64 KiB candidate measured 558.4 MB/s and about 401 KB.
- These are preliminary ECDH record-layer results from 3 repetitions, not PQC measurements or hard memory-cap enforcement.

---

## ADR-006: Fail-Closed PQC Backend

### Status
Accepted.

### Context
The earlier implementation silently substituted a locally written simulator when the vetted `liboqs` backend was unavailable. Standard-sized objects do not implement ML-KEM or ML-DSA and cannot support cryptographic or PQC performance claims.

### Decision
Remove the simulator. `OQSBackend` must use the vetted `liboqs-python` binding and fail closed with a clear availability error if the library or requested algorithms are missing.

### Consequences
- PQC correctness and timing claims require an actual vetted-library run.
- Old fallback-produced PQC timings and attack rows are historical, unverified artifacts and are excluded from conclusions until rerun.
