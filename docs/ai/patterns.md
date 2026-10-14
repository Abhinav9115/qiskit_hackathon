# Design and Implementation Patterns

**Project:** PS-P1 - Quantum-Safe Secure Channel  
**Track:** Post-Quantum Cryptography, Qiskit Fall Fest 2026 Phase 1

## 1. Hybrid key derivation

The hybrid design combines the ECDH P-256 and ML-KEM shared secrets as input to HKDF-SHA256. The combiner is project-specific and is not a standardized TLS codepoint or a formal security proof. The ML-KEM component must come from the vetted `liboqs-python` backend; the project fails closed if that implementation is unavailable.

## 2. Authenticated streaming records

Large payloads are read in bounded chunks and sent as independently authenticated AES-256-GCM records. Each record carries an authenticated sequence number and a final-record flag. The design aims to reduce application-level buffering for constrained targets. Historical memory figures are retained as unverified run artifacts until the benchmark is regenerated with consistent provenance.

## 3. Required-map graph analysis

Processor connectivity is represented as an undirected graph so qubit count, edges, degree, diameter, and shortest paths can be reported separately from compiler results. The required maps are the final-kit 5-qubit chain for Processor A and the specified 9-qubit sparse graph for Processor B. The ring and grid are optional candidates only. The pure-Python greedy routing output is an estimate, not a substitute for the Qiskit baseline of optimization level 1, SABRE layout/routing, and seed 42.

## 4. Cryptographic backend interface

The `Backend` interface separates handshake and record-layer logic from primitive providers:

- `ClassicalBackend` uses ECDH P-256 and ECDSA P-256 through `cryptography` for the quantum-vulnerable baseline.
- `OQSBackend` uses the vetted `liboqs-python` binding for ML-KEM and ML-DSA.
- `HybridBackend` combines the ECDH and ML-KEM KEM outputs and uses ML-DSA authentication.

If the vetted PQC provider or requested algorithms are missing, PQC operations report an availability error. No locally implemented or synthetic PQC primitive is used as a fallback.
