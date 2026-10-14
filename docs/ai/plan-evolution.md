# Project Plan and Requirement Evolution

**Project:** PS-P1 - Quantum-Safe Secure Channel  
**Track:** Post-Quantum Cryptography, Qiskit Fall Fest 2026 Phase 1

## 1. Initial scope

The project began as a classical secure-channel demonstration comparing ECDH P-256, pure PQC, and a hybrid ECDH + ML-KEM-768 design. The planned channel uses ML-DSA authentication, HKDF-SHA256, AES-256-GCM records, and Platform D streaming trade-offs.

## 2. Clarifying the Track 5 workflow

Organizer guidance clarified that PQC cryptography runs on classical CPUs. The A/B/C/D labels in Track 5 refer to computing platforms, not quantum processors. Processor A/B architecture work remains a separate Phase 1 qualification artifact; the PQC handshake itself is not run as a quantum circuit.

## 3. Processor topology decision updated

Early exploration compared a 5-qubit ring and 9-qubit grid with the chain and sparse graph. The required Processor A chain and exact 9-qubit Processor B sparse map was specified, and says those topologies must be used for the required benchmark. Accordingly, the required JSON files and validator now target the final-kit maps. Ring/grid remain optional comparisons and are not described as the required processors.

## 4. PQC provider and evidence correction

An earlier implementation used a locally written simulator when native `liboqs` was unavailable. This was not ML-KEM/ML-DSA and could not support PQC security or timing claims. The simulator has been removed; the revised backend fails closed unless the vetted `liboqs-python` provider and requested algorithms are present. Historical PQC result files are marked unverified and must be replaced by a real-library run before those claims are used.

## 5. Current submission state

- The secure-channel protocol and benchmark harness remain in the repository.
- Required Processor A/B maps follow the final Challenge Kit; alternatives are supplemental.
- Platform D uses a record-size trade-off and needs a verified PQC rerun for final Track 5 performance claims.
- The saved quick-run outputs are historical; the final report must be regenerated from a single provenance-recorded run.
- AI-assisted design and coding are disclosed in `prompts.md`; the team remains responsible for review and validation.
