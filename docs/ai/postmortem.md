# Project Retrospective

**Project:** PS-P1 - Quantum-Safe Secure Channel  
**Track:** Post-Quantum Cryptography, Qiskit Fall Fest 2026 Phase 1

## What the project established

- The Track 5 secure-channel benchmark belongs on classical computing platforms; quantum circuits do not execute ML-KEM or ML-DSA.
- A streamed AES-GCM record layer, handshake flow, benchmark harness, and MITM scenarios are present in the codebase.
- The Processor A/B maps are now separated from the PQC platform benchmark, and optional topology exploration is labeled separately.
- A record-size sweep provides a concrete design approach for Platform D, subject to confirming the organizer's numeric A/B/C platform configuration.

## What needs further evidence

- The saved notebook shows that the vetted PQC library was unavailable during the historical PQC run. A locally implemented simulator was used at that time; its outputs are not valid ML-KEM/ML-DSA security or performance results. The simulator has been removed and those artifacts are marked unverified.
- The saved benchmark status is a quick run, and the report's older measurement tables do not fully match the checked-in CSVs. Generate one new, provenance-recorded benchmark run and regenerate all dependent tables and figures.
- The optional Qiskit A/B experiment was not run in this snapshot. Greedy routing counts are illustrative estimates, not transpiler results.
- The numeric resource budgets for Platforms A/B/C should be confirmed against the organizer's released platform specification before finalizing the comparison.

## Lessons and next actions

1. Fail closed when a vetted cryptographic dependency is missing; never let a compatibility fallback appear as a standardized primitive.
2. Treat the final Challenge Kit as authoritative when earlier guidance is superseded, and preserve earlier topology ideas only as optional comparisons.
3. Record the backend, environment, repetition counts, payload source, and run mode with every result.
4. Regenerate the report, tables, and figures together so all claims map to one reproducible run.
5. Keep limitations visible and distinguish protocol-size estimates, graph-derived metrics, routing estimates, and measured execution results.
