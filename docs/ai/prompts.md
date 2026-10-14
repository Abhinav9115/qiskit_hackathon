# AI Assistance and Prompt Log

**Project:** PS-P1 — Quantum-Safe Secure Channel  
**Track:** Post-Quantum Cryptography  
**Event:** Qiskit Fall Fest 2026, Phase 1

## Disclosure and review process

AI tools were used as development assistants for requirement interpretation, design exploration, code drafting, debugging, benchmark analysis, and documentation. The team is responsible for reviewing the generated material, validating implementation behavior, and ensuring that submitted claims match reproducible evidence.

This log summarizes the main assistance sessions and decisions. Prompt descriptions are concise summaries rather than a complete verbatim transcript.

## Session 1 — Separate the PQC benchmark from processor qualification

**Prompt summary:** Interpret the guidance for PS-P1 and distinguish the computing platforms from the Processor A/B qualification models.

**AI contribution:** Organized the work into two distinct parts: (1) the secure-channel implementation and its benchmarks run as classical software; (2) Processor A/B are architecture artifacts for the broader qualification requirements. The PQC channel is not executed as a quantum circuit.

**Decision:** Keep the cryptographic benchmark on classical computing platforms. Do not describe the channel's ML-KEM or ML-DSA operations as quantum-circuit executions.

## Session 2 — Explore processor connectivity and routing cost

**Prompt summary:** Compare possible coupling maps for the 5-qubit and 9-qubit processor models and estimate how connectivity affects routing overhead.

**AI contribution:** Helped enumerate candidate graphs and calculate graph metrics and illustrative SWAP estimates. Early exploration included a 5-qubit ring and a 9-qubit grid.

**Final update:** The required Processor A chain and the exact 9-qubit Processor B sparse coupling map was specified. Those definitions take precedence for the required processor files and benchmark configuration. The ring and grid remain optional comparison only; they are not presented as the required A/B architectures.

**Decision:** Generate and validate `processor_A.json` and `processor_B.json`. Keep any alternative topology results clearly labeled as additional analysis.

## Session 3 — Design the secure-channel flow and threat model

**Prompt summary:** Structure a demonstration handshake using the specified cryptographic building blocks and explain the relevant on-path attacker scenarios.

**AI contribution:** Assisted with protocol-flow documentation, transcript binding, key derivation, authenticated records, streaming, and MITM scenario organization.

**Decision:** Use vetted library implementations for cryptographic primitives. Treat the channel and its benchmark as a systems demonstration; do not claim production readiness or formal security proof.

## Session 4 — Review PQC dependency behavior and benchmark validity

**Prompt summary:** Diagnose why PQC runs appeared to succeed on a machine where the native `liboqs` dependency was unavailable.

**AI contribution:** Identified that the prior automatic fallback generated standard-sized objects with locally implemented code. Object lengths alone do not implement or validate FIPS 203 ML-KEM or FIPS 204 ML-DSA.

**Decision:** Remove the fallback from the revised project. PQC operations now require the vetted `liboqs-python` binding and requested algorithms; otherwise the backend reports that it is unavailable. Previously saved PQC timings and attack outcomes from the fallback are retained only as historical, unverified artifacts and must not be presented as real PQC measurements.

## Session 5 — Improve reproducibility and submission clarity

**Prompt summary:** Review the repository and report against the final Challenge Kit, then make the required configuration and documentation consistent.

**AI contribution:** Compared the requirements with the project structure, identified stale topology and benchmark claims, and prepared this decision log and related documentation updates.

**Decision:** Keep the final-kit Processor A/B definitions, keep the PQC platforms classical, document Platform D as the custom Track 5 design, and state benchmark provenance and limitations plainly.

## Human review responsibility

AI-generated suggestions and code are not treated as authoritative specifications or validation results. Cryptographic, benchmark, and architecture claims should be retained in the submission only when the corresponding implementation and run evidence support them.
