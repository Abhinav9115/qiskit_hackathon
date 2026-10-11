# AI Usage and Methodology Disclosure
**Project:** Quantum-Safe Channel (QSC v1.0)  
**Hackathon Event:** Qiskit Fall Fest 2026 (Track 5: Post-Quantum Cryptography, Problem Statement P1)

---

## 1. Compliance Statement & Attribution

In accordance with the Qiskit Fall Fest 2026 rules and ethical academic research standards, this document transparently records the utilization of AI assistance throughout the lifecycle of this project.

## 2. Tools & Models Utilized
* **Model:** Gemini 3.8 Flash (High Agentic Reasoning Mode) via Google Antigravity IDE.
* **Role:** Architectural co-designer, test suite scaffolding, benchmark data collector, and formal mathematical documentation generator.

## 3. Human Oversight & Engineering Verification
* **Zero Hand-Rolled Cryptography:** All cryptographic primitives strictly defer to standardized implementations (`liboqs-python` for NIST FIPS 203 / 204 primitives, and Python `cryptography` for HKDF-SHA256 and AES-256-GCM).
* **Wire Size Verification:** Assertions on exact public key, ciphertext, and signature byte sizes were verified against NIST FIPS 203 and 204 published standards.
* **Empirical Measurements:** No benchmark values, latencies, memory footprints, or test results were hallucinated or fabricated. All numbers reported in `report.md` and `results/` represent empirical execution traces on classical hardware.
* **Security Testing:** Adversarial tests (tamper, replay, monotonic counter gaps, unpinned identity rejection, and MitM proxy interception) were actively verified through automated tests (`pytest`) with 100% pass rates.
