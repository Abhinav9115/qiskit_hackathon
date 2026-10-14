# Issue and Resolution Log

**Project:** PS-P1 - Quantum-Safe Secure Channel  
**Track:** Post-Quantum Cryptography, Qiskit Fall Fest 2026 Phase 1

## 1. Processor maps differed from the final Challenge Kit

- **Impact:** Required Processor A/B benchmark configuration was not compliant with the final kit.
- **Cause:** Early exploration selected a ring for A and a grid for B based on earlier topology-exploration guidance.
- **Resolution:** The final kit is authoritative for required maps. The required files now default to the 5-qubit chain and the exact 9-qubit sparse graph. Validation checks the undirected edge set as well as qubit count and connectivity. Ring/grid remain optional comparisons.

## 2. PQC fallback could be mistaken for standardized cryptography

- **Impact:** Historical PQC latency and MITM results cannot be used as ML-KEM/ML-DSA evidence.
- **Cause:** When `liboqs` was missing, the previous code generated synthetic, standard-sized objects using locally written code. Matching FIPS object lengths does not implement FIPS 203 or FIPS 204.
- **Resolution:** The simulator has been removed. The revised PQC backend requires the vetted `liboqs-python` binding and the requested algorithms, and reports an availability error instead of silently substituting another implementation. Historical fallback outputs are labeled unverified and require a real-library rerun.

## 3. Windows resource measurement portability

- **Impact:** The measurement harness previously depended on Unix-only resource APIs.
- **Resolution:** The harness uses conditional platform-specific measurement and affinity support, with `psutil` fallbacks where available. These measurements track resource use; they do not enforce a hard memory cap or emulate CPU clock speed.

## 4. Processor graph visualization after topology changes

- **Impact:** Static coordinates could make non-chain topology diagrams hard to read.
- **Resolution:** The visualization code derives positions from topology type and uses a graph layout fallback. Required Processor A/B diagrams must be regenerated from the final-kit chain and sparse graph.

## 5. MITM scenario count and evidence scope

- **Impact:** Earlier documentation described seven attack scenarios, but the table contains seven rows including the no-attacker control.
- **Resolution:** Describe the table as six attack cases plus a control. Results from the old PQC simulator are not cryptographic verification; rerun these cases with the vetted PQC backend before making PQC security claims.

## 6. Benchmark provenance and report synchronization

- **Impact:** The saved benchmark status is `quick`, repetition counts and report tables do not fully agree, and the PQC backend was not recorded in historical outputs.
- **Resolution:** Historical PQC measurements are marked unverified. The report identifies the quick-run and value mismatch. A final run should record backend provenance and regenerate the tables and figures together.
