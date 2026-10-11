# QSC Threat Model & Security Architecture
**System:** Quantum-Safe Channel (QSC v1.0)  
**Track:** Qiskit Fall Fest 2026 — Track 5, Problem Statement P1

---

## 1. Adversary Model & Capabilities

The security of QSC is analyzed under two distinct adversarial tiers:

### 1.1 Classical Active Adversary (Dolev-Yao Model)
The adversary $\mathcal{A}_{\text{classical}}$ controls the physical network interface between client and server with full capabilities:
* **Eavesdropping:** Read all packets transmitted across loopback, LAN, or WAN.
* **Injection & Modification:** Inject fabricated packets, flip arbitrary bits in transit, and truncate streams.
* **Replay & Reordering:** Record past valid handshake flights or symmetric frames and retransmit them at arbitrary times or in arbitrary order.
* **Identity Spoofing & MitM:** Impersonate either peer, advertise altered public keys, or attempt to split the key exchange via man-in-the-middle proxies.

### 1.2 Quantum Adversary (Harvest-Now, Decrypt-Later — HNDL)
The adversary $\mathcal{A}_{\text{quantum}}$ captures and stores all encrypted wire communications indefinitely.
* **CRQC Availability:** When a Cryptanalytically Relevant Quantum Computer (CRQC) emerges, $\mathcal{A}_{\text{quantum}}$ executes Shor's algorithm (polynomial time factorisation and discrete logarithms).
* **Target:** Classical key exchanges (ECDH P-256, X25519, RSA) are immediately broken, exposing retroactive plaintexts.
* **QSC Resistance:** Ephemeral key encapsulation is protected by NIST FIPS 203 (ML-KEM-768), which is rooted in the hardness of Module Learning With Errors (M-LWE). Quantum lattice reduction algorithms (e.g., Block-Korkine-Zolotarev / BKZ sieving) require $\ge 2^{192}$ quantum operations, ensuring confidentiality holds against future CRQC cryptanalysis.

---

## 2. Security Objectives & Guarantees

| Security Property | Architectural Mechanism | Adversarial Defense |
| :--- | :--- | :--- |
| **Confidentiality against CRQC** | Ephemeral `ML-KEM-768` | Prevents Harvest-Now-Decrypt-Later decryption. |
| **Mutual Authentication** | Long-term `ML-DSA-65` signatures | Disallows peer impersonation and unpinned identity acceptance. |
| **MitM Immunity** | Cryptographic Transcript Binding ($\text{Transcript}_1, \text{Transcript}_2$) | Binding prevents active key substitution; signers attest to exact session context. |
| **Integrity & Authenticity** | AES-256-GCM AEAD (128-bit authentication tag) | Fails closed on any modified ciphertext byte. |
| **Replay & Reordering Defense** | Strictly monotonic 64-bit counter + XOR IV derivation + AAD binding | Replayed, duplicate, or out-of-order chunks are rejected instantly. |
| **End-to-End Plaintext Hash** | SHA-256 running digest in authenticated EOF chunk | Detects stream truncation or silent data truncation. |
| **Session Independence** | Ephemeral nonces $N_c, N_s$ + RFC 5869 HKDF extraction | Compromise of one session leaks zero state of past/future sessions. |

---

## 3. Threat Mitigation Proofs & Mechanics

### 3.1 Ephemeral Man-in-the-Middle (MitM) Mitigation
* **Vulnerability in Unauthenticated KEM:** In a naive KEM protocol, an adversary $\mathcal{M}$ intercepts `ClientHello`, swaps $PK_{KEM\_eph}$ with their own $PK_{M}$, returns an encapsulation to the client, and independently encaps-decaps with the server.
* **QSC Defense:**
  $$\text{Transcript}_1 = \text{SHA-256}(\text{"QSC-v1-SERVER-BIND"} \,\|\, \text{Wire}(ClientHello) \,\|\, CT_{KEM} \,\|\, N_s \,\|\, \text{ID}_{server})$$
  $$\text{Sig}_{server} = \text{Sign}_{SK_{DSA\_server}}(\text{Transcript}_1)$$
  Because $ClientHello$ contains the client's $PK_{KEM\_eph}$, any substitution by $\mathcal{M}$ alters $\text{Transcript}_1$. The server's valid signature $\text{Sig}_{server}$ cannot be forged by $\mathcal{M}$ because $\mathcal{M}$ does not possess the server's pinned long-term $SK_{DSA\_server}$. The client verifies $\text{Sig}_{server}$ using the pinned public key, aborting the connection before symmetric keys are derived.

### 3.2 Transcript Substitution & Cross-Protocol Attacks
* Domain-separated tags (`"QSC-v1-SERVER-BIND"`, `"QSC-v1-CLIENT-BIND"`, `"QSC-v1-AES-256-GCM-C2S"`, etc.) prevent cross-ciphersuite confusion and reflection attacks.
* $Transcript_2$ incorporates $Transcript_1$ and $ServerHello$, guaranteeing both parties mutually agree on the exact byte-for-byte history.

### 3.3 Framing & Replay Defense
* Nonces are formed as:
  $$IV_{\text{chunk}} = IV_{\text{base}} \oplus \text{ZeroPad}_{12}(\text{Counter})$$
  Because the 64-bit counter increments monotonically from 1, no two chunks ever share the same IV with a given key $K$, guaranteeing AES-GCM nonce uniqueness.
* The Associated Authenticated Data (AAD) binds:
  $$AAD = \text{SessionID} \parallel \text{Direction} \parallel \text{Counter} \parallel \text{FinalFlag}$$
  If an adversary attempts to reflect a Client-to-Server chunk back to the client, the `Direction` byte mismatch (`0x01` vs `0x02`) fails GCM authentication immediately.
* Any counter value $\le$ the last observed counter is dropped as a replay. Any counter $> \text{expected}$ is dropped as a sequence gap.

---

## 4. Scope Limitations & Non-Goals

1. **Endpoint Compromise:** If an adversary obtains root access to a host or reads raw memory containing unpinned keys or active process memory, cryptographic channel guarantees do not apply.
2. **Denial-of-Service (DoS):** An adversary dropping network packets or severing TCP connections will disrupt transmission availability; QSC guarantees confidentiality and integrity, failing closed safely.
3. **Physical Side-Channel Attacks:** While the underlying `liboqs` C implementations aim for constant-time execution in core polynomial operations, Python interpreters do not provide constant-time guarantees at the language runtime layer.
