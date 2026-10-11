# QSC (Quantum-Safe Channel) Specification — v1.0
**Target Track:** Qiskit Fall Fest 2026 (Track 5: Post-Quantum Cryptography, Problem Statement P1)  
**Standard Compliance:** NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA), RFC 5869 (HKDF), NIST SP 800-38D (AES-GCM)

---

## 1. Cryptographic Primitives & Byte Assertions

| Primitive Role | Algorithm Specification | FIPS / RFC Reference | Wire Size (Bytes) | Security Level |
| :--- | :--- | :--- | :--- | :--- |
| **Identity / Auth** | `ML-DSA-65` (Dilithium3 legacy) | NIST FIPS 204 | $PK$: 1,952 B<br>$Sig$: 3,309 B | NIST Level 3 (AES-192 equiv.) |
| **Key Encapsulation** | `ML-KEM-768` (Kyber768 legacy) | NIST FIPS 203 | $PK$: 1,184 B<br>$CT$: 1,088 B<br>$SS$: 32 B | NIST Level 3 (AES-192 equiv.) |
| **Key Derivation** | HKDF-SHA256 | RFC 5869 | Digest: 32 B | 256-bit collision res. |
| **Transcript Hash** | SHA-256 | FIPS 180-4 | 32 B output | 256-bit |
| **Bulk AEAD** | AES-256-GCM | NIST SP 800-38D | Key: 32 B, IV: 12 B, Tag: 16 B | 256-bit confidential / 128-bit auth |

---

## 2. Trust Bootstrap & Out-of-Band Key Pinning

1. **Long-Term Identity:** Peers generate an ML-DSA-65 keypair $(SK_{DSA}, PK_{DSA})$.
2. **Fingerprint:** Fingerprint is defined as:
   $$\text{FP}(PK) = \text{SHA-256}(PK) \quad (\text{represented as 64 lowercase hex characters})$$
3. **Local Trust Store:** Identities are stored in `~/.qsc/trust_store.json` (or application data directory). Handshakes **strictly fail closed** if an unpinned peer identity is presented over the wire.

---

## 3. Handshake State Machine (1-RTT Mutually Authenticated)

```
       Client                                                        Server
       ======                                                        ======
[Generate Ephemeral ML-KEM-768]
       |
       |  ----------------- 1. ClientHello -------------------->  [Verify Version & Suite]
       |     {version, suite_id, N_c, PK_kem_eph, timestamp}        [Generate N_s]
       |                                                            [SS, CT_kem = Encaps(PK_kem_eph)]
       |                                                            [Compute Transcript_1]
       |                                                            [Sig_server = Sign(SK_dsa_server, Transcript_1)]
       |                                                            [Derive PRK = HKDF-Extract(N_c || N_s, SS)]
       |  <---------------- 2. ServerHello ---------------------    |
       |     {CT_kem, N_s, ID_server, Sig_server, timestamp}        |
[Verify Server Identity Pin]                                        |
[Compute Transcript_1]                                              |
[Verify Sig_server using pinned PK_dsa_server]                      |
[SS = Decaps(SK_kem_eph, CT_kem)]                                   |
[Derive PRK = HKDF-Extract(N_c || N_s, SS)]                         |
[Derive Session Keys: K_c2s, K_s2c, IV_c2s, IV_s2c, MAC_confirm]     |
[Compute Transcript_2]                                              |
[Sig_client = Sign(SK_dsa_client, Transcript_2)]                    |
       |                                                            |
       |  ----------------- 3. ClientAuth --------------------->  [Verify Client Identity Pin]
       |     {ID_client, Sig_client, MAC_confirm}                   [Compute Transcript_2]
       |                                                            [Verify Sig_client]
       |                                                            [Derive Session Keys]
       |                                                            [Verify MAC_confirm]
[CHANNEL ESTABLISHED]                                         [CHANNEL ESTABLISHED]
```

### 3.1 Handshake Messages & Transcripts

#### Step 1: ClientHello
$$\text{ClientHello} = \{ \text{version}: \text{uint16}, \text{suite\_id}: \text{uint16}, N_c: [32]\text{byte}, PK_{KEM\_eph}: [1184]\text{byte}, \text{timestamp}: \text{uint64} \}$$
* Total Wire Length: $2 + 2 + 32 + 1184 + 8 = 1,228 \text{ bytes}$.

#### Step 2: ServerHello
1. Server encapsulates: $(SS, CT_{KEM}) \leftarrow \text{Encaps}(PK_{KEM\_eph})$.
2. Server computes:
   $$\text{Transcript}_1 = \text{SHA-256}\left(\text{"QSC-v1-SERVER-BIND"} \,\|\, \text{Wire}(\text{ClientHello}) \,\|\, CT_{KEM} \,\|\, N_s \,\|\, \text{LenPre}(\text{ID}_{server})\right)$$
3. Server signs:
   $$\text{Sig}_{server} = \text{Sign}_{SK_{DSA\_server}}(\text{Transcript}_1)$$
4. Server constructs:
   $$\text{ServerHello} = \{ CT_{KEM}: [1088]\text{byte}, N_s: [32]\text{byte}, \text{ID}_{server}: \text{LenPre(string)}, \text{Sig}_{server}: [3309]\text{byte}, \text{timestamp}: \text{uint64} \}$$

#### Step 3: ClientAuth & Key Confirmation
1. Client verifies $\text{ID}_{server}$ is in trust store, decapsulates $SS$, hashes $\text{Transcript}_1$, and verifies $\text{Sig}_{server}$.
2. Client derives PRK and session tokens (see §4).
3. Client computes:
   $$\text{Transcript}_2 = \text{SHA-256}\left(\text{"QSC-v1-CLIENT-BIND"} \,\|\, \text{Transcript}_1 \,\|\, \text{Wire}(\text{ServerHello}) \,\|\, \text{LenPre}(\text{ID}_{client})\right)$$
4. Client signs:
   $$\text{Sig}_{client} = \text{Sign}_{SK_{DSA\_client}}(\text{Transcript}_2)$$
5. Client sends:
   $$\text{ClientAuth} = \{ \text{ID}_{client}: \text{LenPre(string)}, \text{Sig}_{client}: [3309]\text{byte}, \text{MAC}_{confirm}: [32]\text{byte} \}$$

---

## 4. Key Derivation (RFC 5869 HKDF-SHA256)

1. **Extraction:**
   $$\text{PRK} = \text{HKDF-Extract}(\text{salt} = N_c \parallel N_s, \text{IKM} = SS)$$
2. **Context-Specific Expansion:**
   * **Client-to-Server Encryption Key (32 B):**
     $$K_{c2s} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-AES-256-GCM-C2S"} \parallel \text{Transcript}_2, 32)$$
   * **Server-to-Client Encryption Key (32 B):**
     $$K_{s2c} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-AES-256-GCM-S2C"} \parallel \text{Transcript}_2, 32)$$
   * **Client-to-Server Base IV (12 B):**
     $$IV_{c2s\_base} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-IV-BASE-C2S"} \parallel \text{Transcript}_2, 12)$$
   * **Server-to-Client Base IV (12 B):**
     $$IV_{s2c\_base} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-IV-BASE-S2C"} \parallel \text{Transcript}_2, 12)$$
   * **Key Confirmation Token (32 B):**
     $$\text{MAC}_{confirm} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-FINISHED-CONFIRM"}, 32)$$
   * **Session Identifier (32 B):**
     $$\text{SessionID} = \text{HKDF-Expand}(\text{PRK}, \text{"QSC-v1-SESSION-ID"} \parallel \text{Transcript}_2, 32)$$

---

## 5. Bulk Symmetric Framing & Streaming Protocol

To transfer variable length data and multi-megabyte streams (1 KB, 100 KB, 10 MB) with zero memory blowup, transmission is framed into **64 KB authenticated chunks** ($65,536 \text{ bytes}$ plaintext maximum per chunk).

### 5.1 Binary Packet Layout
Each packet is serialized strictly in big-endian network byte order:

```
+-----------------------------------------------------------------------------+
| Chunk Length N  | Monotonic Counter |        IV         | Ciphertext ...    | GCM Tag  |
|    (4 Bytes)    |     (8 Bytes)     |    (12 Bytes)     |    (N-16 Bytes)   | (16 B)   |
+-----------------------------------------------------------------------------+
```
* **Chunk Length (4 Bytes):** uint32 big-endian, represents total size of `Ciphertext + GCM Tag`.
* **Monotonic Counter (8 Bytes):** uint64 big-endian, starting at `1` and incrementing strictly by 1.
* **Per-Chunk IV (12 Bytes):** Derived as:
  $$IV_{\text{chunk}} = IV_{\text{base}} \oplus \text{ZeroPad}_{12}(\text{Counter})$$
* **Associated Authenticated Data (AAD):**
  $$AAD = \text{SessionID} \,(32\text{B}) \parallel \text{Direction} \,(1\text{B}) \parallel \text{Counter} \,(8\text{B}) \parallel \text{FinalFlag} \,(1\text{B})$$
  * Direction: `0x01` (Client-to-Server), `0x02` (Server-to-Client).
  * FinalFlag: `0x00` (intermediate chunk), `0x01` (terminal EOF chunk).

### 5.2 End-to-End Plaintext Hash Verification
The sender maintains an incremental SHA-256 hash over the unencrypted streaming payload. The final chunk (`FinalFlag = 0x01`) encapsulates an authenticated trailer:
$$\text{EOF\_Payload} = \text{"QSC-EOF"} \,(7\text{B}) \parallel \text{TotalBytes} \,(8\text{B}) \parallel \text{SHA256}(\text{RawPlaintext}) \,(32\text{B})$$
Upon receipt and AEAD verification of the final chunk, the receiver asserts that the accumulated plaintext hash matches this trailer.
