"""
QSC Wire Framing, Handshake State Machine, and Streaming Protocol.
Implements binary serialization, domain-separated transcript hashing,
64 KB chunk authenticated framing, replay defenses, and EOF digest validation.
"""

from __future__ import annotations

import struct
import time
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional, Generator

from src.crypto_suite import (
    ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_SHARED_SECRET_SIZE,
    ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    compute_chunk_iv,
    sha256_digest,
)

PROTOCOL_VERSION = 0x0100  # v1.0
CIPHERSUITE_ML_KEM_768_ML_DSA_65_AES256GCM = 0x0001
MAX_CHUNK_PLAINTEXT_SIZE = 65536  # 64 KB

DIRECTION_C2S = 0x01
DIRECTION_S2C = 0x02

FLAG_INTERMEDIATE = 0x00
FLAG_EOF = 0x01


class QSCProtocolError(Exception):
    """Base error for all QSC protocol violations."""
    pass


class QSCTamperError(QSCProtocolError):
    """Raised when an AEAD tag, signature, or cryptographic field is corrupted."""
    pass


class QSCReplayError(QSCProtocolError):
    """Raised on replayed, skipped, duplicate, or out-of-order counter packets."""
    pass


class QSCAuthenticationError(QSCProtocolError):
    """Raised when peer identity verification or key confirmation fails."""
    pass


# =====================================================================
# Handshake Messages Data Structures & Wire Serialization
# =====================================================================
@dataclass(frozen=True)
class ClientHello:
    version: int
    suite_id: int
    nonce: bytes
    kem_public_key: bytes
    timestamp: int

    def serialize(self) -> bytes:
        assert len(self.nonce) == 32, "Nonce must be 32 bytes"
        assert len(self.kem_public_key) == ML_KEM_768_PUBLIC_KEY_SIZE, "Invalid KEM PK size"
        return struct.pack(
            f">HH32s{ML_KEM_768_PUBLIC_KEY_SIZE}sQ",
            self.version,
            self.suite_id,
            self.nonce,
            self.kem_public_key,
            self.timestamp,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> ClientHello:
        expected_len = 2 + 2 + 32 + ML_KEM_768_PUBLIC_KEY_SIZE + 8
        if len(data) != expected_len:
            raise QSCTamperError(f"Malformed ClientHello size: expected {expected_len}, got {len(data)}")
        ver, suite, nonce, kem_pk, ts = struct.unpack(
            f">HH32s{ML_KEM_768_PUBLIC_KEY_SIZE}sQ",
            data,
        )
        if ver != PROTOCOL_VERSION:
            raise QSCProtocolError(f"Unsupported protocol version: 0x{ver:04x}")
        if suite != CIPHERSUITE_ML_KEM_768_ML_DSA_65_AES256GCM:
            raise QSCProtocolError(f"Unsupported ciphersuite: 0x{suite:04x}")
        return cls(version=ver, suite_id=suite, nonce=nonce, kem_public_key=kem_pk, timestamp=ts)


@dataclass(frozen=True)
class ServerHello:
    kem_ciphertext: bytes
    nonce: bytes
    server_id: str
    signature: bytes
    timestamp: int

    def serialize(self) -> bytes:
        assert len(self.kem_ciphertext) == ML_KEM_768_CIPHERTEXT_SIZE
        assert len(self.nonce) == 32
        assert len(self.signature) == ML_DSA_65_SIGNATURE_SIZE
        id_bytes = self.server_id.encode("utf-8")
        header = struct.pack(
            f">{ML_KEM_768_CIPHERTEXT_SIZE}s32sH",
            self.kem_ciphertext,
            self.nonce,
            len(id_bytes),
        )
        trailer = struct.pack(f">{ML_DSA_65_SIGNATURE_SIZE}sQ", self.signature, self.timestamp)
        return header + id_bytes + trailer

    @classmethod
    def deserialize(cls, data: bytes) -> ServerHello:
        header_len = ML_KEM_768_CIPHERTEXT_SIZE + 32 + 2
        trailer_len = ML_DSA_65_SIGNATURE_SIZE + 8
        if len(data) < header_len + trailer_len:
            raise QSCTamperError("ServerHello message truncated")
        ct, nonce, id_len = struct.unpack(f">{ML_KEM_768_CIPHERTEXT_SIZE}s32sH", data[:header_len])
        if len(data) != header_len + id_len + trailer_len:
            raise QSCTamperError("Malformed ServerHello payload framing")
        id_bytes = data[header_len : header_len + id_len]
        sig, ts = struct.unpack(f">{ML_DSA_65_SIGNATURE_SIZE}sQ", data[header_len + id_len :])
        return cls(
            kem_ciphertext=ct,
            nonce=nonce,
            server_id=id_bytes.decode("utf-8", errors="replace"),
            signature=sig,
            timestamp=ts,
        )


@dataclass(frozen=True)
class ClientAuth:
    client_id: str
    signature: bytes
    mac_confirm: bytes

    def serialize(self) -> bytes:
        assert len(self.signature) == ML_DSA_65_SIGNATURE_SIZE
        assert len(self.mac_confirm) == 32
        id_bytes = self.client_id.encode("utf-8")
        header = struct.pack(">H", len(id_bytes))
        trailer = struct.pack(f">{ML_DSA_65_SIGNATURE_SIZE}s32s", self.signature, self.mac_confirm)
        return header + id_bytes + trailer

    @classmethod
    def deserialize(cls, data: bytes) -> ClientAuth:
        if len(data) < 2 + ML_DSA_65_SIGNATURE_SIZE + 32:
            raise QSCTamperError("ClientAuth message truncated")
        id_len = struct.unpack(">H", data[:2])[0]
        if len(data) != 2 + id_len + ML_DSA_65_SIGNATURE_SIZE + 32:
            raise QSCTamperError("Malformed ClientAuth payload framing")
        id_bytes = data[2 : 2 + id_len]
        sig, mac = struct.unpack(
            f">{ML_DSA_65_SIGNATURE_SIZE}s32s",
            data[2 + id_len :],
        )
        return cls(
            client_id=id_bytes.decode("utf-8", errors="replace"),
            signature=sig,
            mac_confirm=mac,
        )


# =====================================================================
# Transcript Binding Computations (§3.1)
# =====================================================================
def compute_transcript_1(
    client_hello_wire: bytes,
    kem_ciphertext: bytes,
    server_nonce: bytes,
    server_id: str,
) -> bytes:
    """
    Transcript_1 = SHA-256("QSC-v1-SERVER-BIND" || ClientHello || CT_kem || N_s || LenPre(ID_server))
    """
    id_bytes = server_id.encode("utf-8")
    payload = (
        b"QSC-v1-SERVER-BIND"
        + client_hello_wire
        + kem_ciphertext
        + server_nonce
        + struct.pack(">H", len(id_bytes))
        + id_bytes
    )
    return sha256_digest(payload)


def compute_transcript_2(
    transcript_1: bytes,
    server_hello_wire: bytes,
    client_id: str,
) -> bytes:
    """
    Transcript_2 = SHA-256("QSC-v1-CLIENT-BIND" || Transcript_1 || ServerHello || LenPre(ID_client))
    """
    id_bytes = client_id.encode("utf-8")
    payload = (
        b"QSC-v1-CLIENT-BIND"
        + transcript_1
        + server_hello_wire
        + struct.pack(">H", len(id_bytes))
        + id_bytes
    )
    return sha256_digest(payload)


# =====================================================================
# Symmetric Frame Layout & Chunk Framing (§3.3)
# =====================================================================
# Layout: Chunk Length (4B) | Counter (8B) | IV (12B) | Ciphertext (NB) | Tag (16B)
CHUNK_HEADER_SIZE = 4 + 8 + 12  # 24 Bytes
GCM_TAG_SIZE = 16


def build_aad(session_id: bytes, direction: int, counter: int, final_flag: int) -> bytes:
    """
    AAD = SessionID(32B) || Direction(1B) || Counter(8B) || FinalFlag(1B)
    """
    assert len(session_id) == 32, "Session ID must be 32 bytes"
    return struct.pack(">32sBQB", session_id, direction, counter, final_flag)


def frame_chunk(
    session_id: bytes,
    key: bytes,
    base_iv: bytes,
    counter: int,
    plaintext: bytes,
    direction: int,
    final_flag: int = FLAG_INTERMEDIATE,
) -> bytes:
    """
    Encrypts and frames an authenticated 64 KB chunk.
    """
    iv = compute_chunk_iv(base_iv, counter)
    aad = build_aad(session_id, direction, counter, final_flag)
    ciphertext, tag = aes_gcm_encrypt(key, iv, plaintext, aad)

    # Chunk length = ciphertext + tag
    chunk_length = len(ciphertext) + len(tag)
    header = struct.pack(">IQ12s", chunk_length, counter, iv)
    return header + ciphertext + tag


def unframe_chunk(
    session_id: bytes,
    key: bytes,
    base_iv: bytes,
    expected_counter: int,
    frame_bytes: bytes,
    direction: int,
    final_flag: int = FLAG_INTERMEDIATE,
) -> Tuple[bytes, int]:
    """
    Validates monotonic counter, derives IV, and decrypts AEAD payload.
    Returns (plaintext, next_expected_counter).
    Fails closed on replay, reordering, or bit corruption.
    """
    if len(frame_bytes) < CHUNK_HEADER_SIZE + GCM_TAG_SIZE:
        raise QSCTamperError("Frame shorter than minimum header + AEAD tag")

    chunk_length, counter, wire_iv = struct.unpack(">IQ12s", frame_bytes[:CHUNK_HEADER_SIZE])
    if len(frame_bytes) != CHUNK_HEADER_SIZE + chunk_length:
        raise QSCTamperError("Frame byte length does not match declared chunk length")

    # Strict Monotonic Counter Validation
    if counter < expected_counter:
        raise QSCReplayError(f"Replay detected: received counter {counter} <= expected {expected_counter}")
    if counter > expected_counter:
        raise QSCReplayError(f"Out-of-order/gap detected: received counter {counter} != expected {expected_counter}")

    expected_iv = compute_chunk_iv(base_iv, counter)
    if wire_iv != expected_iv:
        raise QSCTamperError("Wire IV does not match expected derived counter IV")

    ct_with_tag = frame_bytes[CHUNK_HEADER_SIZE:]
    ciphertext = ct_with_tag[:-GCM_TAG_SIZE]
    tag = ct_with_tag[-GCM_TAG_SIZE:]

    aad = build_aad(session_id, direction, counter, final_flag)
    try:
        plaintext = aes_gcm_decrypt(key, wire_iv, ciphertext, tag, aad)
    except Exception as e:
        raise QSCTamperError(f"AEAD authentication tag verification failed: {e}") from e

    return plaintext, counter + 1


# =====================================================================
# End-to-End Plaintext Hash Serialization (§3.3 & §5.2)
# =====================================================================
def build_eof_payload(total_bytes: int, plaintext_sha256: bytes) -> bytes:
    """
    Authenticated EOF trailer: 'QSC-EOF' (7B) || total_bytes (8B) || plaintext_sha256 (32B)
    """
    assert len(plaintext_sha256) == 32
    return b"QSC-EOF" + struct.pack(">Q", total_bytes) + plaintext_sha256


def verify_eof_payload(payload: bytes, observed_bytes: int, observed_sha256: bytes) -> None:
    """
    Validates end-of-file trailer against receiver's incremental accumulator.
    """
    if not payload.startswith(b"QSC-EOF"):
        raise QSCTamperError("Invalid EOF payload magic identifier")
    if len(payload) != 7 + 8 + 32:
        raise QSCTamperError(f"Invalid EOF payload length: {len(payload)}")

    expected_bytes, expected_hash = struct.unpack(">Q32s", payload[7:])
    if expected_bytes != observed_bytes:
        raise QSCTamperError(
            f"Stream truncation detected: expected {expected_bytes} bytes, received {observed_bytes}"
        )
    if expected_hash != observed_sha256:
        raise QSCTamperError(
            f"End-to-end plaintext hash mismatch: expected {expected_hash.hex()} got {observed_sha256.hex()}"
        )
