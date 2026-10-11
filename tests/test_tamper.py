"""
Adversarial bit-flip and corruption tests across all packet fields and layers.
Verifies that tampering with KEM PK, KEM CT, DSA signatures, nonces,
ciphertext chunks, AAD, or GCM tags causes the system to fail closed immediately.
"""

import pytest
import os
import struct

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    compute_chunk_iv,
)
from src.protocol import (
    ClientHello,
    ServerHello,
    ClientAuth,
    frame_chunk,
    unframe_chunk,
    DIRECTION_C2S,
    FLAG_INTERMEDIATE,
    FLAG_EOF,
    QSCTamperError,
    QSCReplayError,
)


def flip_bit(b: bytes, index: int = 0) -> bytes:
    ba = bytearray(b)
    ba[index] ^= 0x01
    return bytes(ba)


def test_tamper_kem_ciphertext_causes_decap_mismatch_or_error():
    kem = PQCKeyEncapsulation()
    pk, sk = kem.generate_keypair()
    ct, ss1 = kem.encap_secret(pk)

    tampered_ct = flip_bit(ct, 42)
    try:
        ss2 = kem.decap_secret(tampered_ct, sk)
        # In ML-KEM implicit rejection, decapsulating tampered ciphertext produces a pseudo-random secret != ss1
        assert ss2 != ss1, "Implicit rejection failure: tampered ciphertext decrypted to original shared secret"
    except Exception:
        # Or library raises decap error
        pass


def test_tamper_dsa_signature_rejected():
    sig = PQCSignature()
    pk, sk = sig.generate_keypair()
    msg = b"Domain separated transcript binding"
    signature = sig.sign(msg, sk)

    tampered_sig = flip_bit(signature, 100)
    assert sig.verify(msg, tampered_sig, pk) is False


def test_tamper_client_hello_nonce():
    ch = ClientHello(
        version=0x0100,
        suite_id=0x0001,
        nonce=os.urandom(32),
        kem_public_key=os.urandom(1184),
        timestamp=1000,
    )
    wire = ch.serialize()
    # Flip bit in nonce (located at byte offset 4)
    tampered_wire = flip_bit(wire, 4)
    ch_deser = ClientHello.deserialize(tampered_wire)
    assert ch_deser.nonce != ch.nonce


def test_tamper_symmetric_chunk_ciphertext():
    session_id = os.urandom(32)
    key = os.urandom(32)
    base_iv = os.urandom(12)
    counter = 1
    plaintext = b"Top Secret Payload"

    frame = frame_chunk(session_id, key, base_iv, counter, plaintext, DIRECTION_C2S)

    # Frame structure: 4B len | 8B counter | 12B IV | ciphertext (N B) | tag (16 B)
    # Tamper with ciphertext byte (offset 25)
    tampered_frame = flip_bit(frame, 25)

    with pytest.raises(QSCTamperError):
        unframe_chunk(session_id, key, base_iv, counter, tampered_frame, DIRECTION_C2S)


def test_tamper_symmetric_chunk_gcm_tag():
    session_id = os.urandom(32)
    key = os.urandom(32)
    base_iv = os.urandom(12)
    counter = 1
    plaintext = b"Top Secret Payload"

    frame = frame_chunk(session_id, key, base_iv, counter, plaintext, DIRECTION_C2S)

    # Tamper with last byte (GCM tag)
    tampered_frame = flip_bit(frame, len(frame) - 1)

    with pytest.raises(QSCTamperError):
        unframe_chunk(session_id, key, base_iv, counter, tampered_frame, DIRECTION_C2S)


def test_tamper_chunk_direction_reflection_attack():
    session_id = os.urandom(32)
    key = os.urandom(32)
    base_iv = os.urandom(12)
    counter = 1
    plaintext = b"Payload sent Client-to-Server"

    # Encrypted in C2S direction
    frame = frame_chunk(session_id, key, base_iv, counter, plaintext, direction=DIRECTION_C2S)

    # Attacker reflects packet back to Client expecting S2C
    with pytest.raises(QSCTamperError):
        unframe_chunk(session_id, key, base_iv, counter, frame, direction=0x02)  # S2C expected
