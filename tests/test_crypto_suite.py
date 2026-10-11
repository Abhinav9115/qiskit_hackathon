"""
Unit tests for cryptographic suite (src/crypto_suite.py).
Validates NIST FIPS 203 and FIPS 204 byte size assertions,
KEM encap/decap round-trips, signature verification, and AES-256-GCM AEAD.
"""

import pytest
import os
import hashlib

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    derive_session_keys,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    compute_chunk_iv,
    sha256_digest,
    ClassicalReferenceBaseline,
    ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_SHARED_SECRET_SIZE,
    ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE,
)


def test_fips_203_kem_byte_sizes():
    kem = PQCKeyEncapsulation()
    pk, sk = kem.generate_keypair()
    assert len(pk) == ML_KEM_768_PUBLIC_KEY_SIZE == 1184
    ct, ss1 = kem.encap_secret(pk)
    assert len(ct) == ML_KEM_768_CIPHERTEXT_SIZE == 1088
    assert len(ss1) == ML_KEM_768_SHARED_SECRET_SIZE == 32
    ss2 = kem.decap_secret(ct, sk)
    assert len(ss2) == 32
    assert ss1 == ss2


def test_fips_204_dsa_byte_sizes():
    sig = PQCSignature()
    pk, sk = sig.generate_keypair()
    assert len(pk) == ML_DSA_65_PUBLIC_KEY_SIZE == 1952
    msg = b"FIPS 204 Test Vector Validation Payload"
    signature = sig.sign(msg, sk)
    assert len(signature) == ML_DSA_65_SIGNATURE_SIZE == 3309
    assert sig.verify(msg, signature, pk) is True


def test_dsa_rejects_corrupted_signature():
    sig = PQCSignature()
    pk, sk = sig.generate_keypair()
    msg = b"Authenticate this transcript message"
    signature = sig.sign(msg, sk)

    # Flip 1 bit in signature
    corrupted_sig = bytearray(signature)
    corrupted_sig[100] ^= 0x01
    assert sig.verify(msg, bytes(corrupted_sig), pk) is False


def test_dsa_rejects_wrong_message():
    sig = PQCSignature()
    pk, sk = sig.generate_keypair()
    msg1 = b"Message 1"
    msg2 = b"Message 2"
    signature = sig.sign(msg1, sk)
    assert sig.verify(msg2, signature, pk) is False


def test_hkdf_session_key_derivation():
    ss = os.urandom(32)
    nc = os.urandom(32)
    ns = os.urandom(32)
    tr2 = hashlib.sha256(b"Transcript2-Vector").digest()

    keys = derive_session_keys(ss, nc, ns, tr2)
    assert len(keys["prk"]) == 32
    assert len(keys["k_c2s"]) == 32
    assert len(keys["k_s2c"]) == 32
    assert len(keys["iv_c2s_base"]) == 12
    assert len(keys["iv_s2c_base"]) == 12
    assert len(keys["mac_confirm"]) == 32
    assert len(keys["session_id"]) == 32
    # Distinct directional keys
    assert keys["k_c2s"] != keys["k_s2c"]
    assert keys["iv_c2s_base"] != keys["iv_s2c_base"]


def test_aes_gcm_aead_roundtrip():
    key = os.urandom(32)
    base_iv = os.urandom(12)
    iv = compute_chunk_iv(base_iv, counter=1)
    plaintext = b"High security post-quantum bulk encrypted payload"
    aad = b"SessionID-Direction-Counter-Flag"

    ct, tag = aes_gcm_encrypt(key, iv, plaintext, aad)
    assert len(tag) == 16
    assert ct != plaintext

    dec = aes_gcm_decrypt(key, iv, ct, tag, aad)
    assert dec == plaintext


def test_classical_reference_baseline():
    # ECDH
    pk1, sk1 = ClassicalReferenceBaseline.generate_ecdh_keypair()
    pk2, sk2 = ClassicalReferenceBaseline.generate_ecdh_keypair()
    ss1 = ClassicalReferenceBaseline.ecdh_exchange(pk2, sk1)
    ss2 = ClassicalReferenceBaseline.ecdh_exchange(pk1, sk2)
    assert ss1 == ss2
    assert len(ss1) == 32

    # ECDSA
    dpk, dsk = ClassicalReferenceBaseline.generate_ecdsa_keypair()
    msg = b"Classical sign verification test"
    sig = ClassicalReferenceBaseline.ecdsa_sign(msg, dsk)
    assert ClassicalReferenceBaseline.ecdsa_verify(msg, sig, dpk) is True
