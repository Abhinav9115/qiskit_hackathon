"""
Cryptographic Suite for QSC (Quantum-Safe Channel).
Standards-compliant implementation of NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65)
via native liboqs C-bindings only. Zero homemade or fallback primitives.
Bulk encryption via NIST SP 800-38D AES-256-GCM and key derivation via RFC 5869 HKDF-SHA256.
"""

from __future__ import annotations

import os
import hashlib
import struct
import logging
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("qsc.crypto")

# =====================================================================
# Strict Native liboqs Verification (No Homemade Fallbacks)
# =====================================================================
try:
    import oqs  # type: ignore
except ImportError as err:
    raise RuntimeError(
        "CRITICAL SECURITY REQUIREMENT: liboqs-python must be installed and functional. "
        "Post-quantum cryptographic primitives cannot be substituted with homemade fallbacks. "
        "Please install liboqs-python with native C library support or run in the provided container."
    ) from err


def require_algorithm(name: str, enabled: list[str]) -> None:
    """
    Enforces that the requested standardized NIST algorithm is natively compiled and enabled.
    Refuses to execute or substitute lookalike primitives.
    """
    if name not in enabled:
        raise RuntimeError(
            f"FIPS Compliance Error: {name} is unavailable in this liboqs build; "
            f"refusing to use a substitute. Enabled mechanisms: {enabled}"
        )


# Validate enabled mechanisms
_enabled_kems = oqs.get_enabled_kem_mechanisms() if hasattr(oqs, "get_enabled_kem_mechanisms") else oqs.get_enabled_KEM_mechanisms()
_enabled_sigs = oqs.get_enabled_sig_mechanisms() if hasattr(oqs, "get_enabled_sig_mechanisms") else oqs.get_enabled_SIG_mechanisms()

require_algorithm("ML-KEM-768", _enabled_kems)
require_algorithm("ML-DSA-65", _enabled_sigs)


def _detect_native_liboqs_version() -> str:
    """
    Extracts the exact native C library version directly from liboqs bindings.
    Fails closed if the runtime version cannot be verified.
    """
    if hasattr(oqs, "oqs_version") and callable(oqs.oqs_version):
        ver = oqs.oqs_version()
        if ver:
            return str(ver)
    if hasattr(oqs, "OQS_VERSION") and oqs.OQS_VERSION:
        return str(oqs.OQS_VERSION)
    try:
        import importlib.metadata
        return importlib.metadata.version("liboqs-python")
    except Exception as err:
        raise RuntimeError(
            "CRITICAL: Unable to dynamically determine native liboqs version. "
            "Refusing to execute with unverified cryptographic runtime."
        ) from err


def _detect_wrapper_version() -> str:
    """
    Extracts the exact liboqs-python wrapper package version.
    Fails closed if package metadata is inaccessible.
    """
    if hasattr(oqs, "oqs_python_version") and callable(oqs.oqs_python_version):
        return str(oqs.oqs_python_version())
    try:
        import importlib.metadata
        return importlib.metadata.version("liboqs-python")
    except Exception as err:
        raise RuntimeError(
            "CRITICAL: Unable to dynamically determine liboqs-python wrapper version."
        ) from err


LIBOQS_VERSION = _detect_native_liboqs_version()
LIBOQS_WRAPPER_VERSION = _detect_wrapper_version()
LIBOQS_BACKEND = "native_liboqs"


def get_crypto_metadata() -> Dict[str, Any]:
    """
    Returns verified runtime metadata for the cryptographic backend and algorithms.
    """
    return {
        "liboqs_version": LIBOQS_VERSION,
        "liboqs_wrapper_version": LIBOQS_WRAPPER_VERSION,
        "backend": LIBOQS_BACKEND,
        "kem_mechanism": "ML-KEM-768",
        "sig_mechanism": "ML-DSA-65",
        "kem_fips_standard": "NIST FIPS 203",
        "sig_fips_standard": "NIST FIPS 204",
        "enabled_kems_count": len(_enabled_kems),
        "enabled_sigs_count": len(_enabled_sigs),
    }


# =====================================================================
# NIST FIPS Wire-Size Specifications
# =====================================================================
ML_KEM_768_PUBLIC_KEY_SIZE = 1184
ML_KEM_768_CIPHERTEXT_SIZE = 1088
ML_KEM_768_SHARED_SECRET_SIZE = 32

ML_DSA_65_PUBLIC_KEY_SIZE = 1952
ML_DSA_65_SECRET_KEY_SIZE = 4032
ML_DSA_65_SIGNATURE_SIZE = 3309


# =====================================================================
# Post-Quantum Key Encapsulation (NIST FIPS 203 / ML-KEM-768)
# =====================================================================
class PQCKeyEncapsulation:
    """
    Standards-compliant ML-KEM-768 encapsulation provider using native liboqs.
    """

    def __init__(self, alg_name: str = "ML-KEM-768"):
        require_algorithm(alg_name, _enabled_kems)
        self.alg_name = alg_name
        self.backend = LIBOQS_BACKEND

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generates (public_key, secret_key) asserting exact FIPS 203 sizes.
        """
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            pk = bytes(kem.generate_keypair())
            sk = bytes(kem.export_secret_key())

        assert len(pk) == ML_KEM_768_PUBLIC_KEY_SIZE, (
            f"FIPS 203 violation: ML-KEM-768 public key must be {ML_KEM_768_PUBLIC_KEY_SIZE} B, got {len(pk)} B"
        )
        return pk, sk

    def encap_secret(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulates shared secret against public key: returns (ciphertext, shared_secret).
        """
        assert len(public_key) == ML_KEM_768_PUBLIC_KEY_SIZE, (
            f"FIPS 203 violation: invalid ML-KEM-768 public key size: {len(public_key)} B"
        )

        with oqs.KeyEncapsulation(self.alg_name) as kem:
            ct, ss = kem.encap_secret(public_key)
            ct = bytes(ct)
            ss = bytes(ss)

        assert len(ct) == ML_KEM_768_CIPHERTEXT_SIZE, (
            f"FIPS 203 violation: ML-KEM-768 ciphertext must be {ML_KEM_768_CIPHERTEXT_SIZE} B, got {len(ct)} B"
        )
        assert len(ss) == ML_KEM_768_SHARED_SECRET_SIZE, (
            f"FIPS 203 violation: ML-KEM-768 shared secret must be {ML_KEM_768_SHARED_SECRET_SIZE} B, got {len(ss)} B"
        )
        return ct, ss

    def decap_secret(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulates shared secret using private key.
        """
        assert len(ciphertext) == ML_KEM_768_CIPHERTEXT_SIZE, (
            f"FIPS 203 violation: invalid ML-KEM-768 ciphertext size: {len(ciphertext)} B"
        )

        with oqs.KeyEncapsulation(self.alg_name, secret_key=secret_key) as kem:
            ss = bytes(kem.decap_secret(ciphertext))

        assert len(ss) == ML_KEM_768_SHARED_SECRET_SIZE, (
            f"FIPS 203 violation: ML-KEM-768 decapsulated secret must be {ML_KEM_768_SHARED_SECRET_SIZE} B, got {len(ss)} B"
        )
        return ss


# =====================================================================
# Post-Quantum Digital Signature (NIST FIPS 204 / ML-DSA-65)
# =====================================================================
class PQCSignature:
    """
    Standards-compliant ML-DSA-65 digital signature provider using native liboqs.
    """

    def __init__(self, alg_name: str = "ML-DSA-65"):
        require_algorithm(alg_name, _enabled_sigs)
        self.alg_name = alg_name
        self.backend = LIBOQS_BACKEND

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generates (public_key, secret_key) asserting exact FIPS 204 sizes.
        """
        with oqs.Signature(self.alg_name) as sig:
            pk = bytes(sig.generate_keypair())
            sk = bytes(sig.export_secret_key())

        assert len(pk) == ML_DSA_65_PUBLIC_KEY_SIZE, (
            f"FIPS 204 violation: ML-DSA-65 public key must be {ML_DSA_65_PUBLIC_KEY_SIZE} B, got {len(pk)} B"
        )
        return pk, sk

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Signs message using secret key.
        """
        with oqs.Signature(self.alg_name, secret_key=secret_key) as sig:
            signature = bytes(sig.sign(message))

        assert len(signature) == ML_DSA_65_SIGNATURE_SIZE, (
            f"FIPS 204 violation: ML-DSA-65 signature must be {ML_DSA_65_SIGNATURE_SIZE} B, got {len(signature)} B"
        )
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifies signature over message using public key. Returns True if valid, False otherwise.
        """
        if len(signature) != ML_DSA_65_SIGNATURE_SIZE:
            return False
        if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
            return False

        try:
            with oqs.Signature(self.alg_name) as sig:
                return bool(sig.verify(message, signature, public_key))
        except Exception:
            return False


# =====================================================================
# Key Derivation (RFC 5869 HKDF-SHA256) & Mutual Finished MAC
# =====================================================================
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    RFC 5869 Extract step: PRK = HMAC-Hash(salt, IKM).
    """
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    RFC 5869 Expand step: OKM = HKDF-Expand(PRK, info, L).
    """
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return hkdf.derive(prk)


def derive_session_keys(
    shared_secret: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    transcript_2: bytes,
) -> Dict[str, bytes]:
    """
    Derives directional bulk encryption keys, base IVs, dedicated Finished MAC key, and SessionID.
    """
    salt = client_nonce + server_nonce
    prk = hkdf_extract(salt, shared_secret)

    k_c2s = hkdf_expand(prk, b"QSC-v1-AES-256-GCM-C2S" + transcript_2, 32)
    k_s2c = hkdf_expand(prk, b"QSC-v1-AES-256-GCM-S2C" + transcript_2, 32)
    iv_c2s_base = hkdf_expand(prk, b"QSC-v1-IV-BASE-C2S" + transcript_2, 12)
    iv_s2c_base = hkdf_expand(prk, b"QSC-v1-IV-BASE-S2C" + transcript_2, 12)
    k_finished = hkdf_expand(prk, b"QSC-v1-FINISHED-KEY" + transcript_2, 32)
    session_id = hkdf_expand(prk, b"QSC-v1-SESSION-ID" + transcript_2, 32)

    return {
        "prk": prk,
        "k_c2s": k_c2s,
        "k_s2c": k_s2c,
        "iv_c2s_base": iv_c2s_base,
        "iv_s2c_base": iv_s2c_base,
        "k_finished": k_finished,
        "session_id": session_id,
    }


def compute_finished_mac(k_finished: bytes, role: str, transcript: bytes) -> bytes:
    """
    Computes Finished HMAC over role and transcript:
    HMAC-SHA256(k_finished, role.encode() || transcript)
    """
    assert len(k_finished) == 32, "Finished key must be 32 bytes"
    h = hmac.HMAC(k_finished, hashes.SHA256())
    h.update(role.encode("utf-8") + transcript)
    return h.finalize()


# =====================================================================
# Symmetric AEAD Encryption (AES-256-GCM)
# =====================================================================
def compute_chunk_iv(base_iv: bytes, counter: int) -> bytes:
    """
    IV = base_iv ^ ZeroPad12(counter)
    Guarantees strict nonce uniqueness across monotonically increasing counters.
    """
    assert len(base_iv) == 12, "Base IV must be 12 bytes"
    counter_bytes = struct.pack(">Q", counter).rjust(12, b"\x00")
    return bytes(b ^ c for b, c in zip(base_iv, counter_bytes))


def aes_gcm_encrypt(
    key: bytes,
    iv: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext via AES-256-GCM. Returns (ciphertext, 16-byte tag).
    """
    assert len(key) == 32, "Key must be 256 bits (32 bytes)"
    assert len(iv) == 12, "IV must be 96 bits (12 bytes)"
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, tag


def aes_gcm_decrypt(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: bytes,
) -> bytes:
    """
    Decrypts and authenticates ciphertext. Fails closed and raises InvalidTag on tamper.
    """
    assert len(key) == 32, "Key must be 256 bits (32 bytes)"
    assert len(iv) == 12, "IV must be 96 bits (12 bytes)"
    assert len(tag) == 16, "Tag must be 128 bits (16 bytes)"
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, associated_data)


def sha256_digest(data: bytes) -> bytes:
    """
    Computes SHA-256 digest of arbitrary byte sequences.
    """
    return hashlib.sha256(data).digest()


# =====================================================================
# Classical Reference Baseline (ECDH P-256 + ECDSA P-256)
# broken by Shor's algorithm — solely for transition comparison
# =====================================================================
class ClassicalReferenceBaseline:
    """
    Classical key exchange and signature provider for quantitative benchmark comparisons.
    Marked explicitly: Broken by Shor's algorithm on a CRQC.
    """

    @staticmethod
    def generate_ecdh_keypair():
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key()
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return pk_bytes, sk

    @staticmethod
    def ecdh_exchange(peer_pk_bytes: bytes, sk) -> bytes:
        peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pk_bytes)
        shared_secret = sk.exchange(ec.ECDH(), peer_pk)
        return hashlib.sha256(shared_secret).digest()

    @staticmethod
    def generate_ecdsa_keypair():
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key()
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pk_bytes, sk

    @staticmethod
    def ecdsa_sign(message: bytes, sk) -> bytes:
        return sk.sign(message, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def ecdsa_verify(message: bytes, signature: bytes, pk_bytes: bytes) -> bool:
        try:
            pk = serialization.load_der_public_key(pk_bytes)
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
