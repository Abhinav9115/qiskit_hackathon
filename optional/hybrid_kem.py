"""
Optional Hybrid Key Exchange (X25519 + ML-KEM-768) for QSC.
Combines classical Curve25519 ECDH with NIST FIPS 203 ML-KEM-768.
Guarantees security as long as AT LEAST ONE underlying assumption holds.
"""

from __future__ import annotations

import os
import sys
import hashlib
from pathlib import Path
from typing import Tuple, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.crypto_suite import PQCKeyEncapsulation, hkdf_extract, hkdf_expand


class HybridKEM:
    """
    Dual-combiner Key Encapsulation Mechanism:
    Combines ephemeral X25519 with ephemeral ML-KEM-768.
    """

    def __init__(self):
        self.pqc_kem = PQCKeyEncapsulation("ML-KEM-768")

    def generate_keypair(self) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
        """
        Generates hybrid public key (X25519 PK || ML-KEM-768 PK) and private keys.
        """
        # Classical X25519
        x_sk = x25519.X25519PrivateKey.generate()
        x_pk = x_sk.public_key().public_bytes_raw()

        # Post-quantum ML-KEM-768
        kem_pk, kem_sk = self.pqc_kem.generate_keypair()

        hybrid_pk = {
            "x25519_pk": x_pk,
            "ml_kem_pk": kem_pk,
        }
        hybrid_sk = {
            "x25519_sk": x_sk,
            "ml_kem_sk": kem_sk,
        }
        return hybrid_pk, hybrid_sk

    def encap_secret(self, peer_hybrid_pk: Dict[str, bytes]) -> Tuple[Dict[str, bytes], bytes]:
        """
        Encapsulates against peer's hybrid public key.
        Returns (ciphertext_dict, combined_shared_secret).
        """
        # Ephemeral X25519 exchange
        eph_x_sk = x25519.X25519PrivateKey.generate()
        eph_x_pk = eph_x_sk.public_key().public_bytes_raw()
        peer_x_pk = x25519.X25519PublicKey.from_public_bytes(peer_hybrid_pk["x25519_pk"])
        ss_classical = eph_x_sk.exchange(peer_x_pk)

        # ML-KEM-768 encapsulation
        kem_ct, ss_pqc = self.pqc_kem.encap_secret(peer_hybrid_pk["ml_kem_pk"])

        # Dual combiner extraction: PRK = HKDF-Extract(salt="", IKM = ss_pqc || ss_classical)
        combined_ikm = ss_pqc + ss_classical
        combined_ss = hkdf_extract(salt=b"QSC-HYBRID-KEM-v1", ikm=combined_ikm)

        ct_dict = {
            "eph_x25519_pk": eph_x_pk,
            "ml_kem_ct": kem_ct,
        }
        return ct_dict, combined_ss

    def decap_secret(self, ct_dict: Dict[str, bytes], hybrid_sk: Dict[str, Any]) -> bytes:
        """
        Decapsulates hybrid ciphertext using private keys.
        """
        # Classical X25519 decapsulation
        peer_eph_pk = x25519.X25519PublicKey.from_public_bytes(ct_dict["eph_x25519_pk"])
        ss_classical = hybrid_sk["x25519_sk"].exchange(peer_eph_pk)

        # ML-KEM-768 decapsulation
        ss_pqc = self.pqc_kem.decap_secret(ct_dict["ml_kem_ct"], hybrid_sk["ml_kem_sk"])

        # Combined extraction matching encap
        combined_ikm = ss_pqc + ss_classical
        return hkdf_extract(salt=b"QSC-HYBRID-KEM-v1", ikm=combined_ikm)


def test_hybrid_kem():
    hkem = HybridKEM()
    pk, sk = hkem.generate_keypair()
    ct, ss1 = hkem.encap_secret(pk)
    ss2 = hkem.decap_secret(ct, sk)
    assert ss1 == ss2
    print("Hybrid KEM (X25519 + ML-KEM-768) verified successfully!")


if __name__ == "__main__":
    test_hybrid_kem()
