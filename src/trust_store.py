"""
Trust Store and Identity Pinning Management for QSC.
Pins long-term ML-DSA-65 public keys and verifies cryptographic fingerprints.
Handshakes strictly fail closed if an unpinned or untrusted identity is presented.
"""

from __future__ import annotations

import os
import json
import hashlib
import binascii
from pathlib import Path
from typing import Dict, Optional, Tuple

from src.crypto_suite import (
    PQCSignature,
    ML_DSA_65_PUBLIC_KEY_SIZE,
    sha256_digest,
)


def compute_fingerprint(public_key: bytes) -> str:
    """
    Computes standard SHA-256 hex fingerprint (64 lowercase hex characters).
    """
    assert len(public_key) == ML_DSA_65_PUBLIC_KEY_SIZE, (
        f"Public key size mismatch: expected {ML_DSA_65_PUBLIC_KEY_SIZE}, got {len(public_key)}"
    )
    return hashlib.sha256(public_key).hexdigest().lower()


class TrustStore:
    """
    Local pinned identity store for mutual ML-DSA-65 authentication.
    """

    def __init__(self, store_path: Optional[str | Path] = None):
        if store_path is None:
            home = Path.home()
            self.store_dir = home / ".qsc"
            self.store_path = self.store_dir / "trust_store.json"
        else:
            self.store_path = Path(store_path)
            self.store_dir = self.store_path.parent

        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._trusted_peers: Dict[str, Dict[str, str]] = {}
        self.load()

    def load(self) -> None:
        """
        Loads pinned identities from JSON disk file if present.
        """
        if self.store_path.exists():
            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._trusted_peers = data
            except Exception:
                self._trusted_peers = {}
        else:
            self._trusted_peers = {}

    def save(self) -> None:
        """
        Atomically persists pinned identities to disk.
        """
        self.store_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self.store_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self._trusted_peers, f, indent=2)
        tmp_path.replace(self.store_path)

    def pin_peer(self, identity: str, public_key: bytes) -> str:
        """
        Pins an ML-DSA-65 public key under identity name. Returns hex fingerprint.
        """
        assert len(public_key) == ML_DSA_65_PUBLIC_KEY_SIZE, (
            f"Cannot pin invalid public key length: {len(public_key)} B"
        )
        fp = compute_fingerprint(public_key)
        self._trusted_peers[identity] = {
            "fingerprint": fp,
            "public_key_hex": binascii.hexlify(public_key).decode("ascii"),
        }
        self.save()
        return fp

    def get_peer_key(self, identity: str) -> Optional[bytes]:
        """
        Retrieves pinned ML-DSA-65 public key for identity, or None if unpinned.
        """
        record = self._trusted_peers.get(identity)
        if not record or "public_key_hex" not in record:
            return None
        try:
            raw_key = binascii.unhexlify(record["public_key_hex"])
            if len(raw_key) == ML_DSA_65_PUBLIC_KEY_SIZE:
                return raw_key
        except Exception:
            return None
        return None

    def is_trusted(self, identity: str, public_key: bytes) -> bool:
        """
        Checks whether public_key matches the pinned key and fingerprint for identity.
        """
        pinned_key = self.get_peer_key(identity)
        if pinned_key is None:
            return False
        # Constant-time comparison
        return (
            len(pinned_key) == len(public_key)
            and hashlib.sha256(pinned_key).digest() == hashlib.sha256(public_key).digest()
        )

    def unpin_peer(self, identity: str) -> bool:
        """
        Removes an identity from trust store.
        """
        if identity in self._trusted_peers:
            del self._trusted_peers[identity]
            self.save()
            return True
        return False

    def list_peers(self) -> Dict[str, str]:
        """
        Returns mapping of identity -> fingerprint.
        """
        return {k: v.get("fingerprint", "") for k, v in self._trusted_peers.items()}


class IdentityManager:
    """
    Manages local node's long-term ML-DSA-65 identity keypair.
    """

    def __init__(self, key_dir: Optional[str | Path] = None):
        if key_dir is None:
            self.key_dir = Path.home() / ".qsc" / "identities"
        else:
            self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self._sig_provider = PQCSignature()

    def generate_and_save(self, identity: str) -> Tuple[bytes, bytes, str]:
        """
        Generates fresh ML-DSA-65 keypair and saves to disk: returns (pk, sk, fingerprint).
        """
        pk, sk = self._sig_provider.generate_keypair()
        fp = compute_fingerprint(pk)

        pk_file = self.key_dir / f"{identity}.pub"
        sk_file = self.key_dir / f"{identity}.key"

        with open(pk_file, "wb") as f:
            f.write(pk)
        with open(sk_file, "wb") as f:
            f.write(sk)

        # Restrict private key permissions on POSIX
        if os.name == "posix":
            os.chmod(sk_file, 0o600)

        return pk, sk, fp

    def load_identity(self, identity: str) -> Tuple[bytes, bytes, str]:
        """
        Loads local identity (pk, sk, fingerprint). Raises FileNotFoundError if missing.
        """
        pk_file = self.key_dir / f"{identity}.pub"
        sk_file = self.key_dir / f"{identity}.key"

        if not pk_file.exists() or not sk_file.exists():
            raise FileNotFoundError(f"Identity '{identity}' not found at {self.key_dir}")

        with open(pk_file, "rb") as f:
            pk = f.read()
        with open(sk_file, "rb") as f:
            sk = f.read()

        assert len(pk) == ML_DSA_65_PUBLIC_KEY_SIZE, f"Corrupted public key size: {len(pk)}"
        fp = compute_fingerprint(pk)
        return pk, sk, fp
