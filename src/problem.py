"""
Problem Statement Definition & Solution Engine: Track 5, Problem P1
Problem Statement: "Quantum-Safe Secure Channel" (QSC)
Submission for Qiskit Fall Fest 2026.
"""

from __future__ import annotations

import os
import sys
import asyncio
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    derive_session_keys,
    ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_CIPHERTEXT_SIZE,
    ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE,
    LIBOQS_BACKEND,
)
from src.trust_store import TrustStore, IdentityManager, compute_fingerprint
from src.protocol import (
    ClientHello,
    ServerHello,
    ClientAuth,
    frame_chunk,
    unframe_chunk,
    build_eof_payload,
    verify_eof_payload,
    PROTOCOL_VERSION,
    CIPHERSUITE_ML_KEM_768_ML_DSA_65_AES256GCM,
    MAX_CHUNK_PLAINTEXT_SIZE,
)
from src.peer import QSCClient, QSCServer
from src.transport import MockTransport, AsyncTCPTransport


class QuantumSafeChannelProblem:
    """
    Primary solver class for Problem Statement P1: Quantum-Safe Secure Channel.
    Orchestrates identity generation, mutual authentication, AEAD streaming, and validation.
    """

    def __init__(self, work_dir: Optional[str | Path] = None):
        self.work_dir = Path(work_dir) if work_dir else Path("results/scratch_trust")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.identity_mgr = IdentityManager(self.work_dir / "keys")
        self.client_trust_store = TrustStore(self.work_dir / "client_trust.json")
        self.server_trust_store = TrustStore(self.work_dir / "server_trust.json")
        self.backend = LIBOQS_BACKEND

    def setup_identities(self, client_id: str = "client-node", server_id: str = "server-node"):
        """
        Generates and mutual-pins identities in local trust stores.
        """
        c_pk, c_sk, c_fp = self.identity_mgr.generate_and_save(client_id)
        s_pk, s_sk, s_fp = self.identity_mgr.generate_and_save(server_id)

        self.client_trust_store.pin_peer(server_id, s_pk)
        self.server_trust_store.pin_peer(client_id, c_pk)

        return {
            "client": {"id": client_id, "fingerprint": c_fp, "pk": c_pk, "sk": c_sk},
            "server": {"id": server_id, "fingerprint": s_fp, "pk": s_pk, "sk": s_sk},
        }

    async def execute_secure_session(self, payload: bytes) -> Dict[str, Any]:
        """
        Runs an end-to-end authenticated handshake and payload transfer.
        """
        nodes = self.setup_identities()
        client = QSCClient(
            identity="client-node",
            signing_key=nodes["client"]["sk"],
            public_key=nodes["client"]["pk"],
            trust_store=self.client_trust_store,
        )
        server = QSCServer(
            identity="server-node",
            signing_key=nodes["server"]["sk"],
            public_key=nodes["server"]["pk"],
            trust_store=self.server_trust_store,
        )

        mock = MockTransport()
        c_ep, s_ep = mock.get_endpoints()

        # Handshake
        c_res, s_res = await asyncio.gather(
            client.perform_handshake(c_ep),
            server.perform_handshake(s_ep),
        )

        # Payload stream transfer
        send_task = asyncio.create_task(client.send_payload(c_ep, payload))
        recv_task = asyncio.create_task(server.receive_payload(s_ep))
        send_res, received_data = await asyncio.gather(send_task, recv_task)

        assert received_data == payload, "Integrity check failed: received payload does not match source"

        return {
            "status": "SUCCESS",
            "client_handshake": c_res,
            "server_handshake": s_res,
            "payload_bytes": len(payload),
            "sha256": send_res["sha256"],
            "backend": self.backend,
        }


# Convenience aliases for standard submission grading
Problem = QuantumSafeChannelProblem
ProblemP1 = QuantumSafeChannelProblem

__all__ = [
    "QuantumSafeChannelProblem",
    "Problem",
    "ProblemP1",
    "QSCClient",
    "QSCServer",
    "PQCKeyEncapsulation",
    "PQCSignature",
    "TrustStore",
    "IdentityManager",
]
