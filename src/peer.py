"""
Authenticated Peer Nodes (Client & Server) for QSC.
Executes the 1-RTT mutually authenticated handshake state machine,
session key derivation, encrypted chunk streaming, and replay protection.
"""

from __future__ import annotations

import os
import time
import hashlib
from typing import Optional, Tuple, Dict, Any, AsyncIterator

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    derive_session_keys,
    sha256_digest,
)
from src.protocol import (
    PROTOCOL_VERSION,
    CIPHERSUITE_ML_KEM_768_ML_DSA_65_AES256GCM,
    MAX_CHUNK_PLAINTEXT_SIZE,
    DIRECTION_C2S,
    DIRECTION_S2C,
    FLAG_INTERMEDIATE,
    FLAG_EOF,
    ClientHello,
    ServerHello,
    ClientAuth,
    compute_transcript_1,
    compute_transcript_2,
    frame_chunk,
    unframe_chunk,
    build_eof_payload,
    verify_eof_payload,
    QSCProtocolError,
    QSCTamperError,
    QSCReplayError,
    QSCAuthenticationError,
)
from src.trust_store import TrustStore


class QSCPeer:
    """
    Base Peer implementing common state, session keys, and streaming frames.
    """

    def __init__(
        self,
        identity: str,
        signing_key: bytes,
        public_key: bytes,
        trust_store: TrustStore,
    ):
        self.identity = identity
        self.signing_key = signing_key
        self.public_key = public_key
        self.trust_store = trust_store

        self.kem_provider = PQCKeyEncapsulation()
        self.sig_provider = PQCSignature()

        # Session State
        self.session_keys: Optional[Dict[str, bytes]] = None
        self.session_id: Optional[bytes] = None
        self.peer_identity: Optional[str] = None
        self.peer_public_key: Optional[bytes] = None
        self.send_counter = 1
        self.recv_counter = 1
        self.handshake_latency_ns = 0

    @property
    def is_established(self) -> bool:
        return self.session_keys is not None


class QSCClient(QSCPeer):
    """
    Client node initiating the 1-RTT handshake and secure channel session.
    """

    async def perform_handshake(self, transport) -> Dict[str, Any]:
        """
        Executes full 1-RTT handshake with mutual authentication against Server.
        """
        t0 = time.perf_counter_ns()

        # 1. Ephemeral ML-KEM-768 generation & Client Nonce
        kem_pk, kem_sk = self.kem_provider.generate_keypair()
        client_nonce = os.urandom(32)
        client_ts = int(time.time() * 1000)

        # 2. Serialize and send ClientHello
        client_hello = ClientHello(
            version=PROTOCOL_VERSION,
            suite_id=CIPHERSUITE_ML_KEM_768_ML_DSA_65_AES256GCM,
            nonce=client_nonce,
            kem_public_key=kem_pk,
            timestamp=client_ts,
        )
        client_hello_wire = client_hello.serialize()
        await transport.write_length_prefixed(client_hello_wire)

        # 3. Receive ServerHello
        server_hello_wire = await transport.read_length_prefixed()
        server_hello = ServerHello.deserialize(server_hello_wire)

        # 4. Identity verification against TrustStore
        pinned_server_pk = self.trust_store.get_peer_key(server_hello.server_id)
        if pinned_server_pk is None:
            raise QSCAuthenticationError(
                f"Untrusted server identity '{server_hello.server_id}': not pinned in local trust store."
            )

        # 5. Verify Server Transcript Signature over Transcript_1
        transcript_1 = compute_transcript_1(
            client_hello_wire=client_hello_wire,
            kem_ciphertext=server_hello.kem_ciphertext,
            server_nonce=server_hello.nonce,
            server_id=server_hello.server_id,
        )
        if not self.sig_provider.verify(transcript_1, server_hello.signature, pinned_server_pk):
            raise QSCTamperError(
                f"Server transcript signature verification failed for '{server_hello.server_id}'"
            )

        # 6. Decapsulate Shared Secret SS
        shared_secret = self.kem_provider.decap_secret(server_hello.kem_ciphertext, kem_sk)

        # 7. Compute Transcript_2 and derive session keys
        transcript_2 = compute_transcript_2(
            transcript_1=transcript_1,
            server_hello_wire=server_hello_wire,
            client_id=self.identity,
        )
        keys = derive_session_keys(
            shared_secret=shared_secret,
            client_nonce=client_nonce,
            server_nonce=server_hello.nonce,
            transcript_2=transcript_2,
        )

        # 8. Sign Transcript_2 and send ClientAuth
        client_sig = self.sig_provider.sign(transcript_2, self.signing_key)
        client_auth = ClientAuth(
            client_id=self.identity,
            signature=client_sig,
            mac_confirm=keys["mac_confirm"],
        )
        client_auth_wire = client_auth.serialize()
        await transport.write_length_prefixed(client_auth_wire)

        t1 = time.perf_counter_ns()
        self.handshake_latency_ns = t1 - t0

        # Save session context
        self.session_keys = keys
        self.session_id = keys["session_id"]
        self.peer_identity = server_hello.server_id
        self.peer_public_key = pinned_server_pk
        self.send_counter = 1
        self.recv_counter = 1

        return {
            "status": "ESTABLISHED",
            "peer": server_hello.server_id,
            "session_id_hex": keys["session_id"].hex(),
            "latency_ms": self.handshake_latency_ns / 1_000_000.0,
        }

    async def send_payload(self, transport, data: bytes) -> Dict[str, Any]:
        """
        Streams data in 64 KB authenticated chunks from Client to Server.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_c2s"]
        base_iv = self.session_keys["iv_c2s_base"]
        session_id = self.session_id

        total_bytes = len(data)
        hasher = hashlib.sha256()
        offset = 0

        # Send intermediate chunks
        while offset < total_bytes:
            chunk_data = data[offset : offset + MAX_CHUNK_PLAINTEXT_SIZE]
            hasher.update(chunk_data)
            frame = frame_chunk(
                session_id=session_id,
                key=key,
                base_iv=base_iv,
                counter=self.send_counter,
                plaintext=chunk_data,
                direction=DIRECTION_C2S,
                final_flag=FLAG_INTERMEDIATE,
            )
            await transport.write_frame(frame)
            self.send_counter += 1
            offset += len(chunk_data)

        # Send terminal authenticated EOF chunk
        eof_payload = build_eof_payload(total_bytes, hasher.digest())
        eof_frame = frame_chunk(
            session_id=session_id,
            key=key,
            base_iv=base_iv,
            counter=self.send_counter,
            plaintext=eof_payload,
            direction=DIRECTION_C2S,
            final_flag=FLAG_EOF,
        )
        await transport.write_frame(eof_frame)
        self.send_counter += 1

        return {"total_bytes": total_bytes, "sha256": hasher.hexdigest()}

    async def receive_payload(self, transport) -> bytes:
        """
        Receives stream from Server to Client.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_s2c"]
        base_iv = self.session_keys["iv_s2c_base"]
        session_id = self.session_id

        buf = bytearray()
        hasher = hashlib.sha256()

        while True:
            frame = await transport.read_frame()
            # Inspect final_flag from AAD or attempt intermediate first
            try:
                chunk, next_cnt = unframe_chunk(
                    session_id=session_id,
                    key=key,
                    base_iv=base_iv,
                    expected_counter=self.recv_counter,
                    frame_bytes=frame,
                    direction=DIRECTION_S2C,
                    final_flag=FLAG_INTERMEDIATE,
                )
                self.recv_counter = next_cnt
                buf.extend(chunk)
                hasher.update(chunk)
            except QSCTamperError:
                # Try EOF flag
                chunk, next_cnt = unframe_chunk(
                    session_id=session_id,
                    key=key,
                    base_iv=base_iv,
                    expected_counter=self.recv_counter,
                    frame_bytes=frame,
                    direction=DIRECTION_S2C,
                    final_flag=FLAG_EOF,
                )
                self.recv_counter = next_cnt
                verify_eof_payload(chunk, len(buf), hasher.digest())
                break

        return bytes(buf)


class QSCServer(QSCPeer):
    """
    Server node accepting connections and completing mutual authentication.
    """

    async def perform_handshake(self, transport) -> Dict[str, Any]:
        """
        Executes Server side of the 1-RTT handshake.
        """
        t0 = time.perf_counter_ns()

        # 1. Read ClientHello
        client_hello_wire = await transport.read_length_prefixed()
        client_hello = ClientHello.deserialize(client_hello_wire)

        # 2. Encapsulate SS against client's ephemeral KEM key & generate Server Nonce
        ct_kem, shared_secret = self.kem_provider.encap_secret(client_hello.kem_public_key)
        server_nonce = os.urandom(32)
        server_ts = int(time.time() * 1000)

        # 3. Compute Transcript_1 and sign with Server SK
        transcript_1 = compute_transcript_1(
            client_hello_wire=client_hello_wire,
            kem_ciphertext=ct_kem,
            server_nonce=server_nonce,
            server_id=self.identity,
        )
        server_sig = self.sig_provider.sign(transcript_1, self.signing_key)

        # 4. Serialize and send ServerHello
        server_hello = ServerHello(
            kem_ciphertext=ct_kem,
            nonce=server_nonce,
            server_id=self.identity,
            signature=server_sig,
            timestamp=server_ts,
        )
        server_hello_wire = server_hello.serialize()
        await transport.write_length_prefixed(server_hello_wire)

        # 5. Read ClientAuth
        client_auth_wire = await transport.read_length_prefixed()
        client_auth = ClientAuth.deserialize(client_auth_wire)

        # 6. Verify Client Identity against TrustStore
        pinned_client_pk = self.trust_store.get_peer_key(client_auth.client_id)
        if pinned_client_pk is None:
            raise QSCAuthenticationError(
                f"Untrusted client identity '{client_auth.client_id}': not pinned in local trust store."
            )

        # 7. Compute Transcript_2 and verify Client Signature
        transcript_2 = compute_transcript_2(
            transcript_1=transcript_1,
            server_hello_wire=server_hello_wire,
            client_id=client_auth.client_id,
        )
        if not self.sig_provider.verify(transcript_2, client_auth.signature, pinned_client_pk):
            raise QSCTamperError(
                f"Client transcript signature verification failed for '{client_auth.client_id}'"
            )

        # 8. Derive Session Keys & Validate Key Confirmation MAC
        keys = derive_session_keys(
            shared_secret=shared_secret,
            client_nonce=client_hello.nonce,
            server_nonce=server_nonce,
            transcript_2=transcript_2,
        )
        if keys["mac_confirm"] != client_auth.mac_confirm:
            raise QSCAuthenticationError("Client key confirmation MAC verification failed.")

        t1 = time.perf_counter_ns()
        self.handshake_latency_ns = t1 - t0

        # Save session context
        self.session_keys = keys
        self.session_id = keys["session_id"]
        self.peer_identity = client_auth.client_id
        self.peer_public_key = pinned_client_pk
        self.send_counter = 1
        self.recv_counter = 1

        return {
            "status": "ESTABLISHED",
            "peer": client_auth.client_id,
            "session_id_hex": keys["session_id"].hex(),
            "latency_ms": self.handshake_latency_ns / 1_000_000.0,
        }

    async def receive_payload(self, transport) -> bytes:
        """
        Receives stream from Client to Server.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_c2s"]
        base_iv = self.session_keys["iv_c2s_base"]
        session_id = self.session_id

        buf = bytearray()
        hasher = hashlib.sha256()

        while True:
            frame = await transport.read_frame()
            try:
                chunk, next_cnt = unframe_chunk(
                    session_id=session_id,
                    key=key,
                    base_iv=base_iv,
                    expected_counter=self.recv_counter,
                    frame_bytes=frame,
                    direction=DIRECTION_C2S,
                    final_flag=FLAG_INTERMEDIATE,
                )
                self.recv_counter = next_cnt
                buf.extend(chunk)
                hasher.update(chunk)
            except QSCTamperError:
                # Try EOF flag
                chunk, next_cnt = unframe_chunk(
                    session_id=session_id,
                    key=key,
                    base_iv=base_iv,
                    expected_counter=self.recv_counter,
                    frame_bytes=frame,
                    direction=DIRECTION_C2S,
                    final_flag=FLAG_EOF,
                )
                self.recv_counter = next_cnt
                verify_eof_payload(chunk, len(buf), hasher.digest())
                break

        return bytes(buf)

    async def send_payload(self, transport, data: bytes) -> Dict[str, Any]:
        """
        Streams data in 64 KB authenticated chunks from Server to Client.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_s2c"]
        base_iv = self.session_keys["iv_s2c_base"]
        session_id = self.session_id

        total_bytes = len(data)
        hasher = hashlib.sha256()
        offset = 0

        while offset < total_bytes:
            chunk_data = data[offset : offset + MAX_CHUNK_PLAINTEXT_SIZE]
            hasher.update(chunk_data)
            frame = frame_chunk(
                session_id=session_id,
                key=key,
                base_iv=base_iv,
                counter=self.send_counter,
                plaintext=chunk_data,
                direction=DIRECTION_S2C,
                final_flag=FLAG_INTERMEDIATE,
            )
            await transport.write_frame(frame)
            self.send_counter += 1
            offset += len(chunk_data)

        eof_payload = build_eof_payload(total_bytes, hasher.digest())
        eof_frame = frame_chunk(
            session_id=session_id,
            key=key,
            base_iv=base_iv,
            counter=self.send_counter,
            plaintext=eof_payload,
            direction=DIRECTION_S2C,
            final_flag=FLAG_EOF,
        )
        await transport.write_frame(eof_frame)
        self.send_counter += 1

        return {"total_bytes": total_bytes, "sha256": hasher.hexdigest()}
