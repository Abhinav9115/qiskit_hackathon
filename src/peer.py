"""
Authenticated Peer Nodes (Client & Server) for QSC.
Executes the 1-RTT mutually authenticated handshake state machine with mutual Finished MACs,
session key derivation, genuine streaming chunk transfer, and replay protection.
"""

from __future__ import annotations

import io
import os
import time
import hmac
import hashlib
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, Union, BinaryIO

from src.crypto_suite import (
    PQCKeyEncapsulation,
    PQCSignature,
    derive_session_keys,
    compute_finished_mac,
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
    ServerFinished,
    compute_transcript_1,
    compute_transcript_2,
    compute_transcript_3,
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
    Base Peer implementing common cryptographic state and streaming frames.
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
    Client node initiating the mutually authenticated 1-RTT handshake.
    Marks session established only after verifying ServerFinished confirmation.
    """

    async def perform_handshake(self, transport) -> Dict[str, Any]:
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

        # 7. Compute Transcript_2 and derive session keys & Finished key
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

        # 8. Sign Transcript_2 and send ClientAuth with Client Finished MAC
        client_sig = self.sig_provider.sign(transcript_2, self.signing_key)
        client_finished_mac = compute_finished_mac(keys["k_finished"], "CLIENT", transcript_2)

        client_auth = ClientAuth(
            client_id=self.identity,
            signature=client_sig,
            mac_confirm=client_finished_mac,
        )
        client_auth_wire = client_auth.serialize()
        await transport.write_length_prefixed(client_auth_wire)

        # 9. Receive and Verify ServerFinished message before marking established
        server_finished_wire = await transport.read_length_prefixed()
        server_finished = ServerFinished.deserialize(server_finished_wire)

        transcript_3 = compute_transcript_3(transcript_2, client_auth_wire)
        expected_server_mac = compute_finished_mac(keys["k_finished"], "SERVER", transcript_3)

        if not hmac.compare_digest(expected_server_mac, server_finished.mac_confirm):
            raise QSCAuthenticationError("Server Finished confirmation MAC verification failed.")

        t1 = time.perf_counter_ns()
        self.handshake_latency_ns = t1 - t0

        # Channel mutually confirmed and established
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

    async def send_stream(self, transport, source: Union[bytes, str, Path, BinaryIO]) -> Dict[str, Any]:
        """
        Genuine streaming transmission: reads input in 64 KB chunks without buffering full payload.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_c2s"]
        base_iv = self.session_keys["iv_c2s_base"]
        session_id = self.session_id

        is_opened_here = False
        if isinstance(source, (str, Path)):
            stream = open(source, "rb")
            is_opened_here = True
        elif hasattr(source, "read"):
            stream = source
        else:
            stream = io.BytesIO(source)

        try:
            total_bytes = 0
            hasher = hashlib.sha256()

            while chunk := stream.read(MAX_CHUNK_PLAINTEXT_SIZE):
                total_bytes += len(chunk)
                hasher.update(chunk)
                frame = frame_chunk(
                    session_id=session_id,
                    key=key,
                    base_iv=base_iv,
                    counter=self.send_counter,
                    plaintext=chunk,
                    direction=DIRECTION_C2S,
                    final_flag=FLAG_INTERMEDIATE,
                )
                await transport.write_frame(frame)
                self.send_counter += 1

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
            if hasattr(transport, "flush"):
                await transport.flush()

            return {"total_bytes": total_bytes, "sha256": hasher.hexdigest()}
        finally:
            if is_opened_here:
                stream.close()

    async def receive_stream(self, transport, destination: Optional[Union[str, Path, BinaryIO]] = None) -> Dict[str, Any]:
        """
        Genuine streaming receiver: authenticates chunks, writes immediately to destination,
        maintaining bounded O(1) memory footprint.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_s2c"]
        base_iv = self.session_keys["iv_s2c_base"]
        session_id = self.session_id

        is_opened_here = False
        target_path: Optional[Path] = None
        temp_path: Optional[Path] = None
        if isinstance(destination, (str, Path)):
            target_path = Path(destination)
            temp_path = target_path.with_name(f"{target_path.name}.part_{os.getpid()}_{int(time.time()*1000)}")
            dest_stream = open(temp_path, "wb")
            is_opened_here = True
        elif destination is not None and hasattr(destination, "write"):
            dest_stream = destination
        else:
            dest_stream = io.BytesIO()

        try:
            total_bytes = 0
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
                        direction=DIRECTION_S2C,
                        final_flag=FLAG_INTERMEDIATE,
                    )
                    self.recv_counter = next_cnt
                    total_bytes += len(chunk)
                    hasher.update(chunk)
                    dest_stream.write(chunk)
                except QSCTamperError:
                    # Authenticate EOF frame
                    eof_chunk, next_cnt = unframe_chunk(
                        session_id=session_id,
                        key=key,
                        base_iv=base_iv,
                        expected_counter=self.recv_counter,
                        frame_bytes=frame,
                        direction=DIRECTION_S2C,
                        final_flag=FLAG_EOF,
                    )
                    self.recv_counter = next_cnt
                    verify_eof_payload(eof_chunk, total_bytes, hasher.digest())
                    break

            res = {"total_bytes": total_bytes, "sha256": hasher.hexdigest()}
            if destination is None:
                res["data"] = dest_stream.getvalue()
            elif is_opened_here and temp_path is not None and target_path is not None:
                dest_stream.close()
                is_opened_here = False
                temp_path.replace(target_path)
            return res
        finally:
            if is_opened_here:
                dest_stream.close()
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    async def send_payload(self, transport, data: bytes) -> Dict[str, Any]:
        """Convenience wrapper around send_stream."""
        return await self.send_stream(transport, data)

    async def receive_payload(self, transport) -> bytes:
        """Convenience wrapper around receive_stream returning bytes."""
        res = await self.receive_stream(transport, destination=None)
        return res["data"]


class QSCServer(QSCPeer):
    """
    Server node accepting connections, verifying ClientAuth, and returning ServerFinished.
    """

    async def perform_handshake(self, transport) -> Dict[str, Any]:
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

        # 8. Derive Session Keys & Validate Client Finished MAC
        keys = derive_session_keys(
            shared_secret=shared_secret,
            client_nonce=client_hello.nonce,
            server_nonce=server_nonce,
            transcript_2=transcript_2,
        )

        expected_client_mac = compute_finished_mac(keys["k_finished"], "CLIENT", transcript_2)
        if not hmac.compare_digest(expected_client_mac, client_auth.mac_confirm):
            raise QSCAuthenticationError("Client Finished MAC confirmation verification failed.")

        # 9. Compute Transcript_3 and Send ServerFinished message
        transcript_3 = compute_transcript_3(transcript_2, client_auth_wire)
        server_finished_mac = compute_finished_mac(keys["k_finished"], "SERVER", transcript_3)
        server_finished = ServerFinished(mac_confirm=server_finished_mac)
        await transport.write_length_prefixed(server_finished.serialize())

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

    async def receive_stream(self, transport, destination: Optional[Union[str, Path, BinaryIO]] = None) -> Dict[str, Any]:
        """
        Genuine streaming receiver: authenticates chunks and writes directly to file/stream.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_c2s"]
        base_iv = self.session_keys["iv_c2s_base"]
        session_id = self.session_id

        is_opened_here = False
        target_path: Optional[Path] = None
        temp_path: Optional[Path] = None
        if isinstance(destination, (str, Path)):
            target_path = Path(destination)
            temp_path = target_path.with_name(f"{target_path.name}.part_{os.getpid()}_{int(time.time()*1000)}")
            dest_stream = open(temp_path, "wb")
            is_opened_here = True
        elif destination is not None and hasattr(destination, "write"):
            dest_stream = destination
        else:
            dest_stream = io.BytesIO()

        try:
            total_bytes = 0
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
                    total_bytes += len(chunk)
                    hasher.update(chunk)
                    dest_stream.write(chunk)
                except QSCTamperError:
                    eof_chunk, next_cnt = unframe_chunk(
                        session_id=session_id,
                        key=key,
                        base_iv=base_iv,
                        expected_counter=self.recv_counter,
                        frame_bytes=frame,
                        direction=DIRECTION_C2S,
                        final_flag=FLAG_EOF,
                    )
                    self.recv_counter = next_cnt
                    verify_eof_payload(eof_chunk, total_bytes, hasher.digest())
                    break

            res = {"total_bytes": total_bytes, "sha256": hasher.hexdigest()}
            if destination is None:
                res["data"] = dest_stream.getvalue()
            elif is_opened_here and temp_path is not None and target_path is not None:
                dest_stream.close()
                is_opened_here = False
                temp_path.replace(target_path)
            return res
        finally:
            if is_opened_here:
                dest_stream.close()
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    async def send_stream(self, transport, source: Union[bytes, str, Path, BinaryIO]) -> Dict[str, Any]:
        """
        Genuine streaming sender from Server to Client.
        """
        assert self.session_keys is not None, "Handshake not established"
        key = self.session_keys["k_s2c"]
        base_iv = self.session_keys["iv_s2c_base"]
        session_id = self.session_id

        is_opened_here = False
        if isinstance(source, (str, Path)):
            stream = open(source, "rb")
            is_opened_here = True
        elif hasattr(source, "read"):
            stream = source
        else:
            stream = io.BytesIO(source)

        try:
            total_bytes = 0
            hasher = hashlib.sha256()

            while chunk := stream.read(MAX_CHUNK_PLAINTEXT_SIZE):
                total_bytes += len(chunk)
                hasher.update(chunk)
                frame = frame_chunk(
                    session_id=session_id,
                    key=key,
                    base_iv=base_iv,
                    counter=self.send_counter,
                    plaintext=chunk,
                    direction=DIRECTION_S2C,
                    final_flag=FLAG_INTERMEDIATE,
                )
                await transport.write_frame(frame)
                self.send_counter += 1

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
            if hasattr(transport, "flush"):
                await transport.flush()

            return {"total_bytes": total_bytes, "sha256": hasher.hexdigest()}
        finally:
            if is_opened_here:
                stream.close()

    async def receive_payload(self, transport) -> bytes:
        res = await self.receive_stream(transport, destination=None)
        return res["data"]

    async def send_payload(self, transport, data: bytes) -> Dict[str, Any]:
        return await self.send_stream(transport, data)
