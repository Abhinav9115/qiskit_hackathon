"""Quantum-safe secure channel (PS-P1).

Protocol (mutual authentication, KEM key establishment, AEAD records)::

    C -> S : ClientHello  = {magic, kem_alg, sig_alg, nonce_c, kem_pk_eph} + Sig_C(label || hello)
    S -> C : ServerHello  = {nonce_s, kem_ct} + Sig_S(label || H(client_msg || server_body))
    both   : ss  = KEM shared secret
             keys = HKDF-SHA256(ikm=ss, salt=nonce_c||nonce_s, info=label||H(transcript)) -> 64 bytes
                    (32 B client->server key, 32 B server->client key)
    S -> C : Finished record (AES-256-GCM, seq 0) proving the key and the transcript
    C -> S : Finished record (AES-256-GCM, seq 0)
    then   : application data as AES-256-GCM records (optionally chunked / streamed)

Rules followed (Challenge Kit, PS-P1): NO cryptographic primitive is implemented here. All
primitives come from vetted libraries - ML-KEM / ML-DSA from liboqs (liboqs-python), and
HKDF / AES-GCM / ECDH / ECDSA from `cryptography`. Keys, nonces and KEM/signature randomness
always come from the OS CSPRNG (`secrets` or the libraries themselves) - never from seed 42.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import socket
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .problem import DEFAULT_SET, PARAMETER_SETS

# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------


class HandshakeError(Exception):
    """Authentication / protocol failure during the handshake."""


class RecordError(Exception):
    """Integrity failure, replay, reordering or truncation in the record layer."""


class BackendUnavailable(RuntimeError):
    """A required crypto library is not installed."""


# --------------------------------------------------------------------------------------
# Crypto backends (thin adapters over vetted libraries)
# --------------------------------------------------------------------------------------


class Backend:
    """KEM + signature interface used by the protocol."""

    name = "abstract"
    kem_alg = ""
    sig_alg = ""

    def kem_keygen(self) -> tuple[bytes, bytes]:  # (public, secret)
        raise NotImplementedError

    def kem_encaps(self, pk: bytes) -> tuple[bytes, bytes]:  # (ciphertext, shared_secret)
        raise NotImplementedError

    def kem_decaps(self, sk: bytes, ct: bytes) -> bytes:
        raise NotImplementedError

    def sig_keygen(self) -> tuple[bytes, bytes]:
        raise NotImplementedError

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        raise NotImplementedError


class OQSBackend(Backend):
    """ML-KEM (FIPS 203) and ML-DSA (FIPS 204) through the vetted liboqs binding.

    This backend fails closed when liboqs or a requested algorithm is unavailable. The project
    does not substitute locally implemented cryptography or synthetic standard-sized objects.
    """

    def __init__(self, kem_alg: str, sig_alg: str, name: str = "oqs"):
        self.kem_alg, self.sig_alg, self.name = kem_alg, sig_alg, name
        try:
            import oqs  # type: ignore
        except Exception as exc:
            raise BackendUnavailable(
                "PQC requires an installed liboqs-python binding with the native liboqs library; "
                "no simulated or homemade cryptographic fallback is used."
            ) from exc
        try:
            enabled_kem = set(oqs.get_enabled_kem_mechanisms())
            enabled_sig = set(oqs.get_enabled_sig_mechanisms())
        except Exception as exc:
            raise BackendUnavailable("liboqs is installed but its enabled algorithms could not be queried") from exc
        if kem_alg not in enabled_kem or sig_alg not in enabled_sig:
            raise BackendUnavailable(
                f"liboqs does not provide the requested algorithms: {kem_alg}, {sig_alg}"
            )
        self._oqs = oqs

    def kem_keygen(self):
        with self._oqs.KeyEncapsulation(self.kem_alg) as kem:
            pk = kem.generate_keypair()
            return bytes(pk), bytes(kem.export_secret_key())

    def kem_encaps(self, pk):
        with self._oqs.KeyEncapsulation(self.kem_alg) as kem:
            ct, ss = kem.encap_secret(pk)
            return bytes(ct), bytes(ss)

    def kem_decaps(self, sk, ct):
        with self._oqs.KeyEncapsulation(self.kem_alg, secret_key=sk) as kem:
            return bytes(kem.decap_secret(ct))

    def sig_keygen(self):
        with self._oqs.Signature(self.sig_alg) as sig:
            pk = sig.generate_keypair()
            return bytes(pk), bytes(sig.export_secret_key())

    def sign(self, sk, msg):
        with self._oqs.Signature(self.sig_alg, secret_key=sk) as sig:
            return bytes(sig.sign(msg))

    def verify(self, pk, msg, sig):
        with self._oqs.Signature(self.sig_alg) as s:
            try:
                return bool(s.verify(msg, sig, pk))
            except Exception:
                return False


_P256 = ec.SECP256R1()
_P256_POINT_LEN = 65  # uncompressed X9.62 point


class ClassicalBackend(Backend):
    """ECDH P-256 key agreement (as a KEM) + ECDSA P-256 signatures. Quantum-VULNERABLE baseline."""

    name = "classical-p256"
    kem_alg = "ECDH-P-256"
    sig_alg = "ECDSA-P-256"

    @staticmethod
    def _pub_bytes(pub) -> bytes:
        return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    @staticmethod
    def _load_pub(raw: bytes):
        return ec.EllipticCurvePublicKey.from_encoded_point(_P256, raw)

    @staticmethod
    def _sk_bytes(sk) -> bytes:
        return sk.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    def kem_keygen(self):
        sk = ec.generate_private_key(_P256)
        return self._pub_bytes(sk.public_key()), self._sk_bytes(sk)

    def kem_encaps(self, pk):
        eph = ec.generate_private_key(_P256)
        ss = eph.exchange(ec.ECDH(), self._load_pub(pk))
        return self._pub_bytes(eph.public_key()), ss

    def kem_decaps(self, sk, ct):
        key = serialization.load_der_private_key(sk, password=None)
        return key.exchange(ec.ECDH(), self._load_pub(ct))

    def sig_keygen(self):
        sk = ec.generate_private_key(_P256)
        return self._pub_bytes(sk.public_key()), self._sk_bytes(sk)

    def sign(self, sk, msg):
        key = serialization.load_der_private_key(sk, password=None)
        return key.sign(msg, ec.ECDSA(hashes.SHA256()))

    def verify(self, pk, msg, sig):
        try:
            self._load_pub(pk).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


class HybridBackend(Backend):
    """Hybrid KEM = ECDH P-256 || ML-KEM-768; signatures = ML-DSA-65.

    Public key / ciphertext are the concatenation (65-byte P-256 point first). The two shared
    secrets are concatenated and fed to HKDF with the transcript, so the session key is safe if
    EITHER component is unbroken (the same combiner idea used in hybrid TLS key exchange).
    """

    name = "hybrid-L3"

    def __init__(self, kem_alg: str = "ML-KEM-768", sig_alg: str = "ML-DSA-65"):
        self._classical = ClassicalBackend()
        self._pqc = OQSBackend(kem_alg, sig_alg, name="hybrid-pqc-part")
        self.kem_alg = f"ECDH-P-256+{kem_alg}"
        self.sig_alg = sig_alg

    def kem_keygen(self):
        cpk, csk = self._classical.kem_keygen()
        ppk, psk = self._pqc.kem_keygen()
        return cpk + ppk, struct.pack(">I", len(csk)) + csk + psk

    def kem_encaps(self, pk):
        cct, css = self._classical.kem_encaps(pk[:_P256_POINT_LEN])
        pct, pss = self._pqc.kem_encaps(pk[_P256_POINT_LEN:])
        return cct + pct, css + pss

    def kem_decaps(self, sk, ct):
        (n,) = struct.unpack_from(">I", sk, 0)
        csk, psk = sk[4:4 + n], sk[4 + n:]
        css = self._classical.kem_decaps(csk, ct[:_P256_POINT_LEN])
        pss = self._pqc.kem_decaps(psk, ct[_P256_POINT_LEN:])
        return css + pss

    def sig_keygen(self):
        return self._pqc.sig_keygen()

    def sign(self, sk, msg):
        return self._pqc.sign(sk, msg)

    def verify(self, pk, msg, sig):
        return self._pqc.verify(pk, msg, sig)


def get_backend(set_key: str = DEFAULT_SET) -> Backend:
    ps = PARAMETER_SETS[set_key]
    if set_key == "classical-p256":
        return ClassicalBackend()
    if set_key == "hybrid-L3":
        return HybridBackend()
    return OQSBackend(ps.kem, ps.sig, name=set_key)


# --------------------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------------------

MAGIC = b"QFF-PS-P1/v1"
LABEL_C = b"QFF-PS-P1/v1 client-hello"
LABEL_S = b"QFF-PS-P1/v1 server-hello"
LABEL_K = b"QFF-PS-P1/v1 traffic keys"
LABEL_F = b"QFF-PS-P1/v1 finished"
MAX_FRAME = 64 * 1024 * 1024


def pack(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def unpack(buf, expect: Optional[int] = None) -> list[bytes]:
    out, i, n = [], 0, len(buf)
    mv = memoryview(buf)
    while i < n:
        if i + 4 > n:
            raise HandshakeError("truncated field header")
        (ln,) = struct.unpack_from(">I", buf, i)
        i += 4
        if i + ln > n:
            raise HandshakeError("truncated field")
        out.append(bytes(mv[i:i + ln]))
        i += ln
    if expect is not None and len(out) != expect:
        raise HandshakeError(f"malformed message: expected {expect} fields, got {len(out)}")
    return out


class Wire:
    """Length-prefixed framing over a socket, counting every byte sent and received."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sent = 0
        self.received = 0

    def send_frame(self, *parts) -> None:
        total = sum(len(p) for p in parts)
        self.sock.sendall(struct.pack(">I", total))
        for p in parts:
            self.sock.sendall(p)
        self.sent += 4 + total

    def _recv_exact(self, n: int) -> bytearray:
        buf = bytearray(n)
        view = memoryview(buf)
        got = 0
        while got < n:
            r = self.sock.recv_into(view[got:], n - got)
            if r == 0:
                raise ConnectionError("peer closed the connection")
            got += r
        return buf

    def recv_frame(self) -> bytearray:
        (n,) = struct.unpack(">I", self._recv_exact(4))
        if n > MAX_FRAME:
            raise RecordError("frame too large")
        body = self._recv_exact(n)
        self.received += 4 + n
        return body

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@contextmanager
def _timed(info: dict, key: str):
    t0 = time.perf_counter_ns()
    try:
        yield
    finally:
        info[key + "_ns"] = info.get(key + "_ns", 0) + (time.perf_counter_ns() - t0)


# --------------------------------------------------------------------------------------
# Record layer (AES-256-GCM)
# --------------------------------------------------------------------------------------


class Session:
    """Established channel: per-direction AES-256-GCM keys and implicit counter nonces."""

    def __init__(self, wire: Wire, key_send: bytes, key_recv: bytes, transcript_hash: bytes):
        self.wire = wire
        self._aead_send = AESGCM(key_send)
        self._aead_recv = AESGCM(key_recv)
        self.seq_send = 0
        self.seq_recv = 0
        self.transcript_hash = transcript_hash
        self.enc_ns = 0
        self.dec_ns = 0
        self.records_sent = 0

    @staticmethod
    def _nonce(seq: int) -> bytes:
        return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")  # unique per key: keys are per direction

    def send_record(self, plaintext, final: bool = False) -> None:
        flag = b"\x01" if final else b"\x00"
        aad = self.seq_send.to_bytes(8, "big") + flag  # binds order and the end-of-stream marker
        t0 = time.perf_counter_ns()
        ct = self._aead_send.encrypt(self._nonce(self.seq_send), plaintext, aad)
        self.enc_ns += time.perf_counter_ns() - t0
        self.wire.send_frame(flag, ct)
        self.seq_send += 1
        self.records_sent += 1

    def recv_record(self) -> tuple[bytes, bool]:
        body = self.wire.recv_frame()
        if len(body) < 1 + 16 or body[0] not in (0, 1):
            raise RecordError("malformed record")
        flag = body[0]
        aad = self.seq_recv.to_bytes(8, "big") + bytes([flag])
        t0 = time.perf_counter_ns()
        try:
            pt = self._aead_recv.decrypt(self._nonce(self.seq_recv), memoryview(body)[1:], aad)
        except InvalidTag as exc:
            raise RecordError("AES-GCM authentication failed (tampered, replayed or reordered record)") from exc
        self.dec_ns += time.perf_counter_ns() - t0
        self.seq_recv += 1
        return pt, bool(flag)

    def send_stream(self, chunks: Iterable) -> int:
        """Send chunks as records; the last one carries the authenticated 'final' flag."""
        it = iter(chunks)
        try:
            prev = next(it)
        except StopIteration:
            prev = b""
        total = 0
        for nxt in it:
            self.send_record(prev, final=False)
            total += len(prev)
            prev = nxt
        self.send_record(prev, final=True)
        return total + len(prev)

    def recv_stream(self, sink: Callable[[bytes], None]) -> int:
        total = 0
        while True:
            pt, final = self.recv_record()
            sink(pt)
            total += len(pt)
            if final:
                return total


def file_chunks(path, chunk_bytes: Optional[int]):
    """Yield a file in `chunk_bytes` pieces (or whole when chunk_bytes is None)."""
    with open(path, "rb") as f:
        if chunk_bytes is None:
            yield f.read()
            return
        while True:
            block = f.read(chunk_bytes)
            if not block:
                return
            yield block


# --------------------------------------------------------------------------------------
# Handshake
# --------------------------------------------------------------------------------------


@dataclass
class Identity:
    """Long-term signature identity. The PUBLIC key is pinned by the peer (trust anchor)."""

    sig_pk: bytes
    sig_sk: bytes


def make_identity(backend: Backend) -> Identity:
    pk, sk = backend.sig_keygen()
    return Identity(pk, sk)


def _derive_keys(ss: bytes, nonce_c: bytes, nonce_s: bytes, th: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=nonce_c + nonce_s, info=LABEL_K + th).derive(ss)
    return okm[:32], okm[32:]  # (client->server, server->client)


def _finished(th: bytes) -> bytes:
    return hashlib.sha256(LABEL_F + th).digest()


def client_handshake(wire: Wire, backend: Backend, client_id: Identity, server_sig_pk: bytes,
                     info: Optional[dict] = None) -> Session:
    info = info if info is not None else {}
    nonce_c = secrets.token_bytes(32)
    with _timed(info, "client_kem_keygen"):
        kem_pk, kem_sk = backend.kem_keygen()
    hello = pack(MAGIC, backend.kem_alg.encode(), backend.sig_alg.encode(), nonce_c, kem_pk)
    with _timed(info, "client_sign"):
        sig_c = backend.sign(client_id.sig_sk, LABEL_C + hello)
    client_msg = pack(hello, sig_c)
    wire.send_frame(client_msg)
    info.update(size_client_hello=len(client_msg), size_kem_pk=len(kem_pk), size_sig_client=len(sig_c))

    server_msg = bytes(wire.recv_frame())
    body, sig_s = unpack(server_msg, 2)
    nonce_s, kem_ct = unpack(body, 2)
    info.update(size_server_hello=len(server_msg), size_kem_ct=len(kem_ct), size_sig_server=len(sig_s))
    th = hashlib.sha256(client_msg + body).digest()
    with _timed(info, "client_verify"):
        ok = backend.verify(server_sig_pk, LABEL_S + th, sig_s)
    if not ok:
        raise HandshakeError("server signature invalid - possible man-in-the-middle")
    with _timed(info, "client_kem_decaps"):
        ss = backend.kem_decaps(kem_sk, kem_ct)
    with _timed(info, "client_hkdf"):
        k_c2s, k_s2c = _derive_keys(ss, nonce_c, nonce_s, th)
    sess = Session(wire, key_send=k_c2s, key_recv=k_s2c, transcript_hash=th)

    fin, _ = sess.recv_record()  # server Finished (seq 0, key confirmation)
    if not hmac.compare_digest(fin, _finished(th)):
        raise HandshakeError("server Finished mismatch")
    sess.send_record(_finished(th))  # client Finished
    return sess


def server_handshake(wire: Wire, backend: Backend, server_id: Identity, client_sig_pk: bytes,
                     info: Optional[dict] = None) -> Session:
    info = info if info is not None else {}
    client_msg = bytes(wire.recv_frame())
    hello, sig_c = unpack(client_msg, 2)
    magic, kem_alg, sig_alg, nonce_c, kem_pk = unpack(hello, 5)
    if magic != MAGIC or kem_alg != backend.kem_alg.encode() or sig_alg != backend.sig_alg.encode():
        raise HandshakeError("protocol or algorithm mismatch (downgrade attempt?)")
    with _timed(info, "server_verify"):
        ok = backend.verify(client_sig_pk, LABEL_C + hello, sig_c)
    if not ok:
        raise HandshakeError("client signature invalid - possible man-in-the-middle")
    nonce_s = secrets.token_bytes(32)
    with _timed(info, "server_kem_encaps"):
        kem_ct, ss = backend.kem_encaps(kem_pk)
    body = pack(nonce_s, kem_ct)
    th = hashlib.sha256(client_msg + body).digest()
    with _timed(info, "server_sign"):
        sig_s = backend.sign(server_id.sig_sk, LABEL_S + th)
    server_msg = pack(body, sig_s)
    wire.send_frame(server_msg)
    with _timed(info, "server_hkdf"):
        k_c2s, k_s2c = _derive_keys(ss, nonce_c, nonce_s, th)
    sess = Session(wire, key_send=k_s2c, key_recv=k_c2s, transcript_hash=th)
    sess.send_record(_finished(th))  # server Finished
    fin, _ = sess.recv_record()  # client Finished
    if not hmac.compare_digest(fin, _finished(th)):
        raise HandshakeError("client Finished mismatch")
    return sess


# --------------------------------------------------------------------------------------
# Loopback transfer (real sockets, both endpoints in one process) + optional MITM relay
# --------------------------------------------------------------------------------------

CLOSE = object()  # tamper() sentinel: drop the frame and close the connection
Tamper = Callable[[str, int, bytes], "list[bytes] | object"]


@dataclass
class TransferResult:
    handshake_ok: bool = False
    payload_ok: bool = False
    error: Optional[str] = None
    handshake_ms: float = float("nan")
    transfer_ms: float = float("nan")
    encrypt_ms: float = float("nan")
    decrypt_ms: float = float("nan")
    bytes_handshake: int = 0
    bytes_records: int = 0
    bytes_total: int = 0
    payload_bytes: int = 0
    n_records: int = 0
    info: dict = field(default_factory=dict)


def _relay(src: socket.socket, dst: socket.socket, direction: str, tamper: Optional[Tamper]):
    wire_in, idx = Wire(src), 0
    try:
        while True:
            body = bytes(wire_in.recv_frame())
            out = [body] if tamper is None else tamper(direction, idx, body)
            idx += 1
            if out is CLOSE:
                break
            for b in out:  # type: ignore[union-attr]
                dst.sendall(struct.pack(">I", len(b)) + b)
    except (ConnectionError, OSError, RecordError):
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def run_loopback_transfer(
    backend: Backend,
    client_id: Identity,
    server_id: Identity,
    chunks: Iterable,
    expected_digest: Optional[bytes] = None,
    tamper: Optional[Tamper] = None,
    client_pins: Optional[bytes] = None,
    server_pins: Optional[bytes] = None,
    timeout: float = 120.0,
) -> TransferResult:
    """Client sends `chunks` to the server over a real socket pair; the server hashes what it gets.

    `client_pins` is the server public key the client trusts; `server_pins` is the client public
    key the server trusts (defaults: the real identities).
    """
    res = TransferResult()
    client_pin = client_pins if client_pins is not None else server_id.sig_pk
    server_pin = server_pins if server_pins is not None else client_id.sig_pk
    threads: list[threading.Thread] = []
    if tamper is None:
        c_sock, s_sock = socket.socketpair()
    else:  # insert an on-path attacker: client <-> a_c ... a_s <-> server
        c_sock, a_c = socket.socketpair()
        a_s, s_sock = socket.socketpair()
        threads.append(threading.Thread(target=_relay, args=(a_c, a_s, "c2s", tamper), daemon=True))
        threads.append(threading.Thread(target=_relay, args=(a_s, a_c, "s2c", tamper), daemon=True))
    for s in (c_sock, s_sock):
        s.settimeout(timeout)

    state: dict = {}
    sha = hashlib.sha256()
    cw, sw = Wire(c_sock), Wire(s_sock)
    c_info: dict = {}
    s_info: dict = {}

    def server():
        try:
            sess = server_handshake(sw, backend, server_id, server_pin, s_info)
            state["hs_server_done"] = time.perf_counter()
            state["server_hs_bytes"] = sw.sent + sw.received
            n = sess.recv_stream(sha.update)
            state["server_bytes"] = n
            state["xfer_done"] = time.perf_counter()
            state["dec_ns"] = sess.dec_ns
        except Exception as exc:  # noqa: BLE001 - reported to caller
            state["server_error"] = f"{type(exc).__name__}: {exc}"
            sw.close()

    t_server = threading.Thread(target=server, daemon=True)
    for t in threads:
        t.start()
    t_start = time.perf_counter()
    t_server.start()
    try:
        sess = client_handshake(cw, backend, client_id, client_pin, c_info)
        state["hs_client_done"] = time.perf_counter()
        state["client_hs_bytes"] = cw.sent + cw.received
        sess.send_stream(chunks)
        state["enc_ns"] = sess.enc_ns
        state["n_records"] = sess.records_sent
    except Exception as exc:  # noqa: BLE001
        state["client_error"] = f"{type(exc).__name__}: {exc}"
        cw.close()
    t_server.join(timeout)
    cw.close()
    sw.close()
    for t in threads:
        t.join(1.0)

    errs = [state[k] for k in ("client_error", "server_error") if k in state]
    res.error = " | ".join(errs) if errs else None
    res.info = {**c_info, **s_info}
    if "hs_client_done" in state and "hs_server_done" in state:
        res.handshake_ok = True
        res.handshake_ms = (max(state["hs_client_done"], state["hs_server_done"]) - t_start) * 1e3
        res.bytes_handshake = state["client_hs_bytes"]
    if res.handshake_ok and "xfer_done" in state and res.error is None:
        res.transfer_ms = (state["xfer_done"] - max(state["hs_client_done"], state["hs_server_done"])) * 1e3
        res.payload_bytes = state["server_bytes"]
        res.payload_ok = expected_digest is None or hmac.compare_digest(sha.digest(), expected_digest)
        res.encrypt_ms = state.get("enc_ns", 0) / 1e6
        res.decrypt_ms = state.get("dec_ns", 0) / 1e6
        res.bytes_total = cw.sent + cw.received
        res.bytes_records = res.bytes_total - res.bytes_handshake
        res.n_records = state.get("n_records", 0)
    return res


# --------------------------------------------------------------------------------------
# Man-in-the-middle demonstration
# --------------------------------------------------------------------------------------


def mitm_scenarios(backend: Backend) -> list[dict]:
    """Run attacks through an on-path relay and report whether each one was detected."""
    client_id, server_id = make_identity(backend), make_identity(backend)
    attacker_id = make_identity(backend)
    attacker_kem_pk, _ = backend.kem_keygen()
    payload = [b"top secret " * 64, b"second record"]
    digest = hashlib.sha256(b"".join(payload)).digest()

    def flip(b: bytes, pos: int = -1) -> bytes:
        ba = bytearray(b)
        ba[pos] ^= 0x01
        return bytes(ba)

    def swap_client_kem_pk(d, i, body):  # attacker substitutes its own KEM key and re-signs
        if d == "c2s" and i == 0:
            hello, _ = unpack(body, 2)
            magic, ka, sa, nonce, _pk = unpack(hello, 5)
            new_hello = pack(magic, ka, sa, nonce, attacker_kem_pk)
            return [pack(new_hello, backend.sign(attacker_id.sig_sk, LABEL_C + new_hello))]
        return [body]

    def flip_server_ct(d, i, body):  # corrupt the KEM ciphertext without re-signing
        if d == "s2c" and i == 0:
            return [flip(body, len(body) // 2)]
        return [body]

    def forge_server_hello(d, i, body):  # attacker answers with its own ciphertext + signature
        if d == "s2c" and i == 0:
            sbody, _ = unpack(body, 2)
            nonce_s, _ct = unpack(sbody, 2)
            fake_ct, _ = backend.kem_encaps(attacker_kem_pk)
            fake_body = pack(nonce_s, fake_ct)
            return [pack(fake_body, backend.sign(attacker_id.sig_sk, LABEL_S + b"x"))]
        return [body]

    def bitflip_record(d, i, body):
        return [flip(body)] if d == "c2s" and i == 2 else [body]

    def replay_record(d, i, body):
        return [body, body] if d == "c2s" and i == 2 else [body]

    def truncate(d, i, body):  # drop the final record and cut the connection
        if d == "c2s" and i >= 2 and body[0] == 1:
            return CLOSE
        return [body]

    cases = [
        ("no attacker (control)", None, "handshake + transfer succeed", None),
        ("attacker swaps client KEM key and re-signs", swap_client_kem_pk, "server rejects client signature", None),
        ("attacker corrupts server KEM ciphertext", flip_server_ct, "client rejects server signature", None),
        ("attacker forges ServerHello with own key", forge_server_hello, "client rejects server signature", None),
        ("attacker flips a bit in an encrypted record", bitflip_record, "AES-GCM tag check fails", None),
        ("attacker replays an encrypted record", replay_record, "AES-GCM tag check fails (sequence number)", None),
        ("attacker truncates the stream", truncate, "stream ends without authenticated final record", None),
    ]
    rows = []
    for name, tamper, expected, _ in cases:
        r = run_loopback_transfer(backend, client_id, server_id, payload, digest, tamper=tamper, timeout=10.0)
        delivered = r.payload_ok
        attack = tamper is not None
        rows.append({
            "scenario": name,
            "expected_defence": expected,
            "attack_detected": (not delivered) if attack else False,
            "payload_delivered_intact": delivered,
            "detail": r.error or "none",
            "pass": (not delivered) if attack else delivered,
        })
    return rows


# --------------------------------------------------------------------------------------
# Demo + self-test (python -m src.process ...)
# --------------------------------------------------------------------------------------


def tcp_demo(set_key: str, message: bytes, file: Optional[Path] = None, chunk_bytes: Optional[int] = 65536) -> dict:
    """Real localhost TCP demo: handshake, one chat message, optionally a file."""
    backend = get_backend(set_key)
    client_id, server_id = make_identity(backend), make_identity(backend)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    got: dict = {}

    def serve():
        conn, _ = srv.accept()
        w = Wire(conn)
        sess = server_handshake(w, backend, server_id, client_id.sig_pk)
        parts: list[bytes] = []
        sess.recv_stream(parts.append)
        got["message"] = b"".join(parts)
        sess.send_stream([b"ack: " + hashlib.sha256(got["message"]).hexdigest().encode()])
        if file is not None:
            h = hashlib.sha256()
            got["file_bytes"] = sess.recv_stream(h.update)
            got["file_sha256"] = h.hexdigest()
        w.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    cs = socket.create_connection(("127.0.0.1", port))
    cw = Wire(cs)
    info: dict = {}
    sess = client_handshake(cw, backend, client_id, server_id.sig_pk, info)
    sess.send_stream([message])
    parts: list[bytes] = []
    sess.recv_stream(parts.append)
    if file is not None:
        sess.send_stream(file_chunks(file, chunk_bytes))
    t.join(30)
    cw.close()
    srv.close()
    return {"parameter_set": PARAMETER_SETS[set_key].describe(), "server_got": got.get("message"),
            "server_ack": b"".join(parts).decode(), "file_sha256": got.get("file_sha256"),
            "handshake_sizes": {k: v for k, v in info.items() if k.startswith("size_")},
            "bytes_on_wire": cw.sent + cw.received}


def selftest(set_key: str = "classical-p256") -> bool:
    backend = get_backend(set_key)
    cid, sid = make_identity(backend), make_identity(backend)
    data = [secrets.token_bytes(5000), secrets.token_bytes(123)]
    r = run_loopback_transfer(backend, cid, sid, data, hashlib.sha256(b"".join(data)).digest())
    ok = r.handshake_ok and r.payload_ok
    rows = mitm_scenarios(backend)
    ok = ok and all(x["pass"] for x in rows)
    print(f"[{set_key}] handshake_ok={r.handshake_ok} payload_ok={r.payload_ok} "
          f"mitm_all_pass={all(x['pass'] for x in rows)}")
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="PS-P1 quantum-safe secure channel demo")
    ap.add_argument("command", choices=["demo", "mitm", "selftest"])
    ap.add_argument("--param-set", default=DEFAULT_SET, choices=sorted(PARAMETER_SETS))
    ap.add_argument("--message", default="hello from the quantum-safe channel")
    ap.add_argument("--file", type=Path, default=None, help="optional file to transfer")
    ap.add_argument("--chunk-bytes", type=int, default=65536)
    a = ap.parse_args(argv)
    try:
        if a.command == "demo":
            out = tcp_demo(a.param_set, a.message.encode(), a.file, a.chunk_bytes)
            for k, v in out.items():
                print(f"{k}: {v}")
        elif a.command == "mitm":
            for row in mitm_scenarios(get_backend(a.param_set)):
                print(row)
        else:
            raise SystemExit(0 if selftest(a.param_set) else 1)
    except BackendUnavailable as exc:
        raise SystemExit(f"ERROR: {exc}")


if __name__ == "__main__":
    main()
