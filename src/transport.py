"""
Transport Layer for QSC.
Provides Asyncio TCP networking and in-memory mock transports with
support for MTU fragmentation, simulated latency jitter, and packet inspection.
"""

from __future__ import annotations

import asyncio
import struct
import io
from typing import Optional, List, Tuple


class TransportClosedError(Exception):
    pass


class AsyncTCPTransport:
    """
    Asynchronous TCP streaming transport with length-prefixed and framed message boundaries.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.bytes_sent = 0
        self.bytes_received = 0

    async def write_exact(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()
        self.bytes_sent += len(data)

    async def read_exact(self, n: int) -> bytes:
        data = await self.reader.readexactly(n)
        self.bytes_received += len(data)
        return data

    async def write_length_prefixed(self, data: bytes) -> None:
        """
        Sends 4-byte big-endian length prefix followed by data bytes.
        """
        prefix = struct.pack(">I", len(data))
        await self.write_exact(prefix + data)

    async def read_length_prefixed(self) -> bytes:
        prefix = await self.read_exact(4)
        length = struct.unpack(">I", prefix)[0]
        return await self.read_exact(length)

    async def write_frame(self, frame: bytes) -> None:
        """
        Writes a symmetric frame (which already contains a 4-byte length prefix for the chunk).
        Pipelines chunks across kernel socket buffer without blocking on every chunk.
        """
        self.writer.write(frame)
        self.bytes_sent += len(frame)
        tr = self.writer.transport
        if tr is not None and hasattr(tr, "get_write_buffer_size"):
            if tr.get_write_buffer_size() > 524288:  # 512 KB
                await self.writer.drain()
        else:
            await asyncio.sleep(0)

    async def flush(self) -> None:
        """Flushes remaining bytes to socket."""
        await self.writer.drain()

    async def read_frame(self) -> bytes:
        """
        Reads a full symmetric chunk frame:
        4B Chunk Length | 8B Counter | 12B IV | Ciphertext+Tag (Length Bytes)
        """
        header = await self.read_exact(24)
        chunk_length = struct.unpack(">I", header[:4])[0]
        body = await self.read_exact(chunk_length)
        return header + body

    async def close(self) -> None:
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


class MockTransport:
    """
    Bi-directional in-memory transport for fast deterministic testing,
    adversarial packet tampering, and MTU fragmentation simulation.
    """

    def __init__(
        self,
        mtu: int = 65536,
        latency_ms: float = 0.0,
        packet_loss_rate: float = 0.0,
        max_buffer_chunks: int = 8,
    ):
        self.mtu = mtu
        self.latency_ms = latency_ms
        self.packet_loss_rate = packet_loss_rate
        self.queue_c2s: asyncio.Queue[bytes] = asyncio.Queue(maxsize=max_buffer_chunks)
        self.queue_s2c: asyncio.Queue[bytes] = asyncio.Queue(maxsize=max_buffer_chunks)
        self.bytes_sent_c2s = 0
        self.bytes_sent_s2c = 0
        self.tamper_hook = None

    class Endpoint:
        def __init__(self, parent: MockTransport, is_client: bool):
            self.parent = parent
            self.is_client = is_client
            self.send_q = parent.queue_c2s if is_client else parent.queue_s2c
            self.recv_q = parent.queue_s2c if is_client else parent.queue_c2s
            self._read_buffer = bytearray()
            self.bytes_sent = 0
            self.bytes_received = 0
            self.is_closed = False

        async def write_exact(self, data: bytes) -> None:
            if self.is_closed:
                raise TransportClosedError("Cannot write to closed transport")
            if self.parent.latency_ms > 0:
                await asyncio.sleep(self.parent.latency_ms / 1000.0)

            # Apply adversarial tampering hook if active
            if self.parent.tamper_hook is not None:
                data = self.parent.tamper_hook(data, self.is_client)

            await self.send_q.put(data)
            self.bytes_sent += len(data)
            if self.is_client:
                self.parent.bytes_sent_c2s += len(data)
            else:
                self.parent.bytes_sent_s2c += len(data)

        async def read_exact(self, n: int) -> bytes:
            while len(self._read_buffer) < n:
                if self.is_closed and self.recv_q.empty():
                    raise TransportClosedError("Transport closed")
                chunk = await self.recv_q.get()
                if chunk == b"":
                    raise TransportClosedError("Connection closed by peer")
                self._read_buffer.extend(chunk)

            data = bytes(self._read_buffer[:n])
            del self._read_buffer[:n]
            self.bytes_received += len(data)
            return data

        async def write_length_prefixed(self, data: bytes) -> None:
            prefix = struct.pack(">I", len(data))
            await self.write_exact(prefix + data)

        async def read_length_prefixed(self) -> bytes:
            prefix = await self.read_exact(4)
            length = struct.unpack(">I", prefix)[0]
            return await self.read_exact(length)

        async def write_frame(self, frame: bytes) -> None:
            await self.write_exact(frame)

        async def read_frame(self) -> bytes:
            header = await self.read_exact(24)
            chunk_length = struct.unpack(">I", header[:4])[0]
            body = await self.read_exact(chunk_length)
            return header + body

        async def close(self) -> None:
            if not self.is_closed:
                self.is_closed = True
                await self.send_q.put(b"")

    def get_endpoints(self) -> Tuple[Endpoint, Endpoint]:
        return self.Endpoint(self, is_client=True), self.Endpoint(self, is_client=False)
