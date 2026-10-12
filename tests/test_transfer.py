"""
End-to-end round-trip payload streaming tests for 1 KB, 100 KB, and 10 MB files.
Asserts byte integrity and end-to-end SHA-256 validation.
"""

import pytest
import asyncio
from pathlib import Path

from src.trust_store import TrustStore, IdentityManager
from src.peer import QSCClient, QSCServer
from src.transport import MockTransport


@pytest.mark.asyncio
async def test_roundtrip_transfer_1kb(tmp_path):
    await _execute_transfer_test(tmp_path, "data/raw/payload_1kb.bin")


@pytest.mark.asyncio
async def test_roundtrip_transfer_100kb(tmp_path):
    await _execute_transfer_test(tmp_path, "data/raw/payload_100kb.bin")


@pytest.mark.asyncio
async def test_roundtrip_transfer_10mb(tmp_path):
    await _execute_transfer_test(tmp_path, "data/raw/payload_10mb.bin")


async def _execute_transfer_test(tmp_path: Path, file_path: str):
    with open(file_path, "rb") as f:
        data = f.read()

    c_ts = TrustStore(tmp_path / "c_ts.json")
    s_ts = TrustStore(tmp_path / "s_ts.json")
    mgr = IdentityManager(tmp_path / "keys")

    cpk, csk, cfp = mgr.generate_and_save("client-node")
    spk, ssk, sfp = mgr.generate_and_save("server-node")

    c_ts.pin_peer("server-node", spk)
    s_ts.pin_peer("client-node", cpk)

    client = QSCClient("client-node", csk, cpk, c_ts)
    server = QSCServer("server-node", ssk, spk, s_ts)

    mock = MockTransport()
    c_ep, s_ep = mock.get_endpoints()

    # Handshake
    await asyncio.gather(
        client.perform_handshake(c_ep),
        server.perform_handshake(s_ep),
    )

    # Stream transfer from Client to Server
    send_task = asyncio.create_task(client.send_payload(c_ep, data))
    recv_task = asyncio.create_task(server.receive_payload(s_ep))

    send_res, received_bytes = await asyncio.gather(send_task, recv_task)

    assert len(received_bytes) == len(data)
    assert received_bytes == data
    assert send_res["total_bytes"] == len(data)


@pytest.mark.asyncio
async def test_genuine_file_streaming_10mb(tmp_path):
    """
    Verifies that genuine file-to-file streaming across 10 MB payload operates
    with bounded memory (peak heap < 4 MB) without buffering entire plaintext.
    """
    import tracemalloc
    import hashlib

    src_file = Path("data/raw/payload_10mb.bin")
    dst_file = tmp_path / "streamed_10mb_out.bin"

    c_ts = TrustStore(tmp_path / "c_ts.json")
    s_ts = TrustStore(tmp_path / "s_ts.json")
    mgr = IdentityManager(tmp_path / "keys")

    cpk, csk, cfp = mgr.generate_and_save("client-node")
    spk, ssk, sfp = mgr.generate_and_save("server-node")

    c_ts.pin_peer("server-node", spk)
    s_ts.pin_peer("client-node", cpk)

    client = QSCClient("client-node", csk, cpk, c_ts)
    server = QSCServer("server-node", ssk, spk, s_ts)

    mock = MockTransport()
    c_ep, s_ep = mock.get_endpoints()

    await asyncio.gather(
        client.perform_handshake(c_ep),
        server.perform_handshake(s_ep),
    )

    tracemalloc.start()
    send_task = asyncio.create_task(client.send_stream(c_ep, src_file))
    recv_task = asyncio.create_task(server.receive_stream(s_ep, dst_file))

    send_res, recv_res = await asyncio.gather(send_task, recv_task)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert recv_res["total_bytes"] == 10485760
    assert recv_res["sha256"] == send_res["sha256"]
    assert dst_file.stat().st_size == 10485760
    # Assert peak memory during 10 MB transfer stayed strictly bounded (< 4 MB)
    assert peak_mem < 4 * 1024 * 1024, f"Peak memory {peak_mem} exceeded 4 MB bound"

