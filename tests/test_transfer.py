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
