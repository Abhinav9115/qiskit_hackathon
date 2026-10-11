"""
Handshake state machine, transcript binding, and mutual authentication tests.
"""

import pytest
import asyncio
from pathlib import Path

from src.crypto_suite import PQCSignature
from src.trust_store import TrustStore, IdentityManager
from src.peer import QSCClient, QSCServer
from src.transport import MockTransport
from src.protocol import (
    ClientHello,
    ServerHello,
    ClientAuth,
    QSCAuthenticationError,
    QSCTamperError,
)


@pytest.mark.asyncio
async def test_handshake_mutual_auth_success(tmp_path):
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

    c_res, s_res = await asyncio.gather(
        client.perform_handshake(c_ep),
        server.perform_handshake(s_ep),
    )

    assert c_res["status"] == "ESTABLISHED"
    assert s_res["status"] == "ESTABLISHED"
    assert client.session_id == server.session_id
    assert client.session_keys["k_c2s"] == server.session_keys["k_c2s"]
    assert client.session_keys["k_s2c"] == server.session_keys["k_s2c"]


@pytest.mark.asyncio
async def test_handshake_rejects_unpinned_server(tmp_path):
    c_ts = TrustStore(tmp_path / "c_ts.json")  # server NOT pinned
    s_ts = TrustStore(tmp_path / "s_ts.json")
    mgr = IdentityManager(tmp_path / "keys")

    cpk, csk, cfp = mgr.generate_and_save("client-node")
    spk, ssk, sfp = mgr.generate_and_save("server-node")

    s_ts.pin_peer("client-node", cpk)

    client = QSCClient("client-node", csk, cpk, c_ts)
    server = QSCServer("server-node", ssk, spk, s_ts)

    mock = MockTransport()
    c_ep, s_ep = mock.get_endpoints()

    with pytest.raises(QSCAuthenticationError):
        await asyncio.gather(
            client.perform_handshake(c_ep),
            server.perform_handshake(s_ep),
        )


@pytest.mark.asyncio
async def test_handshake_rejects_unpinned_client(tmp_path):
    c_ts = TrustStore(tmp_path / "c_ts.json")
    s_ts = TrustStore(tmp_path / "s_ts.json")  # client NOT pinned
    mgr = IdentityManager(tmp_path / "keys")

    cpk, csk, cfp = mgr.generate_and_save("client-node")
    spk, ssk, sfp = mgr.generate_and_save("server-node")

    c_ts.pin_peer("server-node", spk)

    client = QSCClient("client-node", csk, cpk, c_ts)
    server = QSCServer("server-node", ssk, spk, s_ts)

    mock = MockTransport()
    c_ep, s_ep = mock.get_endpoints()

    with pytest.raises(QSCAuthenticationError):
        await asyncio.gather(
            client.perform_handshake(c_ep),
            server.perform_handshake(s_ep),
        )
