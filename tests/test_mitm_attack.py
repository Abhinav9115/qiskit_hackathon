"""
Active MitM interception regression tests.
Verifies that tampering with KEM keys or transcripts causes handshake termination
and prevents data leakage.
"""

import pytest
import asyncio
from pathlib import Path

from src.trust_store import TrustStore, IdentityManager
from src.peer import QSCClient, QSCServer
from src.attacker import ActiveMitMProxy


@pytest.mark.asyncio
async def test_scenario_a_unauthenticated_kem_is_vulnerable():
    proxy = ActiveMitMProxy()
    secret = b"VULNERABLE_SECRET_VECTOR_12345"
    res = await proxy.run_scenario_a_unauthenticated_kem(secret)
    assert res["mitm_success"] is True
    assert res["intercepted_plaintext"] == secret.decode("utf-8")


@pytest.mark.asyncio
async def test_scenario_b_qsc_authenticated_rejects_mitm(tmp_path):
    c_ts = TrustStore(tmp_path / "c_ts.json")
    s_ts = TrustStore(tmp_path / "s_ts.json")
    mgr = IdentityManager(tmp_path / "keys")

    cpk, csk, cfp = mgr.generate_and_save("client-legit")
    spk, ssk, sfp = mgr.generate_and_save("server-legit")

    c_ts.pin_peer("server-legit", spk)
    s_ts.pin_peer("client-legit", cpk)

    client = QSCClient("client-legit", csk, cpk, c_ts)
    server = QSCServer("server-legit", ssk, spk, s_ts)

    proxy = ActiveMitMProxy()
    secret = b"PROTECTED_BY_QSC_MUTUAL_AUTH_2026"

    res = await proxy.run_scenario_b_qsc_authenticated(c_ts, s_ts, client, server, secret)
    assert res["handshake_aborted"] is True
    assert res["plaintext_compromised"] is False
    assert "SECURE" in res["security_verdict"]
