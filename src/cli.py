"""
Unified CLI Entry Point (`qsc`) for Quantum-Safe Channel.
Supports keygen, trust store pinning, server, client, benchmark runner, and attack-demo.
"""

from __future__ import annotations

import os
import sys
import asyncio
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.trust_store import IdentityManager, TrustStore, compute_fingerprint
from src.peer import QSCClient, QSCServer
from src.transport import AsyncTCPTransport
from src.attacker import ActiveMitMProxy
from src.benchmark import execute_all_platforms
from src.visualization import generate_all_figures


def cmd_keygen(args):
    mgr = IdentityManager()
    pk, sk, fp = mgr.generate_and_save(args.identity)
    print(f"[+] Successfully generated ML-DSA-65 identity keypair for '{args.identity}'")
    print(f"    Public Key File:  {mgr.key_dir / f'{args.identity}.pub'}")
    print(f"    Secret Key File:  {mgr.key_dir / f'{args.identity}.key'}")
    print(f"    SHA-256 Fingerprint: {fp}")


def cmd_trust(args):
    ts = TrustStore()
    pubkey_path = Path(args.pubkey)
    if not pubkey_path.exists():
        print(f"[-] Error: Public key file not found: {pubkey_path}", file=sys.stderr)
        sys.exit(1)
    with open(pubkey_path, "rb") as f:
        pk = f.read()
    fp = ts.pin_peer(args.identity, pk)
    print(f"[+] Successfully pinned peer '{args.identity}' in local trust store")
    print(f"    Fingerprint: {fp}")


def cmd_serve(args):
    mgr = IdentityManager()
    ts = TrustStore()
    try:
        pk, sk, fp = mgr.load_identity(args.identity)
    except FileNotFoundError:
        print(f"[-] Error: Identity '{args.identity}' not found. Run 'qsc keygen --identity {args.identity}' first.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting QSC Server on port {args.port} as identity '{args.identity}' (Fingerprint: {fp[:16]}...)")

    async def handle_client(reader, writer):
        transport = AsyncTCPTransport(reader, writer)
        server = QSCServer(args.identity, sk, pk, ts)
        addr = writer.get_extra_info("peername")
        print(f"[+] Incoming connection from {addr}")
        try:
            res = await server.perform_handshake(transport)
            print(f"[+] Handshake established with peer '{res['peer']}' in {res['latency_ms']:.2f} ms")
            payload = await server.receive_payload(transport)
            print(f"[+] Received and verified {len(payload)} bytes of authenticated plaintext")
        except Exception as e:
            print(f"[-] Handshake / Payload failed: {e}")
        finally:
            await transport.close()

    async def main():
        srv = await asyncio.start_server(handle_client, "0.0.0.0", args.port)
        async with srv:
            await srv.serve_forever()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


def cmd_send(args):
    target = args.target.split(":")
    if len(target) != 2:
        print("[-] Target must be host:port", file=sys.stderr)
        sys.exit(1)
    host, port = target[0], int(target[1])

    mgr = IdentityManager()
    ts = TrustStore()
    client_id = getattr(args, "identity", "client-node")
    try:
        pk, sk, fp = mgr.load_identity(client_id)
    except FileNotFoundError:
        pk, sk, fp = mgr.generate_and_save(client_id)

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[-] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    with open(file_path, "rb") as f:
        data = f.read()

    print(f"[*] Connecting to {host}:{port} as '{client_id}'...")

    async def run():
        reader, writer = await asyncio.open_connection(host, port)
        transport = AsyncTCPTransport(reader, writer)
        client = QSCClient(client_id, sk, pk, ts)
        try:
            res = await client.perform_handshake(transport)
            print(f"[+] Handshake established with server '{res['peer']}' in {res['latency_ms']:.2f} ms")
            s_res = await client.send_payload(transport, data)
            print(f"[+] Streamed {s_res['total_bytes']} bytes. Verified SHA-256: {s_res['sha256']}")
        finally:
            await transport.close()

    asyncio.run(run())


def cmd_attack_demo(args):
    print("=" * 70)
    print("QSC ADVERSARIAL HEADLINE ATTACK DEMONSTRATION")
    print("=" * 70)
    secret_text = b"CONFIDENTIAL_QUANTUM_PATENT_DOCUMENT_QFF2026_TRACK5"
    proxy = ActiveMitMProxy()

    print("\n--- [Scenario A: Unauthenticated Ephemeral KEM] ---")
    print("Adversary intercepts network exchange, substitutes KEM public key,")
    print("and transparently decapsulates session secrets.\n")
    res_a = asyncio.run(proxy.run_scenario_a_unauthenticated_kem(secret_text))
    print(f"  * Intercepted Payload: '{res_a['intercepted_plaintext']}'")
    print(f"  * Original Payload:    '{res_a['original_plaintext']}'")
    print(f"  * MitM Success:        {res_a['mitm_success']}")
    print(f"  * Security Verdict:    \033[91m{res_a['security_verdict']}\033[0m")

    print("\n--- [Scenario B: QSC Mutually Authenticated Channel] ---")
    print("Adversary attempts identical KEM key substitution on QSC protocol.")
    print("Server signs transcript hash containing client's ephemeral key.")
    print("Client verifies against pinned long-term ML-DSA-65 identity key.\n")

    # Setup isolated test trust store
    ts_dir = Path("results/attack_trust")
    ts_dir.mkdir(parents=True, exist_ok=True)
    c_ts = TrustStore(ts_dir / "client_ts.json")
    s_ts = TrustStore(ts_dir / "server_ts.json")
    mgr = IdentityManager(ts_dir / "keys")
    cpk, csk, cfp = mgr.generate_and_save("client-legit")
    spk, ssk, sfp = mgr.generate_and_save("server-legit")
    c_ts.pin_peer("server-legit", spk)
    s_ts.pin_peer("client-legit", cpk)

    client = QSCClient("client-legit", csk, cpk, c_ts)
    server = QSCServer("server-legit", ssk, spk, s_ts)

    res_b = asyncio.run(proxy.run_scenario_b_qsc_authenticated(c_ts, s_ts, client, server, secret_text))
    print(f"  * Attack Interception: {res_b['mitm_attempt']}")
    print(f"  * Handshake Aborted:   {res_b['handshake_aborted']}")
    print(f"  * Error Caught:        {res_b['error_encountered']}")
    print(f"  * Plaintext Leaked:    {res_b['plaintext_compromised']}")
    print(f"  * Security Verdict:    \033[92m{res_b['security_verdict']}\033[0m")
    print("\n" + "=" * 70)


def cmd_bench(args):
    print(f"[*] Starting QSC Benchmarking Engine (Platform mode: {args.platform})...")
    execute_all_platforms()
    generate_all_figures()


def main():
    parser = argparse.ArgumentParser(prog="qsc", description="QSC: Quantum-Safe Secure Channel CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate local ML-DSA-65 identity keypair")
    p_keygen.add_argument("--identity", required=True, help="Identity label for node")

    # trust
    p_trust = subparsers.add_parser("trust", help="Pin a peer's public key in trust store")
    p_trust.add_argument("--identity", required=True, help="Peer identity label")
    p_trust.add_argument("--pubkey", required=True, help="Path to peer's .pub file")

    # serve
    p_serve = subparsers.add_parser("serve", help="Start authenticated receiving server")
    p_serve.add_argument("--port", type=int, default=8443, help="TCP port to listen on")
    p_serve.add_argument("--identity", required=True, help="Server identity label")

    # send
    p_send = subparsers.add_parser("send", help="Send an encrypted authenticated file")
    p_send.add_argument("--target", required=True, help="Server address host:port")
    p_send.add_argument("--file", required=True, help="Path to file to transmit")
    p_send.add_argument("--identity", default="client-node", help="Client identity label")

    # attack-demo
    subparsers.add_parser("attack-demo", help="Demonstrate MitM attack rejection")

    # bench
    p_bench = subparsers.add_parser("bench", help="Run multi-platform benchmark suite")
    p_bench.add_argument("--platform", default="all", help="Target platform (A, B, D, ablation, all)")

    args = parser.parse_args()

    handlers = {
        "keygen": cmd_keygen,
        "trust": cmd_trust,
        "serve": cmd_serve,
        "send": cmd_send,
        "attack-demo": cmd_attack_demo,
        "bench": cmd_bench,
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
