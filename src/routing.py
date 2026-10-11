"""
Network Routing, Transport Dispatch, and Packet Framing Engine for QSC.
Manages TCP session routing, in-memory simulated topologies, MTU packet fragmentation,
and adversarial proxy routing (Scenario A unauthenticated vs. Scenario B QSC).
"""

from __future__ import annotations

import asyncio
import struct
import sys
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.transport import AsyncTCPTransport, MockTransport, TransportClosedError
from src.protocol import (
    frame_chunk,
    unframe_chunk,
    build_eof_payload,
    verify_eof_payload,
    MAX_CHUNK_PLAINTEXT_SIZE,
    DIRECTION_C2S,
    DIRECTION_S2C,
    FLAG_INTERMEDIATE,
    FLAG_EOF,
    QSCTamperError,
    QSCReplayError,
)
from src.attacker import ActiveMitMProxy


class PacketRouter:
    """
    Simulates network topologies, MTU fragmentation, and TCP reassembly routing.
    """

    def __init__(self, mtu: int = 1500, latency_ms: float = 0.0, jitter_ms: float = 0.0):
        self.mtu = mtu
        self.latency_ms = latency_ms
        self.jitter_ms = jitter_ms
        self.total_packets_routed = 0
        self.total_bytes_routed = 0
        self.fragmented_frames = 0

    def calculate_fragmentation(self, packet_bytes: int) -> int:
        """
        Calculates how many MTU fragments an application flight is split into.
        Standard IP overhead: 20B IP header + 20B TCP header = 40B header.
        MSS = MTU - 40.
        """
        mss = max(536, self.mtu - 40)
        fragments = (packet_bytes + mss - 1) // mss
        if fragments > 1:
            self.fragmented_frames += 1
        self.total_packets_routed += fragments
        self.total_bytes_routed += packet_bytes
        return fragments

    def create_routed_channel(self) -> MockTransport:
        """
        Instantiates a mock transport pre-configured with this router's MTU and latency.
        """
        return MockTransport(mtu=self.mtu, latency_ms=self.latency_ms)


class MitMRoutingProxy(ActiveMitMProxy):
    """
    Adversarial router intercepting packets between endpoints to demonstrate MitM mitigation.
    """
    pass


__all__ = [
    "PacketRouter",
    "MitMRoutingProxy",
    "AsyncTCPTransport",
    "MockTransport",
    "TransportClosedError",
]
