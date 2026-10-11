"""
Monotonic counters, reordering, duplicate frame, and replayed message tests.
"""

import pytest
import os

from src.protocol import (
    frame_chunk,
    unframe_chunk,
    DIRECTION_C2S,
    FLAG_INTERMEDIATE,
    QSCReplayError,
)


def test_replay_duplicate_chunk_rejected():
    session_id = os.urandom(32)
    key = os.urandom(32)
    base_iv = os.urandom(12)

    frame_1 = frame_chunk(session_id, key, base_iv, counter=1, plaintext=b"Chunk 1", direction=DIRECTION_C2S)
    pt1, next_cnt = unframe_chunk(session_id, key, base_iv, expected_counter=1, frame_bytes=frame_1, direction=DIRECTION_C2S)
    assert pt1 == b"Chunk 1"
    assert next_cnt == 2

    # Replay frame_1 again
    with pytest.raises(QSCReplayError, match="Replay detected"):
        unframe_chunk(session_id, key, base_iv, expected_counter=next_cnt, frame_bytes=frame_1, direction=DIRECTION_C2S)


def test_reordered_chunk_rejected():
    session_id = os.urandom(32)
    key = os.urandom(32)
    base_iv = os.urandom(12)

    frame_2 = frame_chunk(session_id, key, base_iv, counter=2, plaintext=b"Chunk 2", direction=DIRECTION_C2S)

    # Receiver expects counter 1, but receives frame 2
    with pytest.raises(QSCReplayError, match="Out-of-order/gap detected"):
        unframe_chunk(session_id, key, base_iv, expected_counter=1, frame_bytes=frame_2, direction=DIRECTION_C2S)


def test_stale_counter_rejected():
    session_id = os.urandom(32)
    key = os.urandom(32)
    base_iv = os.urandom(12)

    # Receiver has progressed to counter 5
    old_frame = frame_chunk(session_id, key, base_iv, counter=3, plaintext=b"Old Chunk", direction=DIRECTION_C2S)

    with pytest.raises(QSCReplayError, match="Replay detected"):
        unframe_chunk(session_id, key, base_iv, expected_counter=5, frame_bytes=old_frame, direction=DIRECTION_C2S)
