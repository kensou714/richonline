# /// script
# requires-python = ">=3.12"
# dependencies = ["pytest"]
# ///
# How to run: uv run native-server/check_conformance.py
"""Executable differential checks; vectors are constructed, not wire captures."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "local-server"))
from codec import Channel, Frame, decode_inner, encode_frame, encode_inner

EXE = ROOT / "native-server/build-ninja/richnet_protocol.exe"
RULES = (ROOT / "native-server/rules/boss.lua").as_posix()


def invoke(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(EXE)],
        input=command + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=10,
    )


@pytest.mark.parametrize("channel", list(Channel))
@pytest.mark.parametrize("payload", [b"", b"abc", bytes(range(256))])
def test_frame_roundtrip_when_unknown_payload_is_supplied(
    channel: Channel, payload: bytes
) -> None:
    # Given: independent Python framing of an unknown business message.
    packet = encode_frame(Frame(0xDEADBEEF, payload), channel)
    # When: the built executable decodes and re-encodes it.
    result = invoke(f"frame {channel.value} - {packet.hex()}")
    # Then: every original byte survives.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == packet.hex()


@pytest.mark.parametrize("key", [0, 1, 128, 0x7FFFFFFF])
def test_transform_when_lobby_key_is_supplied(key: int) -> None:
    # Given: Python encoding with the chosen key.
    packet = encode_frame(Frame(7, b"abc"), Channel.LOBBY_C2S, key)
    # When: native framing uses the same transform.
    result = invoke(f"frame lobby_c2s {key} {packet.hex()}")
    # Then: the wire remains identical.
    assert result.stdout.strip() == packet.hex(), result.stderr


@pytest.mark.parametrize("size", [2, 3, 255, 509])
def test_inner_when_arbitrary_filler_is_supplied(size: int) -> None:
    # Given: explicitly distinct payload and filler bytes.
    plain = bytes(i % 256 for i in range(size))
    filler = bytes((i * 37) % 256 for i in range(size + 2))
    # When: the native encoder processes them.
    result = invoke(f"inner_encode {plain.hex()} {filler.hex()}")
    # Then: the independent Python codec yields the same bytes.
    assert result.stdout.strip() == encode_inner(plain, filler).hex(), result.stderr


def test_inner_decoder_when_python_encoder_boundary_is_exceeded() -> None:
    # Given: a canonical W=1024 independent vector for 510 bytes.
    encoded = bytes.fromhex("006b") * 510 + bytes.fromhex("006c0069")
    # When: the native decoder reads it.
    result = invoke(f"inner_decode {encoded.hex()}")
    # Then: decoding matches Python without extending the encoder bound.
    assert result.stdout.strip() == decode_inner(encoded).hex(), result.stderr


def test_stream_when_fragments_and_coalesced_frames_arrive() -> None:
    # Given: three explicit frames with an incomplete header and coalesced body.
    wire = encode_frame(Frame(7, b"abc"), Channel.LOBBY_C2S)
    chunks = [wire[:1], wire[1:6], wire[6:] + wire + wire[:8], wire[8:]]
    # When: the stream parser receives the fragments in order.
    result = invoke("stream lobby_c2s - " + " ".join(chunk.hex() for chunk in chunks))
    # Then: it emits exactly three byte-preserving frames.
    assert result.stdout.splitlines() == [wire.hex()] * 3, result.stderr


@pytest.mark.parametrize(
    "command,code",
    [
        ("frame game_c2s - efbeadde07000000", "invalid_frame_total"),
        ("frame game_c2s - efbeadde01001000", "invalid_frame_total"),
        ("frame game_c2s - efbeadde0b0000006162", "frame_total_mismatch"),
        ("stream game_c2s - efbeadde0b0000006162", "truncated_stream"),
        ("frame game_c2s 0 efbeadde0b000000616263", "game_transport_has_no_lobby_key"),
        ("inner_encode 0100 -", "inner_filler_length_mismatch"),
        ("inner_decode 006bff6c806b7f6e", "inner_declared_length_mismatch"),
    ],
)
def test_rejection_when_input_violates_codec_contract(command: str, code: str) -> None:
    # Given: a malformed message naming a particular boundary failure.
    # When: the actual executable processes it.
    result = invoke(command)
    # Then: the boundary returns the same stable error code.
    assert result.returncode == 1
    assert result.stderr.strip() == code


def test_envelope_when_signed_fields_and_nonzero_tail_are_supplied() -> None:
    # Given: the independently recovered constructor-profile vector.
    wire = "2b01000019000000ffff0800ff006bff6c806b7f6d11223344"
    # When: native parses all packed fields, then rebuilds the frame.
    result = invoke(f"envelope {wire}")
    # Then: signed fields, arbitrary filler, and explicit tail remain intact.
    assert result.stdout.strip() == wire, result.stderr


@pytest.mark.parametrize(
    "bucket,expected",
    [
        (i, "idle" if i < 80 else "mine" if i < 90 else "weapon:1046")
        for i in range(100)
    ],
)
def test_lua_policy_when_probability_bucket_is_injected(
    bucket: int, expected: str
) -> None:
    # Given: one deterministic bucket followed by three idle attempts.
    draws = f"{bucket},0,0,0,0" if bucket >= 90 else f"{bucket},0,0,0"
    # When: the embedded Lua runtime evaluates the production rules file.
    result = invoke(f'policy "{RULES}" {draws}')
    # Then: every threshold bucket agrees with the live 80/10/10 policy.
    assert result.stdout.splitlines() == [expected, "idle", "idle", "idle"], (
        result.stderr
    )


@pytest.mark.parametrize(
    "draws,expected",
    [
        ("80,89,80,89", ["mine"] * 4),
        (
            "90,0,99,1,95,2,90,0",
            ["weapon:1046", "weapon:1063", "weapon:1075", "weapon:1046"],
        ),
    ],
)
def test_lua_policy_when_four_same_category_draws_occur(
    draws: str, expected: list[str]
) -> None:
    # Given: four successful same-category random draws.
    # When: Lua evaluates the rules without inventory access.
    result = invoke(f'policy "{RULES}" {draws}')
    # Then: no implicit per-type cap changes the live baseline.
    assert result.stdout.splitlines() == expected, result.stderr


if __name__ == "__main__":
    raise SystemExit(
        pytest.main(
            [__file__, str(Path(__file__).with_name("check_boundaries.py")), "-q"]
        )
    )
