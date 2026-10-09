# /// script
# requires-python = ">=3.12"
# dependencies = ["pytest"]
# ///
# How to run: uv run --with pytest python -m pytest native-server/check_boundaries.py
"""Direct native observations prevent two incorrect transforms cancelling out."""

from __future__ import annotations

from pathlib import Path

import pytest
from check_conformance import ROOT, RULES, invoke
from codec import Channel, Frame, encode_frame


@pytest.mark.parametrize("key", [0, 1, 128, 0x7FFFFFFF])
def test_plain_payload_when_keyed_frame_is_decoded(key: int) -> None:
    # Given: independently encoded lobby payload with non-palindromic bytes.
    packet = encode_frame(Frame(7, b"abc"), Channel.LOBBY_C2S, key)
    # When: native exposes the actual decoded fields.
    result = invoke(f"frame_decode lobby_c2s {key} {packet.hex()}")
    # Then: the type and plaintext agree directly with the independent input.
    assert result.stdout.strip() == "7 616263", result.stderr


@pytest.mark.parametrize("channel", list(Channel))
def test_wire_when_explicit_fields_are_encoded(channel: Channel) -> None:
    # Given: an unsigned type and bytes extending above ASCII.
    payload = bytes.fromhex("80feff0102")
    # When: native creates a frame from the explicit type and plaintext.
    result = invoke(f"frame_encode {channel.value} - 4294967295 {payload.hex()}")
    # Then: the wire agrees with the Python encoder without native decode.
    assert (
        result.stdout.strip() == encode_frame(Frame(0xFFFFFFFF, payload), channel).hex()
    ), result.stderr


def test_envelope_fields_when_negative_tags_and_tail_are_decoded() -> None:
    # Given: a literal vector whose fields cannot default to zero.
    wire = "2b01000019000000ffff0800ff006bff6c806b7f6d11223344"
    # When: native exposes every field in the known constructor profile.
    result = invoke(f"envelope_decode {wire}")
    # Then: tags and wire buffers retain their actual values.
    assert result.stdout.strip() == "-1 -1 006bff6c806b7f6d 11223344", result.stderr


@pytest.mark.parametrize(
    "wire",
    [
        "430200001400000005000000fb00000040000000",
        "5fd8a110f70200000c0000007d000000",
    ],
)
def test_handshake_when_transform_is_requested(wire: str) -> None:
    # Given: a recovered plaintext handshake frame.
    channel = "lobby_c2s" if wire.startswith("5fd8") else "lobby_s2c"
    # When: the caller incorrectly supplies a later lobby key.
    result = invoke(f"frame {channel} 100 {wire}")
    # Then: the handshake cannot be silently encrypted.
    assert result.stderr.strip() == "handshake_payload_must_remain_plain"


def test_frame_when_local_resource_limit_is_reached() -> None:
    # Given: a frame exactly at the shared local 1 MiB policy boundary.
    packet = encode_frame(Frame(9, b"\xff" * ((1 << 20) - 8)), Channel.GAME_C2S)
    # When: the actual executable parses and rebuilds it.
    result = invoke(f"frame game_c2s - {packet.hex()}")
    # Then: a valid boundary frame is retained byte for byte.
    assert result.stdout.strip() == packet.hex(), result.stderr


def test_resource_payload_when_rankings_fixture_is_framed() -> None:
    # Given: a genuine decoded client resource, explicitly wrapped as a constructed frame.
    payload = (
        ROOT / "protocol-analysis/inquiry-rankings/13764.decoded.bin"
    ).read_bytes()
    packet = encode_frame(Frame(0xDEADBEEF, payload), Channel.GAME_C2S)
    # When: native handles the arbitrary resource bytes as an unknown message.
    result = invoke(f"frame_decode game_c2s - {packet.hex()}")
    # Then: no guessed business layout discards or replaces bytes.
    assert result.stdout.strip() == f"3735928559 {payload.hex()}", result.stderr


def test_config_override_when_lua_file_supplies_distinct_rules(tmp_path: Path) -> None:
    # Given: the real policy function with a distinct, valid configuration.
    configured = tmp_path / "override.lua"
    configured.write_text(
        'local p = assert(loadfile("native-server/rules/boss.lua"))()\n'
        "p.config = {attempts=2, idle_weight=0, mine_weight=0, weapon_weight=100, weapon_pool={1075}}\n"
        "return p\n",
        encoding="utf-8",
    )
    # When: native loads the file and injects deterministic draws.
    result = invoke(f'policy "{configured.as_posix()}" 0,0,99,0')
    # Then: the override takes effect, including count and weapon pool.
    assert result.stdout.splitlines() == ["weapon:1075", "weapon:1075"], result.stderr


@pytest.mark.parametrize(
    "draws,code",
    [
        ("100,0,0,0", "random_draw_out_of_range"),
        ("90", "random_draws_exhausted"),
        ("0,0,0,0,0", "random_draws_remaining"),
    ],
)
def test_lua_rejection_when_rng_contract_is_broken(draws: str, code: str) -> None:
    # Given: out-of-range, missing, or surplus deterministic values.
    # When: the same production policy consumes them.
    result = invoke(f'policy "{RULES}" {draws}')
    # Then: the CLI exits with an explicit failure.
    assert result.returncode == 1
    assert code in result.stderr


def test_lua_error_when_script_raises_non_string_value(tmp_path: Path) -> None:
    # Given: a malformed configuration script with a table-valued error.
    script = tmp_path / "table_error.lua"
    script.write_text("error({})", encoding="utf-8")
    # When: native handles the Lua boundary error.
    result = invoke(f'policy "{script.as_posix()}" 0')
    # Then: a stable diagnostic is produced without dereferencing a null string.
    assert result.returncode == 1
    assert result.stderr.strip() == "lua_error_non_string"
