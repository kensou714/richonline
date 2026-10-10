"""独立核对高扇入专题的 PE 字节、E9 别名及两种入边口径。"""

import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
ANALYSIS = ROOT / "docs/逆向资料/全量分析"
EXPECTED_EXE = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
EXPECTED_IDB_INPUT = "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    image = (ROOT / "RnClient.exe").read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_EXE
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[:2] == b"MZ" and image[pe:pe + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", image, pe + 24)[0] == 0x10B
    image_base = struct.unpack_from("<I", image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from("<H", image, pe + 20)[0]
    sections = [struct.unpack_from("<4I", image, section_table + 40 * i + 8)
                for i in range(struct.unpack_from("<H", image, pe + 6)[0])]

    def disk_at(va, size):
        matches = [(rva, raw_offset) for _, rva, raw_size, raw_offset in sections
                   if image_base + rva <= va and va + size <= image_base + rva + raw_size]
        assert len(matches) == 1, hex(va)
        rva, offset = matches[0]
        return image[offset + va - image_base - rva:offset + va - image_base - rva + size]

    raw = read(HERE / "highfanout_raw.json")
    aliases = read(HERE / "highfanout_aliases.json")
    group = read(HERE / "85bb_group_raw.json")
    assert {x["disk_sha256"] for x in (raw, aliases, group)} == {EXPECTED_EXE}
    assert {x["idb_input_sha256"] for x in (raw, aliases, group)} == {EXPECTED_IDB_INPUT}

    ranges = 0
    instructions = 0
    functions = [target["function"] for target in raw["targets"]] + group["functions"]
    for function in functions:
        for chunk in function["chunks"]:
            va = int(chunk["va"], 16)
            code = disk_at(va, chunk["size"])
            assert len(code) == chunk["size"]
            assert code.hex() == chunk["ida_hex"] == chunk["disk_hex"]
            ranges += 1
        for ins in function["instructions"]:
            va = int(ins["va"], 16)
            assert disk_at(va, ins["size"]).hex() == ins["hex"]
            instructions += 1
    windows = 0
    for target in raw["targets"]:
        for window in target["windows"]:
            block = window["block"]
            code = disk_at(int(block["va"], 16), block["size"])
            assert code.hex() == block["ida_hex"] == block["disk_hex"]
            windows += 1
            for ins in window["instructions"]:
                assert disk_at(int(ins["va"], 16), ins["size"]).hex() == ins["hex"]
                instructions += 1
    assert disk_at(0x85C736, 2) == bytes.fromhex("8b00")

    queue = {row["va"]: row for row in read(ANALYSIS / "followup_queue.json")["functions"]}
    graph = {}
    for path in sorted((ANALYSIS / "callgraph").glob("batch_*.json")):
        for function in read(path):
            for edge in function["edges"]:
                target = edge.get("normalized_target_va") or edge["target_va"]
                graph.setdefault(target, []).append(edge)

    report = []
    for target, alias in zip(raw["targets"], aliases["targets"]):
        va = target["va"]
        assert va == alias["va"] and len(alias["aliases"]) == 1
        entry = int(alias["aliases"][0]["entry"], 16)
        jump = disk_at(entry, 5)
        assert jump[0] == 0xE9
        assert entry + 5 + struct.unpack("<i", jump[1:])[0] == int(va, 16)
        incoming = alias["incoming"]
        assert len(incoming) == alias["totals"]["incoming"]
        assert len({item["site"] for item in incoming}) == len(incoming)
        assert all(item["iscode"] for item in incoming)
        assert len(target["incoming"]) == 1
        assert target["incoming"][0]["site"] == alias["incoming"][0]["site"] or any(
            item["site"] == target["incoming"][0]["site"] for item in incoming)
        edges = graph.get(va, [])
        assert len(edges) == queue[va]["direct_incoming_edges"]
        graph_sites = {edge["site"] for edge in edges}
        live_sites = {item["site"] for item in incoming}
        assert graph_sites <= live_sites
        missing = [item for item in incoming if item["site"] not in graph_sites]
        report.append(dict(va=va, alias=hex(entry), raw_direct=len(target["incoming"]),
                           live_incoming=len(incoming), central_incoming=len(edges),
                           missing_sites=[dict(site=item["site"], owner=item["owner"])
                                          for item in missing],
                           missing_tail_sites=sum(int(item["site"], 16) >= 0xA10000
                                                  for item in missing),
                           missing_no_owner=sum(item["owner"] is None for item in missing)))

    assert [(row["va"], row["live_incoming"], row["central_incoming"],
             row["missing_tail_sites"], row["missing_no_owner"]) for row in report] == [
        ("0x91f7e0", 270, 212, 57, 1),
        ("0x9ca953", 96, 95, 0, 1),
        ("0x9db4b6", 73, 73, 0, 0),
        ("0x85bb10", 56, 56, 0, 0),
    ]
    assert [row["missing_sites"][0]["site"] for row in report[:2]] == ["0x7def11", "0x9d0dba"]

    result = dict(status="PASS", exe_sha256=EXPECTED_EXE, idb_input_sha256=EXPECTED_IDB_INPUT,
                  function_count=len(functions), function_chunks=ranges,
                  call_windows=windows, verified_instructions=instructions,
                  targets=report, scope="离线 PE 与已保存 IDA 原证；不证明运行时可达性")
    (HERE / "independent_offline.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "targets"},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
