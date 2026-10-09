"""独审只读验证；结果返回 stdout，不覆盖作者原证。"""
import contextlib
import hashlib
import io
import json
import re
import runpy
import struct
from collections import Counter
from pathlib import Path
from unittest.mock import patch

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
GROUPS = ('startup_and_navigation.json', 'io_and_parser_navigation.json',
          'controls_and_flow_navigation.json', 'controls_and_queue_navigation.json',
          'queue_and_ui_gate.json', 'replay_state_stubs.json', 'digest_helper.json')


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', blob, 60)[0]
    count, opt = struct.unpack_from('<H', blob, pe + 6)[0], struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt + 40*i + 8) for i in range(count)]

    def disk(va, size):
        for _, rva, raw, offset in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw:
                return blob[offset+delta:offset+delta+size]
        return None

    comparisons, ranges = 0, {}

    def compare(va, data, allow_unbacked=False):
        nonlocal comparisons
        data = bytes.fromhex(data)
        raw = disk(va, len(data))
        assert raw == data or (allow_unbacked and raw is None), hex(va)
        if db is not None:
            assert db.bytes.get_bytes_at(va, len(data)) == data, ('IDA字节', hex(va))
        key = (va, len(data))
        if key in ranges:
            assert ranges[key] == data, ('重复原证', hex(va))
        ranges[key] = data
        comparisons += 1

    functions, thunks, chunks, insns = {}, {}, set(), set()
    for name in GROUPS:
        group = json.loads((HERE/name).read_text(encoding='utf-8'))
        assert group['disk_sha256'] == EXPECTED
        for f in group['functions']:
            va = int(f['va'], 16)
            if va in functions:
                for key in ('assembly', 'declared_chunks', 'byte_ranges', 'chunk_byte_ranges', 'calls'):
                    assert functions[va][key] == f[key], (hex(va), key)
            functions[va] = f
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
            saved = {(int(c['va'], 16), int(c['va'], 16)+c['size']) for c in f['chunk_byte_ranges']}
            assert {(s, e) for s, e, _ in declared} == saved
            chunks.update((va, s, e) for s, e, _ in declared)
            for row in f['byte_ranges'] + f['chunk_byte_ranges']:
                assert len(bytes.fromhex(row['idb_hex'])) == row['size']
                compare(int(row['va'], 16), row['idb_hex'])
            asm = {int(i['va'], 16): i['text'] for i in f['assembly']}
            assert len(asm) == len(f['assembly'])
            insns.update(asm)
            assert all(any(s <= a < e for s, e, _ in declared) for a in asm)
            if db is not None:
                live = db.functions.get_at(va)
                assert live is not None and live.start_ea == va and live.end_ea == int(f['end_va'], 16)
                actual = list(db.functions.get_chunks(live))
                assert {(c.start_ea, c.end_ea, c.is_main) for c in actual} == declared, ('声明块', hex(va))
                live_insns = {i.ea: db.instructions.get_disassembly(i)
                              for c in actual for i in db.instructions.get_between(c.start_ea, c.end_ea)}
                assert live_insns == asm, ('全部块内指令', hex(va))
        for t in group['thunks']:
            va = int(t['va'], 16)
            if va in thunks:
                assert thunks[va] == t
            thunks[va] = t
            compare(va, t['idb_hex'])
            raw = bytes.fromhex(t['idb_hex'])
            assert len(raw) == 5 and raw[0] == 0xe9
            assert va+5+int.from_bytes(raw[1:], 'little', signed=True) == int(t['target'], 16)

    unbacked = []
    for name in ('control_data_navigation.json', 'state_and_switch_data.json', 'file_path_constants.json'):
        for row in json.loads((HERE/name).read_text(encoding='utf-8')):
            va = int(row['va'], 16)
            allow = name == 'control_data_navigation.json' and va == 0xa7c730
            if allow:
                assert row['size'] == 20 and disk(va, 20) is None
                unbacked.append(dict(va=hex(va), size=20, scope='仅IDB，无文件后备'))
            compare(va, row['idb_hex'], allow)
    windows = json.loads((HERE/'undeclared_io_windows.json').read_text(encoding='utf-8'))
    for row in windows:
        start, end = int(row['start_va'], 16), int(row['end_va'], 16)
        assert len(bytes.fromhex(row['idb_hex'])) == end-start
        compare(start, row['idb_hex'])
        if db is not None:
            assembly = [dict(va=hex(i.ea), size=i.size, text=db.instructions.get_disassembly(i))
                        for i in db.instructions.get_between(start, end)]
            assert assembly == row['assembly'], ('原始窗口', hex(start))
    tables = json.loads((HERE/'binary_tables.json').read_text(encoding='utf-8'))
    for row in tables['raw_ranges']:
        compare(int(row['va'], 16), row['disk_hex'])
    for row in tables['switch_rows']:
        idx = disk(0x706e82+row['command']-90, 1)[0]
        target = struct.unpack('<I', disk(0x706e6a+4*idx, 4))[0]
        assert idx == row['index'] and target == int(row['target'], 16)
    assert all(row['target'] == '0x706c80' for row in tables['switch_rows'] if row['command'] in (150, 151, 160, 161))
    for va in (0x6258f0, 0x625900):
        assert disk(va, 10).hex() == '558becb8010000005dc3'
    review = json.loads((HERE.parent/'function_review.json').read_text(encoding='utf-8'))
    assert {int(f['va'], 16) for f in review['functions']} == set(functions)
    for f in review['functions']:
        assert f['declared_chunks'] == functions[int(f['va'], 16)]['declared_chunks']
        assert f['status'] == f['level'] and f['conclusion'] == f['summary']
        assert f['evidence'] == f['sources'] and f['unknown']
        assert f['full_dependency_closure'] is False

    # 原作者验证器再次执行，但拦截唯一输出，保留作者原证与结果文件不变。
    generated = {}
    def capture(path, text, *args, **kwargs):
        assert path == HERE.parent/'验证结果.json'
        generated['author_validator_result'] = json.loads(text)
        return len(text)
    if db is None:
        with patch.object(Path, 'write_text', capture), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(HERE/'validate.py'))
    result = dict(exe_sha256=EXPECTED, independent_functions=len(functions),
                  complete_declared_chunks=len(chunks), instruction_addresses=len(insns),
                  unique_thunks=len(thunks), byte_comparisons=comparisons,
                  unique_byte_ranges=len(ranges), unique_range_bytes=sum(len(b) for b in ranges.values()),
                  raw_windows=len(windows), unbacked_ranges=unbacked,
                  manual_levels=dict(Counter(f['level'] for f in review['functions'])),
                  live_ida_checked=db is not None, mismatches=0,
                  resource_validation='IDA模式不导入LZO；资源与作者验证器由本地Python另行核验。' if db is not None else '本地重跑作者验证器，拦截文件写入。',
                  scope='独审从当前PE核验；IDA模式另逐块核声明、汇编与字节。范围重叠不相加为分析量。',
                  provenance='独审脚本作者为ida_patch_docs；若IDA模式由父代理代跑，另在审阅记录披露。')
    result.update(generated)
    return result


if __name__ == '__main__':
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
