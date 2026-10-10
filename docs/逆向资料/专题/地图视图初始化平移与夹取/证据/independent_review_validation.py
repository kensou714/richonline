"""地图视图专题独立离线核验；不调用作者程序或 IDA。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = ('0x7b6c90', '0x7b6ef0', '0x638150', '0x650c10', '0x7b6d50', '0x7b6f60', '0x7e1600')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preparation-only', action='store_true')
    parser.add_argument('--evidence-only', action='store_true')
    parser.add_argument('--show', nargs=2)
    args = parser.parse_args()
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA and blob[:2] == b'MZ'
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[pe:pe + 4] == b'PE\0\0' and struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, at + index * 40 + 8)
                for index in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded, hashes, counts = {}, {}, {}

    def load(path):
        raw = path.read_bytes()
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def disk(ea, size):
        hits = [(rva, offset) for _, rva, length, offset in sections
                if base + rva <= ea and ea + size <= base + rva + length]
        assert len(hits) == 1, (hex(ea), size)
        rva, offset = hits[0]
        raw = blob[offset + ea - base - rva:offset + ea - base - rva + size]
        assert len(raw) == size
        return raw

    def audit(row, address=None):
        ea = address if address is not None else int(row.get('start_va', row.get('va')), 16)
        raw = disk(ea, row['size'])
        assert raw.hex() == row['disk_hex'].lower()
        assert raw.hex() == row.get('idb_hex', row.get('ida_hex')).lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw

    def decode_record(row):
        chunks = row.get('chunk_byte_ranges', row.get('chunks', row.get('byte_ranges')))
        heads = []
        for chunk in chunks:
            raw = audit(chunk)
            ea = int(chunk.get('start_va', chunk.get('va')), 16)
            insns = list(decoder.disasm(raw, ea))
            assert sum(ins.size for ins in insns) == len(raw)
            heads.extend(insns)
            for ins in insns:
                decoded[ins.address] = ins
        assembly = row.get('assembly', row.get('instructions'))
        assert [hex(ins.address) for ins in heads] == [item.get('site_va', item.get('va')) for item in assembly]
        return len(heads), len(chunks)

    old_specs = (
        ('专题/断线与离席恢复/ida_disconnect_fields.json', '0x7b6d50'),
        ('专题/断线与离席恢复/ida_disconnect_dependencies.json', '0x7b6f60'),
        ('专题/断线与离席恢复/ida_disconnect_fields.json', '0x7e1600'),
    )
    old_rows = {}
    counts.update(historical_functions=3, historical_chunks=0, historical_mechanical_instructions=0)
    for path, va in old_specs:
        source = load(DOCS / path)
        assert source['disk_sha256'].lower() == SHA
        matches = [(index, row) for index, row in enumerate(source['functions']) if row['va'] == va]
        assert len(matches) == 1
        index, row = matches[0]
        old_rows[va] = row
        number, chunks = decode_record(row)
        counts['historical_chunks'] += chunks
        counts['historical_mechanical_instructions'] += number
        counts[va + '_source_pointer'] = '/functions/' + str(index)
    init_source = load(DOCS / '专题/TeachMode序号生产与根对象/证据/load_source_raw.json')
    assert init_source['disk_sha256'] == SHA
    assert init_source['functions'][1]['va'] == '0x64f2a0'
    number, chunks = decode_record(init_source['functions'][1])
    counts['caller_reference_mechanical_instructions'] = number
    counts['caller_reference_chunks'] = chunks
    if not args.preparation_only:
        bounded = load(HERE / 'bounded_raw.json')
        assert bounded['disk_sha256'] == SHA and tuple(x['seed_va'] for x in bounded['seeds']) == SEEDS
        core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
        assert hashlib.sha256(core.read_bytes()).hexdigest() == bounded['exporter_sha256']
        assert [x['seed_va'] for x in bounded['functions']] == list(SEEDS[:4])
        assert [x['seed_va'] for x in bounded['reused_seeds']] == list(SEEDS[4:])
        assert len(bounded['current_chunk_audits']) == len(SEEDS)
        counts.update(new_functions=4, new_chunks=0, new_instructions=0)
        for row in bounded['current_chunk_audits']:
            for chunk in row['chunk_byte_ranges']:
                audit(chunk)
            if row['seed_va'] in old_rows:
                assert [(x['start_va'], x['size'], x['disk_hex']) for x in row['chunk_byte_ranges']] == [
                    (x.get('start_va', x.get('va')), x['size'], x['disk_hex'])
                    for x in old_rows[row['seed_va']].get('chunk_byte_ranges', old_rows[row['seed_va']].get('chunks', old_rows[row['seed_va']].get('byte_ranges')))]
        for row in bounded['functions']:
            current = next(x for x in bounded['current_chunk_audits'] if x['seed_va'] == row['seed_va'])
            assert current['chunk_byte_ranges'] == row['chunk_byte_ranges']
            number, chunks = decode_record(row)
            assert all(item['is_code'] for item in row['assembly'])
            counts['new_instructions'] += number
            counts['new_chunks'] += chunks
        bridges = {}
        for row in bounded['verified_direct_bridges']:
            raw = audit(row)
            ea = int(row['start_va'], 16)
            assert len(raw) == 5 and raw[0] == 0xE9
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            assert target == int(row['target_va'], 16)
            assert ea not in bridges or bridges[ea] == target
            bridges[ea] = target
        counts.update(unique_bridges=len(bridges), direct_calls=0, owner_items=0)
        for row in bounded['calls']:
            ins = decoded[int(row['site_va'], 16)]
            assert ins.mnemonic in ('call', 'jmp') and ins.operands[0].type == X86_OP_IMM
            target = ins.operands[0].imm
            assert target == int(row['target_va'], 16)
            for bridge in row['bridges']:
                assert target == int(bridge, 16)
                target = bridges[target]
            assert target == int(row['implementation_va'], 16)
            counts['direct_calls'] += 1
        windows = bounded['explicit_owner_windows'] + [edge['owner_window']
            for edges in bounded['incoming'].values() for edge in edges if 'owner_window' in edge]
        assert [x['site_va'] for x in bounded['explicit_owner_windows']] == [
            '0x64f50a', '0x64f519', '0x64f532', '0x64f54c']
        for window in windows:
            if window['owner_va'] is None:
                assert not window['assembly']
                continue
            assert window['site_va'] in [x['site_va'] for x in window['assembly']]
            assert len(window['assembly']) <= 11
            previous_end = None
            for item in window['assembly']:
                ea = int(item['site_va'], 16)
                raw = audit(item['bytes'], ea)
                assert previous_end is None or ea == previous_end
                previous_end = ea + len(raw)
                if item['is_code']:
                    insns = list(decoder.disasm(raw, ea))
                    assert len(insns) == 1 and insns[0].size == len(raw)
                    decoded[ea] = insns[0]
                counts['owner_items'] += 1
        assert not bounded['strings'] and not bounded['data_windows']
        for row in bounded['reuse_sources']:
            path = (DOCS / row['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            load(path)
            assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
    if args.show:
        start, end = (int(value, 16) for value in args.show)
        for ea, ins in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X} {ins.mnemonic:8} {ins.op_str}')
        return
    assert args.preparation_only or args.evidence_only, '当前只完成原证核验，终稿未审，不可升级 PASS'
    for path in TOPIC.glob('*.txt'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    for path in HERE.glob('*.py'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = dict(status='PREPARATION_CHECKED' if args.preparation_only else 'EVIDENCE_CHECKED',
                  disk_sha256=SHA, **counts, source_sha256=hashes,
                  boundary='当前PE、声明块与有限窗口机械核验；未完成终稿；未调用IDA或运行游戏。')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
