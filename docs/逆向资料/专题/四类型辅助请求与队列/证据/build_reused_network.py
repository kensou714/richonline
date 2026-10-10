"""离线复核四个既有网络入口；保存来源与范围，不产生新函数完成结论。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
NETWORK = DOCS / '专题/网络协议/证据/第二批'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = ('first_candidates_recheck.json', 'auxiliary_callbacks.json',
           'extra_callers.json', '版本与逐函数核验.json')
TARGETS = {0x859980, 0x859CC0, 0x858FB0, 0x6BEF20}


def build():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_at = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_at + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    sources, loaded = [], {}
    for name in SOURCES:
        path = NETWORK / name
        raw = path.read_bytes()
        loaded[name] = json.loads(raw)
        sources.append(dict(path=path.relative_to(DOCS).as_posix(),
                            sha256=hashlib.sha256(raw).hexdigest()))
    baseline = loaded['版本与逐函数核验.json']
    assert baseline['disk_sha256'] == EXPECTED
    identities = {int(row['va'], 16): row for row in baseline['functions']}
    records = {}
    for name in SOURCES[:-1]:
        for row in loaded[name]:
            va = int(row['va'], 16)
            if va in TARGETS:
                assert va not in records, hex(va)
                records[va] = (name, row)
    assert records.keys() == TARGETS
    output = []
    for va in sorted(TARGETS):
        name, row = records[va]
        old = identities[va]
        size = int(row['end_va'], 16) - va
        assert size == old['byte_count'] and old['matches_disk']
        match = [(rva, off) for _, rva, length, off in sections
                 if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(match) == 1
        rva, off = match[0]
        raw = image[off + va - base - rva:off + va - base - rva + size]
        assert len(raw) == size
        sha = hashlib.sha256(raw).hexdigest()
        assert sha == old['disk_sha256'] == old['idb_sha256']
        output.append(dict(seed_va=hex(va), source=next(s for s in sources
                           if s['path'].endswith('/' + name)), record=row,
                           current_range_audit=dict(start_va=hex(va), size=size,
                                                    disk_hex=raw.hex(), sha256=sha),
                           legacy_version_record=old,
                           pending_status='既有语义复用；本批未提升完成等级',
                           range_boundary='旧单区间原证；不伪造IDA declared_chunks'))
    result = dict(schema='richonline-network-reuse-range-audit-1',
                  disk_sha256=EXPECTED, idb_input_sha256=baseline['idb_input_sha256'],
                  sources=sources, functions=output,
                  pending_status='复用前范围重核；不是新增函数语义完成')
    (HERE / 'reused_network.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status='PASS', reused_ranges=len(output),
                unique_range_bytes=sum(r['current_range_audit']['size'] for r in output),
                output=str(HERE / 'reused_network.json'))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
