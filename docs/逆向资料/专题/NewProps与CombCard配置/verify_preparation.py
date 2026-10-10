"""离线核验复用快照身份与字节；结果仅表示准备正确，不认领新函数语义。"""
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        candidates = [(rva, off) for _, rva, length, off in sections
                      if base + rva <= ea and ea + size <= base + rva + length]
        assert len(candidates) == 1, hex(ea)
        rva, off = candidates[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    data = json.loads((HERE / '证据/reused_raw.json').read_text('utf-8'))
    selected = {row['va']: row for row in data['functions']}
    assert len(selected) == len(data['functions']) == 8
    blocks = set()
    for source in data['provenance']:
        blob = (ROOT / source['source']).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == source['source_sha256']
        originals = {row['va']: row for row in json.loads(blob)['functions']}
        for va in source['functions']:
            assert selected[va] == originals[va]
    for function in selected.values():
        assert function['bytes_match_disk'] is True
        for row in function['byte_ranges'] + function.get('chunk_byte_ranges', []):
            assert row['matching'] is True
            assert disk(int(row['va'], 16), row['size']).hex() == row['idb_hex'] == row['disk_hex']
            blocks.add((row['va'], row['size']))
    for script in (HERE / 'refresh_reused.py', HERE / '证据/export_readonly.py', Path(__file__)):
        compile(script.read_text('utf-8'), str(script), 'exec')
    for doc in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in doc.read_text('utf-8').splitlines())
    assert not (HERE / '证据/functions_raw.json').exists()
    assert not (HERE / '函数审阅清单.json').exists()
    result = dict(status='PREPARATION_CHECKED', disk_sha256=EXPECTED_SHA,
                  reused_functions=8, unique_reused_ranges=len(blocks), new_functions_exported=0,
                  boundary='仅核复用身份及磁盘字节；未执行IDA，未创建新增函数完成清单。')
    (HERE / '证据/preparation_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
