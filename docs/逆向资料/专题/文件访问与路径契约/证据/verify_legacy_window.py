"""只读补核旧未声明窗口；三份完整字节一致后另存新原证，不改旧JSON。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = HERE / 'undeclared_write.json'
OUTPUT = HERE / 'legacy_window_verified.json'
START, END = 0x81B8B0, 0x81B973
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def disk_range(image, start, size):
    assert image[:2] == b'MZ'
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 4)[0] == 0x14C
    optional = pe + 24
    assert struct.unpack_from('<H', image, optional)[0] == 0x10B
    base = struct.unpack_from('<I', image, optional + 28)[0]
    table = optional + struct.unpack_from('<H', image, pe + 20)[0]
    matches = []
    for index in range(struct.unpack_from('<H', image, pe + 6)[0]):
        header = table + index * 40
        _, rva, raw_size, raw_offset = struct.unpack_from('<4I', image, header + 8)
        relative = start - base - rva
        if 0 <= relative and relative + size <= raw_size:
            flags = struct.unpack_from('<I', image, header + 36)[0]
            assert flags & 0x20000000, '窗口必须完整落在可执行节'
            matches.append(image[raw_offset + relative:raw_offset + relative + size])
    assert len(matches) == 1 and len(matches[0]) == size, '窗口磁盘映射不完整或不唯一'
    return matches[0]


def export(db):
    import ida_nalt

    source_bytes = SOURCE.read_bytes()
    old = json.loads(source_bytes.decode('utf-8-sig'))
    row = old['code_range']
    assert (int(row['start_va'], 16), int(row['end_va'], 16)) == (START, END)
    archived = bytes.fromhex(row['idb_hex'])
    size = END - START
    assert len(archived) == size, '旧原证缺少完整跨度'
    image = (ROOT / 'RnClient.exe').read_bytes()
    disk_sha = hashlib.sha256(image).hexdigest()
    assert disk_sha == old['disk_sha256'] == EXPECTED_SHA
    disk = disk_range(image, START, size)
    current = db.bytes.get_bytes_at(START, size)
    assert current is not None and len(current) == size, '当前IDA未返回完整窗口'
    assert current == archived == disk, '当前IDA、旧IDB原证与当前PE字节不一致；不生成补证'
    input_sha = ida_nalt.retrieve_input_file_sha256().hex()
    assert len(input_sha) == 64, 'IDA输入文件fingerprint无效'
    result = dict(
        start_va=hex(START), end_va=hex(END), size=size,
        scope='未声明代码导航窗；只补完整字节原证，不确认函数入口、边界或完整语义',
        assembly=[], idb_hex=current.hex(), disk_hex=disk.hex(), matching=True,
        disk_sha256=disk_sha, idb_input_sha256=input_sha,
        input_hash_matches_disk=input_sha == disk_sha,
        legacy_source=SOURCE.relative_to(ROOT / 'docs/逆向资料').as_posix() + '#/code_range',
        legacy_source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        legacy_idb_hex=archived.hex(), legacy_idb_matches_current=True,
        verification='旧IDB窗口、当前IDA窗口、当前PE磁盘窗口三份完整字节相等；未实机')
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(path=str(OUTPUT), start_va=hex(START), end_va=hex(END), size=size,
                matching=True, disk_sha256=disk_sha, idb_input_sha256=input_sha,
                legacy_source_sha256=result['legacy_source_sha256'])
