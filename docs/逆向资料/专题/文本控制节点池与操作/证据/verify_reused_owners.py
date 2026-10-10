"""只读核对复用 owner 的声明范围与指令锚点，不产生完整语义覆盖。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
ROOT = DOCS.parents[1]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCE = DOCS / '专题/提示文本生命周期/证据/lifecycle.json'
SOURCE_SHA = '172aa6b273f084b8ff97e5dd49228e72e7a5f16a303a30bfc1e5010fc9101b2f'


class Image:
    def __init__(self):
        self.blob = (ROOT / 'RnClient.exe').read_bytes()
        assert hashlib.sha256(self.blob).hexdigest() == EXPECTED_SHA
        assert self.blob[:2] == b'MZ'
        pe = struct.unpack_from('<I', self.blob, 0x3c)[0]
        assert self.blob[pe:pe + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', self.blob, pe + 24)[0] == 0x10b
        self.base = struct.unpack_from('<I', self.blob, pe + 52)[0]
        table = pe + 24 + struct.unpack_from('<H', self.blob, pe + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.blob, table + 40 * i + 8)
                         for i in range(struct.unpack_from('<H', self.blob, pe + 6)[0])]

    def read(self, va, size):
        matches = [(raw_offset + va - self.base - rva)
                   for _, rva, raw_size, raw_offset in self.sections
                   if 0 <= va - self.base - rva and va - self.base - rva + size <= raw_size]
        assert len(matches) == 1, (hex(va), size)
        raw = self.blob[matches[0]:matches[0] + size]
        assert len(raw) == size
        return raw

    def check_range(self, row):
        va = int(row.get('start_va', row.get('va')), 16)
        raw = self.read(va, row['size'])
        assert row['matching'] is True
        assert raw.hex() == row['idb_hex'] == row['disk_hex'], hex(va)
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        return dict(start_va=hex(va), end_va=hex(va + len(raw)), size=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest())


def audit_reuse(image):
    source_raw = SOURCE.read_bytes()
    assert hashlib.sha256(source_raw).hexdigest() == SOURCE_SHA
    data = json.loads(source_raw)
    assert data['disk_sha256'] == EXPECTED_SHA
    anchors = {
        0x8e1620: {
            0x8e16ee: '8a4708', 0x8e16f8: '8a5704', 0x8e16fe: '8b07',
            0x8e1700: '8b7f0c', 0x8e1703: '8d6c28ff', 0x8e1725: 'ff5120',
            0x8e172b: '83c410', 0x8e1736: '3b1f', 0x8e173a: '8b7f0c',
            0x8e1746: '7ca2',
        },
        0x8ea2b0: {
            0x8ea2d7: 'a1c4c3ac00', 0x8ea2e0: '8b700c',
            0x8ea2e4: 'e814aad1ff', 0x8ea2f0: 'a3c4c3ac00', 0x8ea2f5: '75e9',
        },
    }
    result = []
    for va, checks in anchors.items():
        function = next(row for row in data['functions'] if int(row['va'], 16) == va)
        assert function['bytes_match_disk'] is True
        ranges = [image.check_range(row) for row in function['byte_ranges']]
        for chunk in function['declared_chunks']:
            start, end = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
            assert start < end
            assert all(any(int(row['start_va'], 16) <= at < int(row['end_va'], 16)
                           for row in ranges) for at in range(start, end)), chunk
        asm_sites = {int(row['va'], 16) for row in function['assembly']}
        for site, raw_hex in checks.items():
            assert site in asm_sites
            assert image.read(site, len(raw_hex) // 2).hex() == raw_hex, hex(site)
        result.append(dict(owner_va=hex(va), declared_chunks=function['declared_chunks'],
                           current_range_audits=ranges,
                           semantic_anchor_sites=[hex(site) for site in checks],
                           scope='字节核验覆盖旧证全部声明块；语义仅限节点消费或池释放路径'))
    return dict(source=str(SOURCE.relative_to(DOCS)), source_sha256=SOURCE_SHA,
                disk_sha256=EXPECTED_SHA, owners=result,
                boundary='非运行时验证；不增加 owner 整函数语义覆盖')


def audit_binding(image):
    setter_path = DOCS / '专题/提示文本生命周期/证据/registration_setters.json'
    setter_sha = 'a2cdf1566ac6443d8c178d9e65ed63ef30f56487c6a28bf55c7d88bb129a4c60'
    sources = [(SOURCE, SOURCE_SHA, 0x6e2e60), (setter_path, setter_sha, 0x8e8720)]
    result = []
    for path, expected, va in sources:
        source_raw = path.read_bytes()
        assert hashlib.sha256(source_raw).hexdigest() == expected
        data = json.loads(source_raw)
        assert data['disk_sha256'] == EXPECTED_SHA
        function = next(row for row in data['functions'] if int(row['va'], 16) == va)
        ranges = [image.check_range(row) for row in function['byte_ranges']]
        for chunk in function['declared_chunks']:
            assert all(any(int(row['start_va'], 16) <= at < int(row['end_va'], 16)
                           for row in ranges)
                       for at in range(int(chunk['start_va'], 16), int(chunk['end_va'], 16)))
        result.append(dict(owner_va=hex(va), source=str(path.relative_to(DOCS)),
                           source_sha256=expected, current_range_audits=ranges,
                           scope='复用注册+40路径或条件setter；不增加整函数语义覆盖'))
    assert image.read(0x6e2f0e, 5).hex() == '6837956000'
    assert image.read(0x6e2f19, 5).hex() == 'e879d8f2ff'
    assert image.read(0x8e8720, 14).hex() == '8b44240485c07403894140c20400'
    bridges = []
    for va, target in ((0x610797, 0x8e8720), (0x609537, 0x6e52d0)):
        code = image.read(va, 5)
        assert code[0] == 0xe9 and va + 5 + struct.unpack_from('<i', code, 1)[0] == target
        bridges.append(dict(va=hex(va), target=hex(target), code=code.hex()))
    return dict(reused_paths=result, bridges=bridges,
                conclusion='该注册路径把6E52D0桥地址写入ACC3C8管理器+40；运行期改写图未闭合')


def main():
    result = audit_reuse(Image())
    output = HERE / 'reused_owner_audit.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(owners=len(result['owners']),
                         semantic_anchors=sum(len(row['semantic_anchor_sites']) for row in result['owners']),
                         result=str(output)), ensure_ascii=False))


if __name__ == '__main__':
    main()
