"""离线复用准备；不调用IDA，不宣称任何入口已完成语义审阅。"""
from pathlib import Path
import hashlib
import json
import struct
import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    assert blob[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10b
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, at + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(va, size):
        matches = [(rva, offset) for _, rva, raw_size, offset in sections
                   if 0 <= va - base - rva and va - base - rva + size <= raw_size]
        assert len(matches) == 1, (hex(va), size)
        rva, offset = matches[0]
        start = offset + va - base - rva
        return blob[start:start + size]

    refs = {}

    def source(relative):
        raw = (DOCS / relative).read_bytes()
        data = json.loads(raw)
        refs[relative] = dict(path=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                              declared_binary_sha256=data.get('disk_sha256') if isinstance(data, dict) else None)
        return data

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rows, transcript = [], []

    def append(va, chunks, evidence, pointer, scope):
        assembly = []
        for chunk in chunks:
            start, size = int(chunk['start_va'], 16), chunk['size']
            current = disk(start, size)
            assert current.hex() == chunk['disk_hex']
            assert hashlib.sha256(current).hexdigest() == chunk['sha256']
            assembly.extend(dict(va=hex(ins.address), size=ins.size, bytes_hex=ins.bytes.hex(),
                                 text=ins.mnemonic + ' ' + ins.op_str)
                            for ins in decoder.disasm(current, start))
        rows.append(dict(va=hex(va), pending_status='仅复用准备；未完成本专题语义审阅',
                         source=evidence, source_pointer=pointer, review_scope=scope,
                         chunk_byte_ranges=chunks, assembly=assembly))
        transcript.append('// 仅复用准备 ' + hex(va) + ' / ' + scope)
        transcript.extend('// ' + ins['va'] + ' ' + ins['text'] for ins in assembly)

    audit_path = '专题/网络协议/证据/第二批/版本与逐函数核验.json'
    audit = source(audit_path)
    for va in (0x8BB2E0, 0x8BB090, 0x755DE0):
        index, item = next((i, x) for i, x in enumerate(audit['functions']) if int(x['va'], 16) == va)
        raw = disk(va, item['byte_count'])
        assert item['matches_disk'] and hashlib.sha256(raw).hexdigest() == item['disk_sha256'] == item['idb_sha256']
        semantic_path = '专题/网络协议/' + item['evidence_path']
        source(semantic_path)
        chunks = [dict(start_va=hex(va), size=len(raw), disk_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())]
        append(va, chunks, audit_path, '/functions/' + str(index),
               '既有主区间按SHA复核；尾块完整性未由此来源证明，不重计新导出')

    tree_path = '专题/整数键树容器契约/证据/callers_and_node.json'
    tree = source(tree_path)
    for va in (0x8BA950, 0x8BB700):
        index, item = next((i, x) for i, x in enumerate(tree['functions']) if int(x['va'], 16) == va)
        chunks = []
        for old in item['chunk_byte_ranges']:
            raw = disk(int(old['va'], 16), old['size'])
            assert old['idb_hex'].lower() == old['disk_hex'].lower() == raw.hex()
            chunks.append(dict(start_va=old['va'], size=old['size'], disk_hex=raw.hex(),
                               sha256=hashlib.sha256(raw).hexdigest()))
        append(va, chunks, tree_path, '/functions/' + str(index),
               '复用已有完整声明块原证；字段消费或请求语义须由本专题人工逐指令再审')
    source('专题/整数键树容器契约/证据/entries.json')
    source('专题/网络协议/证据/第二批/first_candidates_recheck.json')
    contracts = []
    contract_inputs = {
        'reader_and_cleanup.json': (0x8BA830, 0x8BAF70, 0x8CC740),
        'direct_dependencies.json': (0x8BC4E0,),
        'callers_and_node.json': (0x8C6AD0, 0x8C6DD0),
    }
    for filename, addresses in contract_inputs.items():
        relative = '专题/整数键树容器契约/证据/' + filename
        data = source(relative)
        for va in addresses:
            index, item = next((i, x) for i, x in enumerate(data['functions']) if int(x['va'], 16) == va)
            chunks, assembly = [], []
            for old in item['chunk_byte_ranges']:
                start = int(old['va'], 16)
                raw = disk(start, old['size'])
                assert raw.hex() == old['disk_hex'].lower() == old['idb_hex'].lower()
                chunks.append(dict(start_va=hex(start), size=len(raw), disk_hex=raw.hex(),
                                   sha256=hashlib.sha256(raw).hexdigest()))
                assembly.extend(dict(va=hex(ins.address), size=ins.size, bytes_hex=ins.bytes.hex(),
                                     text=ins.mnemonic + ' ' + ins.op_str)
                                for ins in decoder.disasm(raw, start))
            contracts.append(dict(va=hex(va), source=relative, source_pointer='/functions/' + str(index),
                                  status='历史局部契约复用；不新增本批函数统计',
                                  chunk_byte_ranges=chunks, assembly=assembly))
            transcript.append('// 历史局部契约复用 ' + hex(va))
            transcript.extend('// ' + ins['va'] + ' ' + ins['text'] for ins in assembly)
    static_data = []
    for va in (0xA3023C, 0xA30248):
        raw = disk(va, 12)
        static_data.append(dict(start_va=hex(va), size=12, disk_hex=raw.hex(),
                                sha256=hashlib.sha256(raw).hexdigest(),
                                dwords=list(struct.unpack('<3I', raw)),
                                scope='离线PE数据；不冒称IDA或运行时快照'))
    output = dict(disk_sha256=SHA, pending_status='复用准备；不供语义覆盖计数',
                  sources=list(refs.values()), functions=rows, historical_contracts=contracts,
                  static_data=static_data,
                  scope='仅离线复用和磁盘字节核验；未调用IDA，未启动游戏')
    (HERE / 'reused_preparation.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'reused_assembly.txt').write_text('\n'.join(transcript) + '\n', 'utf-8')
    print(json.dumps(dict(status='PREPARATION', reused_functions=len(rows), sources=len(refs))))


if __name__ == '__main__':
    main()
