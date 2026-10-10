"""从既有完整角色原证抽ASTable消费窗口；独立按磁盘字节复核，不调用IDA。"""
from pathlib import Path
import hashlib
import json
import struct
import capstone

ROOT = Path('F:/大富翁online/Richonline')
BASE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    source = ROOT / 'docs/逆向资料/专题/角色与精灵动画/证据/角色精灵_IDA原始导出.json'
    audit = ROOT / 'docs/逆向资料/专题/角色与精灵动画/证据/角色精灵_当前磁盘核验.json'
    data = source.read_bytes()
    record = next(item for item in json.loads(data.decode('utf-8'))['functions'] if item['address'] == '0x642740')
    assert json.loads(audit.read_text('utf-8'))['disk_exe_sha256'].lower() == SHA
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((base + rva, size, offset))

    def read(va, size):
        for start, count, offset in sections:
            if start <= va and va + size <= start + count:
                return blob[offset + va - start:offset + va - start + size]
        raise ValueError('无磁盘映射：' + hex(va))

    chunks = []
    for chunk in record['chunks']:
        old = bytes.fromhex(chunk['bytes_hex'])
        assert read(int(chunk['start'], 16), len(old)) == old
        assert hashlib.sha256(old).hexdigest().upper() == chunk['sha256'].upper()
        chunks.append(dict(start_va=chunk['start'], end_va=chunk['end'], sha256=hashlib.sha256(old).hexdigest(), matching=True))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    full = [ins for chunk in record['chunks'] for ins in decoder.disasm(bytes.fromhex(chunk['bytes_hex']), int(chunk['start'], 16))]
    selected = [ins for ins in full if 0x642921 <= ins.address < 0x6429E4]
    assembly = []
    for ins in selected:
        item = dict(va=hex(ins.address), text=ins.mnemonic + ' ' + ins.op_str, size=ins.size, disk_hex=ins.bytes.hex())
        if ins.mnemonic == 'call' and ins.bytes[0] == 0xE8:
            target = ins.address + 5 + int.from_bytes(ins.bytes[1:], 'little', signed=True)
            bridge = read(target, 5)
            item['target'] = hex(target)
            if bridge[0] == 0xE9:
                item['bridge'] = dict(va=hex(target), size=5, disk_hex=bridge.hex(),
                                      target=hex(target + 5 + int.from_bytes(bridge[1:], 'little', signed=True)))
        assembly.append(item)
    result = dict(disk_sha256=SHA, source=str(source.relative_to(ROOT)).replace('\\', '/'),
                  source_sha256=hashlib.sha256(data).hexdigest(), historical_idb_input_sha256=json.loads(data.decode('utf-8'))['idb_input_sha256'],
                  version_audit=str(audit.relative_to(ROOT)).replace('\\', '/'), function='0x642740', full_chunk_audit=chunks,
                  assembly=assembly, scope='历史函数只复用ASTable三访问器参数/返回值局部；不新增整函数覆盖')
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'consumer_reused.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(instructions=len(assembly), complete_historical_chunks=len(chunks)), ensure_ascii=False))


if __name__ == '__main__':
    main()
