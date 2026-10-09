"""在当前IDA-MCP lease只读重导；公共导出器变化时要求人工检查。"""
from pathlib import Path
import hashlib
import json
import re
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/控件树与对象生命周期/证据'
source = (ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8')
expected = json.loads((BASE / '链字段与虚表数据.json').read_text(encoding='utf-8'))['exporter_sha256']
assert hashlib.sha256(source.encode('utf-8')).hexdigest() == expected, '公共导出器已变化，请先检查完整chunks语义'
exec(compile(source, '控件树完整chunks导出器', 'exec'))
def run(db):
    results = []
    for name in ['创建与链表.json', '几何传播.json', '状态与销毁.json', '名称调用复用.json']:
        path = BASE / name
        raw = json.loads(path.read_text(encoding='utf-8'))
        results.append(dict(source=name, **export_group(db, [int(f['va'], 16) for f in raw['functions']], path)))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    opts = struct.unpack_from('<H', blob, pe + 20)[0]
    imagebase = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opts + 40*i + 8) for i in range(count)]
    def check(ea, size, label):
        original = db.bytes.get_bytes_at(ea, size)
        for vs, rva, rawsize, off in sections:
            rel = ea - imagebase - rva
            if 0 <= rel and rel + size <= rawsize:
                disk = blob[off + rel:off + rel + size]
                return dict(va=hex(ea), size=size, label=label, idb_hex=original.hex(), disk_hex=disk.hex(), matching=original == disk)
        raise ValueError(hex(ea))
    writers, writer_checks = [], []
    for ins in db.instructions.get_between(0x8e0000, 0x910000):
        text = db.instructions.get_disassembly(ins)
        if re.match(r'(mov|and|or|xchg)\s+[^,]*\+(190h|194h|198h)\],', text, re.I):
            f = db.functions.get_at(ins.ea)
            writers.append(dict(va=hex(ins.ea), function=hex(f.start_ea) if f else None, text=text))
            writer_checks.append(check(ins.ea, ins.size, '显式链字段写者'))
    candidate = dict(scope='仅8E0000..910000内显式+190h/+194h/+198h目的操作数候选；非全程序别名证明', writers=writers)
    (BASE / '链字段写者候选.json').write_text(json.dumps(candidate, ensure_ascii=False, indent=2), encoding='utf-8')
    table = struct.unpack('<I', db.bytes.get_bytes_at(0x8e24f7, 4))[0]
    regions = [(0xa305ac,204,'基础控件虚表首51项'),(table,52,'默认工厂type0..12跳表'),
               (0xa67adc,16,'创建失败调试文本'),(0xa67aec,20,'名称查找空参调试文本')]
    mappings = []
    for offset in [0,8,12,16,20,120,196]:
        target = db.bytes.get_dword_at(0xa305ac + offset)
        code = db.bytes.get_bytes_at(target, 5)
        assert code[0] == 0xe9
        mappings.append(dict(offset=offset, entry=hex(target), implementation=hex(target + 5 + struct.unpack('<i', code[1:])[0])))
    data = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), data_checks=[check(*r) for r in regions],
                virtual_mapping=mappings, writer_checks=writer_checks, default_factory_table=hex(table),
                vtable_thunk_checks=[check(int(r['entry'],16),5,'基础虚表跳板') for r in mappings], exporter_sha256=expected,
                name_lookup_direct_callers=[dict(site=hex(x.from_ea), function=hex(db.functions.get_at(x.from_ea).start_ea))
                                            for x in db.xrefs.to_ea(0x610d96) if db.functions.get_at(x.from_ea)])
    (BASE / '链字段与虚表数据.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return results
