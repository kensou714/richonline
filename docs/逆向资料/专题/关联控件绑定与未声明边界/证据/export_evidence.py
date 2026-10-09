"""只读导出两个未声明代码窗口及声明函数依赖；不创建IDA函数。"""
from pathlib import Path
import hashlib
import json
import re
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/关联控件绑定与未声明边界/证据'
source = (ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8')
assert 'chunk_byte_ranges' in source and 'declared_chunks' in source, '请人工确认公共导出器完整块契约'
exec(compile(source, '关联控件依赖导出', 'exec'))
def run(db):
    BASE.mkdir(parents=True, exist_ok=True)
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
                disk = blob[off+rel:off+rel+size]
                return dict(va=hex(ea),size=size,label=label,idb_hex=original.hex(),disk_hex=disk.hex(),matching=original==disk)
        raise ValueError(hex(ea))
    def xrefs(ea):
        return [dict(source=hex(x.from_ea),type=int(x.type)) for x in db.xrefs.to_ea(ea)]
    windows=[]
    for start,end,thunk,label in [(0x8e14f0,0x8e1542,0x60b116,'关联数组数量设置'),(0x8e15f0,0x8e160f,0x602be2,'一基关联槽写入')]:
        assert db.functions.get_at(start) is None, '原未声明窗口已变更，需要重新核实覆盖口径'
        insns=list(db.instructions.get_between(start,end))
        assert insns[0].ea==start and insns[-1].ea+insns[-1].size==end
        assert all(a.ea+a.size==b.ea for a,b in zip(insns,insns[1:]))
        calls=[]
        for ins in insns:
            for x in db.xrefs.from_ea(ins.ea):
                if x.type in (16,17):
                    calls.append(dict(site=hex(ins.ea),target=hex(x.to_ea),name=db.functions.get_name(db.functions.get_at(x.to_ea)) if db.functions.get_at(x.to_ea) else None))
        windows.append(dict(va=hex(start),end_va=hex(end),kind='未声明代码窗口',label=label,
            assembly=[dict(va=hex(ins.ea),size=ins.size,text=db.instructions.get_disassembly(ins)) for ins in insns],
            byte_range=check(start,end-start,label),thunk=check(thunk,5,'直接入口跳板'),entry_xrefs=xrefs(start),thunk_xrefs=xrefs(thunk),calls=calls,
            boundary_checks=[check(start-16,16,'入口前填充'),check(end,16,'返回后填充')]))
    candidates=[]
    for ins in db.instructions.get_between(0x5ff000,0xa21a73):
        line=db.instructions.get_disassembly(ins)
        if re.search(r'\+(1A8h|1ACh)\]',line,re.I):
            f=db.functions.get_at(ins.ea)
            candidates.append(dict(va=hex(ins.ea),function=hex(f.start_ea) if f else None,text=line,
                                   bytes=check(ins.ea,ins.size,'同偏移候选，不代表同一结构')))
    # 磁盘字面指针只能作为候选，不能代替IDA的代码/数据交叉引用。
    pointer_occurrences=[]
    for target in [0x8e14f0,0x8e15f0,0x60b116,0x602be2]:
        needle=struct.pack('<I',target)
        positions=[]
        for vs,rva,rawsize,off in sections:
            at=blob.find(needle,off,off+rawsize)
            while at!=-1:
                positions.append(dict(va=hex(imagebase+rva+at-off),file_offset=hex(at)))
                at=blob.find(needle,at+1,off+rawsize)
        pointer_occurrences.append(dict(target=hex(target),occurrences=positions))
    data=dict(disk_sha256=hashlib.sha256(blob).hexdigest(),exporter_sha256=hashlib.sha256(source.encode('utf-8')).hexdigest(),
        scope='两个未声明窗口；不计入IDA声明函数覆盖；显式同偏移搜索仅筛候选',windows=windows,
        candidate_scan_range=['0x5ff000','0xa21a73'],field_candidates=candidates,pointer_occurrences=pointer_occurrences)
    (BASE/'未声明窗口与全段候选.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    result=export_group(db,[0x8e0af0,0x8e0ed0,0x8e2d80,0x8e31b0,0x8e3340],BASE/'构造释放复制与移动复用.json')
    return dict(windows=len(windows),candidate_instructions=len(candidates),dependencies=result,pointer_occurrences=pointer_occurrences)
