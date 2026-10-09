"""在只读IDA-MCP中调用collect(db)，导出配置区域引用和完整消费者函数块。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局数值配置')
ROOT = HERE.parents[3]


def collect(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), namespace)
    references, functions = [], set()
    for target in range(0xA87080, 0xA87480):
        for ref in db.xrefs.to_ea(target):
            function = db.functions.get_at(ref.from_ea)
            insn = db.instructions.get_at(ref.from_ea)
            references.append({'target': hex(target), 'index': (target - 0xA87080) // 4,
                               'byte_offset': (target - 0xA87080) % 4,
                               'site': hex(ref.from_ea), 'kind': int(ref.type),
                               'function': hex(function.start_ea) if function else None,
                               'text': db.instructions.get_disassembly(insn) if insn else None})
            if function:
                functions.add(function.start_ea)
    initial = [0x7B9AD0, 0x7B74C0, 0x623B60, 0x7A3D90]
    functions.update(initial)
    first_path = HERE / '证据/loader_probe.json'
    namespace['export_group'](db, [0x7B9AD0], str(first_path))
    probe = json.loads(first_path.read_text(encoding='utf-8'))
    dependencies = {int(c['implementation'], 16) for c in probe['functions'][0]['calls']
                    if 0x620000 <= int(c['implementation'], 16) < 0x900000}
    functions.update(dependencies)
    # 两类对象的实际清理以及LZO锁/解压包装，CRT分配与字符串库不递归扩展。
    functions.update([0x8193F0, 0x81AD80, 0x6BFA00, 0x6BFA40, 0x827890])
    summary = namespace['export_group'](db, functions, str(HERE / '证据/functions.json'))
    data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    for function in data['functions']:
        for instruction in function['assembly']:
            instruction['size'] = db.instructions.get_at(int(instruction['va'], 16)).size
    (HERE / '证据/functions.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n',
                                             encoding='utf-8')
    segment = db.segments.get_at(0xA87080)
    evidence = {'disk_sha256': data['disk_sha256'],
                'scope': '逐字节枚举A87080..A8747F引用；1024字节扫描窗口不是数组合法容量证明',
                'ida_segment': {'start': hex(segment.start_ea), 'end': hex(segment.end_ea)},
                'references': references, 'startup_exported': [hex(x) for x in initial],
                'loader_direct_dependencies': [hex(x) for x in sorted(dependencies)]}
    (HERE / '证据/references.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n',
                                              encoding='utf-8')
    return {'export': summary, 'references': len(references), 'functions': len(functions),
            'indices': sorted(set(r['index'] for r in references))}


def recheck(db):
    data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    rows, mismatches = [], []
    for saved in data['functions']:
        f = db.functions.get_at(int(saved['va'], 16))
        chunks = list(db.functions.get_chunks(f))
        declared = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]
        actual = {hex(i.ea): i.size for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
        expected = {i['va']: i['size'] for i in saved['assembly']}
        if declared != saved['declared_chunks'] or actual != expected:
            mismatches.append(saved['va'])
        if any(db.bytes.get_bytes_at(int(s['va'], 16), s['size']).hex() != s['idb_hex']
               for s in saved['byte_ranges']):
            mismatches.append(saved['va'])
        rows.append({'va': saved['va'], 'declared_chunks': declared,
                     'instruction_count': len(actual), 'instruction_bytes': sum(actual.values())})
    result = {'disk_sha256': data['disk_sha256'], 'scope': '重取全部函数块及指令集合和当前IDA字节',
              'functions': rows, 'mismatches': sorted(set(mismatches))}
    (HERE / '证据/ida_recheck.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if mismatches:
        raise ValueError(mismatches)
    return {'functions': len(rows), 'mismatches': []}
