"""在既有 IDA-MCP 租约运行；只读导出本专题函数、完整尾块、分派和飞弹启动区间。"""
import json
from pathlib import Path
import idautils

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/40B8系列事件/证据'
exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'))


def save(name, value):
    (BASE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def run(db):
    groups = json.loads((BASE / 'export_groups.json').read_text(encoding='utf-8'))
    functions = {}
    for filename, addresses in groups.items():
        export_group(db, [int(address, 16) for address in addresses], BASE / filename)
        source = json.loads((BASE / filename).read_text(encoding='utf-8'))
        functions.update({item['va']: item for item in source['functions']})
    chunks, gaps, mismatches = [], [], []
    for address, item in functions.items():
        function = db.functions.get_at(int(address, 16))
        declared = [(chunk.start_ea, chunk.end_ea) for chunk in db.functions.get_chunks(function)]
        alternate = list(idautils.Chunks(int(address, 16)))
        if set(declared) != set(alternate):
            mismatches.append(address)
        covered = set()
        for region in item['byte_ranges']:
            covered.update(range(int(region['va'], 16), int(region['va'], 16)+region['size']))
        for start, end in declared:
            missing = sorted(set(range(start, end))-covered)
            if missing:
                gaps.append({'function': address, 'addresses': [hex(x) for x in missing]})
            chunks.append({'function': address, 'va': hex(start), 'size': end-start,
                           'idb_hex': db.bytes.get_bytes_at(start, end-start).hex()})
    save('完整函数块审核.json', {'functions': len(functions), 'chunks': chunks,
                              'coverage_gaps': gaps, 'chunk_api_mismatches': mismatches,
                              'method': 'get_chunks 与 idautils.Chunks 交叉核对；逐字节核导出覆盖，非语义完成证明'})
    extras = []
    for index, address in enumerate(range(0x7ee8c9, 0x7ee919, 10)):
        extras.append({'kind': 'registration', 'opcode': hex(0x40b8+index),
                       'va': hex(address), 'size': 10,
                       'idb_hex': db.bytes.get_bytes_at(address, 10).hex()})
    for address in [0x612b9b, 0x603669, 0x609109, 0x607066, 0x600da6, 0x612cbd, 0x60ce8f, 0x60aa77]:
        extras.append({'kind': 'dispatch_thunk', 'va': hex(address), 'size': 5,
                       'idb_hex': db.bytes.get_bytes_at(address, 5).hex()})
    extras.append({'kind': 'vtable', 'va': '0xa2c0c0', 'size': 12,
                   'idb_hex': db.bytes.get_bytes_at(0xa2c0c0, 12).hex()})
    start, end = 0x6335b0, 0x6336f0
    code = {'va': hex(start), 'size': end-start, 'kind': 'undefined_code_range',
            'idb_hex': db.bytes.get_bytes_at(start, end-start).hex(),
            'assembly': [{'va': hex(ins.ea), 'text': db.instructions.get_disassembly(ins)}
                         for ins in db.instructions.get_between(start, end)]}
    save('补充区间.json', {'ranges': extras, 'code_ranges': [code],
                        'scope': '6335B0 当前未定义函数，单列代码区间，不能计为已定义函数'})
    if gaps or mismatches:
        raise ValueError('函数块覆盖或两套枚举不一致')
    return {'functions': len(functions), 'chunks': len(chunks), 'extras': len(extras), 'gaps': len(gaps)}
