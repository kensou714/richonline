"""Lossless five-body adaptation and bounded reuse; never invokes IDA."""
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
RAW_SHA = 'dbf28909a2e4328fd31158367ecb9c806fbfd6554e32e38b11a9eadb8084f635'
CALLER = '专题/回合等待与自动选择/证据/pending_functions.json'
CALLER_POINTER = '/functions/0x7c6640'
DEPENDENCIES = (
    ('专题/随机数状态与取样边界/证据/functions_raw.json', 1, '候选容器WORD元素；无界检查'),
    ('专题/随机数状态与取样边界/证据/functions_raw.json', 2, '容器DWORD计数'),
    ('专题/回合继续与落点调度/证据/property_effect_predicates.json', 0, '记录+0等于11'),
    ('专题/40EE系列事件/证据/direct_helpers.json', 9, '记录+0等于12'),
    ('专题/回合继续与落点调度/证据/stage2_dependencies.json', 50, '记录+1等于0'),
    ('专题/回合继续与落点调度/证据/property_effect_predicates.json', 7, '记录+1等于1'),
    ('专题/回合继续与落点调度/证据/property_effect_predicates.json', 8, '记录signed BYTE+3等于完整DWORD参数'),
    ('专题/本地事件剩余消费者/证据/property_fields.json', 0, '记录signed BYTE+2，作为搜索比较量'),
    ('专题/回合继续与落点调度/证据/property_effect_predicates.json', 1, '八字节节点+2 signed WORD到地产记录编号'),
    ('专题/回合继续与落点调度/证据/stage2_dependencies.json', 2, '参与者对象+5B8h位置字段'),
    ('专题/回合继续与落点调度/证据/property_effect_predicates.json', 4, '记录signed BYTE+3不等于-1'),
    ('专题/回合继续与落点调度/证据/stage2_dependencies.json', 33, '记录+1等于2'),
    ('专题/回合继续与落点调度/证据/stage2_dependencies.json', 37, '记录+1等于6'),
    ('专题/回合继续与落点调度/证据/property_effect_predicates.json', 12, '记录signed BYTE+1处于2至6'),
    ('专题/回合继续与落点调度/证据/property_effect_helpers.json', 2, '赋记录BYTE+1；取参数低BYTE'),
    ('专题/40C7系列事件/证据/property_core.json', 9, '加等级并按模式5/7封顶；返回是否抵达上限'),
    ('专题/回合继续与落点调度/证据/property_effect_helpers.json', 4, '减等级、写回BYTE后按signed值清零及类型续接'),
    ('专题/大厅URL读取与缓冲契约/证据/short_helpers_raw.json', 8, 'RTC栈检查正常直返；故障若返回恢复EAX'),
)
WINDOWS = (
    (0x7C66D2, 0x7C673F, '参与者位置与当前地产编号生产'),
    (0x7C67DF, 0x7C6800, '阶段参数3/4/5直接跳转；不审整个调度器'),
    (0x7C8BAC, 0x7C8BC9, '已归属门及进入7C8DA2'),
    (0x7C8DA2, 0x7C8E6C, '自身归属及其他门，subtype2否分支进入第一搜索链'),
    (0x7C8F5E, 0x7C9259, '两搜索链、只在-1回退、加等级和消息消费'),
    (0x7CA1AA, 0x7CA249, '阶段4前置局部门，其他类型分支之外进入三搜索链'),
    (0x7CA8CB, 0x7CAB3C, '三搜索链、减等级及结果消息，后接阶段4续调'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bind(path, pointer, topic=False):
    data = ((HERE.parent if topic else DOCS) / path).read_bytes()
    node = json.loads(data)
    for part in pointer.lstrip('/').split('/'):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return dict(base='topic' if topic else 'docs', path=path, sha256=digest(data), json_pointer=pointer), node


def pe_reader():
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe+24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe+52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, table+40*i+8) for i in range(struct.unpack_from('<H', image, pe+6)[0])]
    def read(va, size):
        offsets = [off+va-base-rva for _, rva, count, off in sections if rva <= va-base and va-base+size <= rva+count]
        assert len(offsets) == 1
        result = image[offsets[0]:offsets[0]+size]
        assert len(result) == size
        return result
    return image, read


def build():
    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    assert digest(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    image, read = pe_reader()
    assert digest(image) == raw['disk_sha256']
    functions = []
    for i, original in enumerate(raw['functions']):
        source, record = bind('证据/bounded_raw.json', '/functions/'+str(i), True)
        functions.append(dict(va=record['seed_va'], end_va=record['end_va'], name=record['name'],
            source=source, source_record=record, pseudocode=record['pseudocode'],
            decompile_error=record['decompile_error'],
            assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in record['assembly']],
            chunk_byte_ranges=record['chunk_byte_ranges'],
            coverage_origin='本批新增完整主体', status='原证无损适配；语义级别见清单'))
    dependencies = []
    for path, index, contract in DEPENDENCIES:
        source, record = bind(path, '/functions/'+str(index))
        dependencies.append(dict(va=record['va'], source=source, source_record=record,
            contract=contract, scope='旧指定短契约复用；不计本批完整主体与新增成果'))
    source, caller = bind(CALLER, CALLER_POINTER)
    old_bytes = bytes.fromhex(caller['bytes'])
    owner_start = int(caller['address'], 16)
    windows, bridges = [], {}
    for lo, hi, purpose in WINDOWS:
        indices = [i for i, row in enumerate(caller['assembly']) if lo <= int(row[0],16) < hi]
        assert indices and int(caller['assembly'][indices[0]][0],16) == lo
        assert int(caller['assembly'][indices[-1]+1][0],16) == hi
        old = old_bytes[lo-owner_start:hi-owner_start]
        current = read(lo,hi-lo)
        assert old == current
        selected = [caller['assembly'][i] for i in indices]
        windows.append(dict(owner_va=caller['address'], start_va=hex(lo), end_va=hex(hi),
            window_status='旧caller有限case复用；非完整函数审阅', window_conclusion=purpose,
            source=source, source_assembly_start=indices[0], source_assembly_end_exclusive=indices[-1]+1,
            source_byte_offset=lo-owner_start, source_rows=selected,
            assembly=[dict(va=a,text=t) for a,t in selected],
            byte_audit=dict(start_va=hex(lo),size=hi-lo,idb_hex=old.hex(),disk_hex=current.hex(),
                            matching=True,sha256=digest(current),origin='旧来源bytes切片与本次当前PE比对；非新IDA采样')))
    # Limited direct bridges used to explain caller inputs and immediate mutations.
    for va in (0x60FFD1,0x6066CF,0x60C62E,0x608452,0x60C43A,0x6114D0,0x60244E,0x60579D,0x60CBCE):
        payload = read(va,5)
        assert payload[0] == 0xE9
        bridges[hex(va)] = dict(va=hex(va), disk_hex=payload.hex(), size=5, sha256=digest(payload),
            target_va=hex(va+5+struct.unpack_from('<i',payload,1)[0]),
            scope='当前PE离线导航桥；无本批IDA快照，不计正式桥原证或新增函数')
    result = dict(schema='richonline-property-selection-formal-1', disk_sha256=raw['disk_sha256'],
        raw_sha256=RAW_SHA, functions=functions, dependency_contracts=dependencies,
        caller_windows=windows, caller_navigation_bridges=list(bridges.values()))
    (HERE/'formal_functions.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(functions=len(functions),dependencies=len(dependencies),caller_windows=len(windows))))


if __name__ == '__main__':
    build()
