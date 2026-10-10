"""无损适配本批原证，绑定旧中文主体和有限装载窗口；全程离线。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
RAW_SHA = 'dfd483b21b8b4211368295e6af6e52cab0532bd972fba62395a693d033309495'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
MAP = '专题/地图与路径/证据/map_runtime_core.json'
CLEANUP = '全量分析/异常尾块与清理契约/cleanup_targets_full.json'
WINDOWS = (
    (0, 0x7DE36C, 0x7DE37E, '地图构造中的C实例与完成状态'),
    (0, 0xA153EE, 0xA153FC, '构造异常尾调用C析构'),
    (1, 0x7DED50, 0x7DED65, '正常地图析构调用C析构'),
    (1, 0xA15414, 0xA15422, '地图析构异常尾调用C析构'),
    (3, 0x7DF542, 0x7DF554, '初始容量32、增长16及C实例'),
    (3, 0x7DF9BC, 0x7DF9DD, '记录索引0起、signed上界、逐项递增'),
    (3, 0x7DFA04, 0x7DFA45, '文件K/S/等级低BYTE进入运行时记录'),
    (3, 0x7DFB21, 0x7DFB65, '历史字段勘误：写的是R+1子型，不是R+0种类'),
    (3, 0x7DFBF1, 0x7DFC96, '类型门、特殊子型分流、两个容器追加'),
    (3, 0x7DFCB6, 0x7DFCCC, '字符串后置零及返回递增点'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bind(path, pointer, topic=False):
    payload = ((HERE.parent if topic else DOCS) / path).read_bytes()
    node = json.loads(payload)
    for key in pointer.strip('/').split('/'):
        node = node[int(key)] if isinstance(node, list) else node[key]
    return dict(base='topic' if topic else 'docs', path=path,
                sha256=digest(payload), json_pointer=pointer), node


def pe_reader():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(image) == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe+24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe+52)[0]
    table = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, table+40*i+8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]
    def read(va, size):
        offsets = [off+va-base-rva for _, rva, count, off in sections
                   if rva <= va-base and va-base+size <= rva+count]
        assert len(offsets) == 1
        data = image[offsets[0]:offsets[0]+size]
        assert len(data) == size
        return data
    return image, read


def build():
    payload = (HERE/'bounded_raw.json').read_bytes()
    assert digest(payload) == RAW_SHA
    raw = json.loads(payload)
    _, read = pe_reader()
    functions = []
    for i, node in enumerate(raw['functions']):
        source, original = bind('证据/bounded_raw.json', f'/functions/{i}', True)
        functions.append(dict(va=node['seed_va'], end_va=node['end_va'], name=node['name'],
            source=source, source_record=original, pseudocode=node['pseudocode'],
            decompile_error=node['decompile_error'], assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in node['assembly']],
            chunk_byte_ranges=node['chunk_byte_ranges'],
            coverage_origin='本批新原证入口' if i == 0 else '旧完整原证本批重采；不计新增原证入口'))
    legacy = []
    for i, audit in enumerate(raw['legacy_reused_byte_audits']):
        source, original = bind(audit['source_path'], audit['source_pointer'])
        assert source['sha256'] == audit['source_sha256']
        # 历史中文状态必须隔离于中央递归审阅扫描；反序列化仍与原记录完全等价。
        legacy.append(dict(va=audit['seed_va'], source=source,
            source_record_json=json.dumps(original, ensure_ascii=False, separators=(',', ':')),
            current_audit_pointer=f'/legacy_reused_byte_audits/{i}',
            scope='旧中文已逐函数分析；本批只复用并补核，不冒充新增'))
    historical = []
    for index in (9, 10):
        source, original = bind(CLEANUP, f'/functions/{index}')
        historical.append(dict(va=original['va'], source=source, source_record=original,
            scope='旧全量分析原证复用；原记录状态仅导出，不代表当时无人工专题审阅'))
    windows = []
    for index, lo, hi, purpose in WINDOWS:
        source, owner = bind(MAP, f'/函数/{index}')
        selected = [(i, row) for i, row in enumerate(owner['完整汇编']) if lo <= int(row['地址'],16) < hi]
        assert selected and int(selected[0][1]['地址'],16) == lo
        data = b''.join(bytes.fromhex(row['字节核验']['IDB字节']) for _, row in selected)
        assert len(data) == hi-lo and data == read(lo, hi-lo)
        windows.append(dict(owner_va=owner['地址'], start_va=hex(lo), end_va=hex(hi),
            window_status='旧原证有限窗口复核；不新认领完整地图函数', window_conclusion=purpose,
            source=source, source_indices=[i for i, _ in selected], source_rows=[row for _, row in selected],
            assembly=[dict(va=row['地址'], text=row['汇编']) for _, row in selected],
            byte_audit=dict(start_va=hex(lo), size=len(data), idb_hex=data.hex(), disk_hex=read(lo,len(data)).hex(), matching=True,
                sha256=digest(data), origin='旧中文逐指令字节连接并核当前PE；非新IDA原证')))
    bridges = []
    for va in (0x60C9D5,0x607084,0x606D69,0x603F74,0x609997,0x60E3E8,0x601CD3,0x608F51):
        data = read(va,5)
        assert data[0] == 0xE9
        bridges.append(dict(va=hex(va), size=5, disk_hex=data.hex(), sha256=digest(data),
            target_va=hex(va+5+struct.unpack_from('<i',data,1)[0]), scope='当前PE离线导航；不冒充IDA本批桥'))
    result = dict(schema='richonline-property-container-formal-1', disk_sha256=EXPECTED, raw_sha256=RAW_SHA,
        functions=functions, legacy_reused_functions=legacy, historical_dependencies=historical,
        caller_windows=windows, offline_navigation_bridges=bridges,
        coverage_correction='当次2完整采证体；7ECD80旧原证/functions/9已存在，全局新入口仅7ECD50')
    (HERE/'formal_functions.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(functions=2,legacy_reused=4,historical=2,windows=len(windows)),ensure_ascii=False))


if __name__ == '__main__':
    build()
