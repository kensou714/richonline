"""收集明确依赖的已有原证，保留来源哈希和原始范围；不调用 IDA。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SOURCES = (
    ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', (0x628FB0, 0x623EE0, 0x6279C0, 0x6E4640)),
    ('专题/文本过滤与字码转换/证据/caller_functions.json', (0x64A9F0,)),
    ('专题/文本过滤与字码转换/证据/functions_raw.json', (0x8198E0, 0x81B4C0)),
    ('专题/事件文字记录器/证据/resource_parser.json', (0x819250, 0x819470, 0x819660, 0x81B7F0)),
    ('专题/事件文字记录器/证据/shutdown.json', (0x624080,)),
    ('专题/提示文本生命周期/证据/lifecycle.json', (0x6E6080, 0x6E3B40)),
    ('专题/界面系统/第二批/ida_ui_batch2_raw.json', (0x6E8F50,)),
)


def build():
    rows, bridges, sources = [], [], []
    for relative, addresses in SOURCES:
        blob = (DOCS / relative).read_bytes()
        raw = json.loads(blob.decode('utf-8'))
        records = raw['functions']
        if isinstance(records, dict):
            lookup = {int(va, 16): record for va, record in records.items()}
        else:
            lookup = {int(record['va'], 16): record for record in records}
        digest = hashlib.sha256(blob).hexdigest()
        for ea in addresses:
            assert ea in lookup, (relative, hex(ea))
            record = lookup[ea]
            if 'idb_bytes_hex' in record:
                # 老档案只有主范围，不能补造未保存的异常尾块。
                old_bytes = record['idb_bytes_hex']
                record = dict(record, va=hex(ea), byte_ranges=[dict(va=hex(ea), size=len(bytes.fromhex(old_bytes)),
                                                                  idb_hex=old_bytes)],
                              saved_scope='老档案主范围；异常尾块未在该来源保存')
            rows.append(dict(va=hex(ea), source=relative, source_sha256=digest, record=record))
        for bridge in raw.get('thunks', []):
            bridges.append(dict(source=relative, source_sha256=digest, record=bridge))
        sources.append(dict(path=relative, sha256=digest))
    result = dict(schema=1, scope='复用原证，不新增函数；仅核验已保存范围', functions=rows,
                  bridge_sources=bridges, sources=sources)
    (HERE / 'reused_evidence.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(functions=len(rows), bridge_records=len(bridges))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=False))
