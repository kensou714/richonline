"""收集实际共享依赖的保存范围与来源哈希，不重新导出已有函数。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SOURCES = (
    ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', (0x628D20,0x623EE0,0x627C20,0x691A70,0x64EFA0)),
    ('专题/事件文字记录器/证据/shutdown.json', (0x624080,)),
    ('专题/事件文字记录器/证据/resource_parser.json', (0x819250,0x819470,0x819660,0x81B7F0)),
    ('专题/文本过滤与字码转换/证据/functions_raw.json', (0x8198E0,0x81B4C0)),
)


def build():
    rows, sources, bridges = [], [], []
    for relative, entries in SOURCES:
        raw = (DOCS/relative).read_bytes()
        data = json.loads(raw)
        lookup = {int(r['va'],16):r for r in data['functions']}
        sha = hashlib.sha256(raw).hexdigest()
        for ea in entries:
            assert ea in lookup, (relative,hex(ea))
            rows.append(dict(va=hex(ea), source=relative, source_sha256=sha, record=lookup[ea]))
        sources.append(dict(path=relative,sha256=sha))
        bridges.extend(dict(source=relative,record=r) for r in data.get('thunks',[]))
    result = dict(scope='12个实际依赖复用；旧chunks与现代范围分别保留，不新增覆盖',
                  functions=rows,sources=sources,bridges=bridges)
    (HERE/'reused_evidence.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(functions=len(rows),bridge_rows=len(bridges))


if __name__=='__main__':
    print(json.dumps(build(),ensure_ascii=False))
