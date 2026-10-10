"""准备必要既有原证快照，保留来源哈希；不把复用状态提升为本批完成。"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCES = (
    ('股票与交易流程/证据/stock_core.json', (0x623CB0,)),
    ('KoNpc记录与消费者/证据/npc_methods_raw.json', (0x805380, 0x8052E0)),
    ('业务提示与期限映射/证据/followups.json', (0x627C20, 0x800AD0, 0x800B30, 0x800B90)),
    ('业务提示与期限映射/证据/callers.json', (0x741820,)),
    ('4050系列事件/证据/inventory_followup.json', (0x800FD0,)),
    ('业务提示与期限映射/证据/ctor_and_loaders.json', (0x7FEA80,)),
    ('文本段键解析与预处理/证据/functions_raw.json', (0x8191D0, 0x819220, 0x819250, 0x819470, 0x819660)),
    ('大厅URL读取与缓冲契约/证据/functions_raw.json', (0x8198E0,)),
    ('Rank标签与称号消费/证据/rank_supplement_raw.json', (0x819A20,)),
)


def main():
    functions, provenance, thunks = [], [], {}
    for relative, addresses in SOURCES:
        source = ROOT / 'docs/逆向资料/专题' / relative
        blob = source.read_bytes()
        original = json.loads(blob)
        selected = [row for row in original['functions']
                    if int(row.get('va', row.get('address')), 16) in addresses]
        assert len(selected) == len(addresses)
        functions.extend(selected)
        for row in original.get('thunks', []):
            if row['va'] in thunks:
                assert thunks[row['va']] == row
            thunks[row['va']] = row
        provenance.append(dict(source=str(source.relative_to(ROOT)),
                               source_sha256=hashlib.sha256(blob).hexdigest(),
                               functions=[hex(address) for address in addresses]))
    output = HERE / '证据/reused_raw.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dict(functions=functions, provenance=provenance, thunks=list(thunks.values()),
                                     boundary='仅复用快照，逐入口审阅状态仍以来源清单及后续本批清单为准'),
                               ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(reused=len(functions)), ensure_ascii=False))


if __name__ == '__main__':
    main()
