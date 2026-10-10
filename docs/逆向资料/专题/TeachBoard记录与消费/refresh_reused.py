"""复制本批必要既有原证，保留原记录及来源文件哈希，不修改来源。"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCES = (
    ('股票与交易流程/证据/stock_core.json', (0x623CB0,)),
    ('TeachMode对象与消费者/证据/teachmode_raw.json', (0x646750, 0x6FA7F0)),
    ('参与者布局与人数边界/证据/participant_upstream_dependencies.json', (0x646720,)),
    ('图像运行时接口/证据/draw_mapping_dependencies.json', (0x6DAA10,)),
    ('角色与精灵动画/证据/动画管理与骰子_IDA原始导出.json', (0x63F870, 0x63F8D0)),
    ('StockName与StockRace/证据/supplement_raw.json', (0x6C5510,)),
    ('文本段键解析与预处理/证据/functions_raw.json', (0x819250,)),
)


def main():
    functions, provenance = [], []
    for relative, addresses in SOURCES:
        source = ROOT / 'docs/逆向资料/专题' / relative
        blob = source.read_bytes()
        selected = [row for row in json.loads(blob)['functions']
                    if int(row.get('va', row.get('address')), 16) in addresses]
        assert len(selected) == len(addresses)
        functions.extend(selected)
        provenance.append(dict(source=str(source.relative_to(ROOT)),
                               source_sha256=hashlib.sha256(blob).hexdigest(),
                               functions=[hex(address) for address in addresses]))
    (HERE / '证据/reused_raw.json').write_text(json.dumps(dict(functions=functions, provenance=provenance),
                                                       ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(reused=len(functions)), ensure_ascii=False))


if __name__ == '__main__':
    main()
