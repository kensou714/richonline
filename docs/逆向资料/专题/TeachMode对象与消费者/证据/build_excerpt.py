"""从原证按函数索引生成可定位的伪码摘录，不补写原证。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
raw = json.loads((HERE / 'teachmode_raw.json').read_text(encoding='utf-8'))
selected = set(raw['seeds']) | set(raw['callers']) | {'0x6b7790', '0x6a14b0', '0x691a70', '0x7284b0'}
for row in raw['functions']:
    text = '\n'.join(row['pseudocode'])
    if '368 *' in text or '0x170' in text or 'A76714' in text:
        selected.add(row['va'])
rows = [dict(va=row['va'], end_va=row['end_va'], pseudocode=row['pseudocode'],
             outgoing=row['outgoing'], incoming=row['incoming'])
        for row in raw['functions'] if row['va'] in selected]
(HERE / 'excerpt.json').write_text(json.dumps(dict(source='teachmode_raw.json', functions=rows),
                                             ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(functions=[r['va'] for r in rows]), ensure_ascii=False))
