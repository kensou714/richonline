"""保留复用记录、来源哈希和逐函数范围，不改写原专题。"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
DOCS = ROOT / 'docs/逆向资料'
BASE = Path(__file__).resolve().parent


def main():
    rows = json.loads((BASE / 'reuse_sources.json').read_text('utf-8'))['reused']
    dependency = BASE / 'dependency_reuse.json'
    if dependency.exists():
        rows += json.loads(dependency.read_text('utf-8'))
    for va in ('0x807830', '0x807860', '0x807890', '0x8078c0'):
        rows.append(dict(va=va, evidence=['专题/KoNpc记录与消费者/证据/npc_methods_raw.json']))
    result, paths, seen, bridges = [], {}, set(), {}
    for row in rows:
        va = row['va'].lower()
        if va in seen:
            continue
        seen.add(va)
        candidates = []
        for source in row['evidence']:
            path = DOCS / source
            raw = path.read_bytes()
            value = json.loads(raw)
            records = value.get('functions', [])
            if isinstance(records, dict):
                records = records.values()
            for record in records:
                if record.get('va', '').lower() == va and record.get('byte_ranges'):
                    priority = 0 if 'KoNpc记录与消费者' in source else 1
                    candidates.append((priority, source, record, raw, value))
        if not candidates:
            raise ValueError('未找到含原字节范围的复用记录：' + va)
        _, source, record, raw, value = sorted(candidates, key=lambda item: (item[0], item[1]))[0]
        paths[source] = hashlib.sha256(raw).hexdigest()
        result.append(dict(va=va, source=source, source_sha256=paths[source], record=record))
        referenced = {address for call in record.get('calls', []) for address in call.get('thunks', [])}
        for bridge in value.get('thunks', []):
            if bridge['va'] in referenced:
                bridges[bridge['va']] = bridge
    output = dict(scope='复用原证拷贝；仅来源与字节范围保存，不计新增 IDA 导出',
                  source_hashes=paths, reused=result, thunks=list(bridges.values()))
    (BASE / 'reused_evidence.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('reused records:', len(result))


if __name__ == '__main__':
    main()
