"""机械适配四主体原证，保存来源SHA与JSON Pointer；不授予语义等级。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    source = (HERE / 'bounded_raw.json').read_bytes()
    raw = json.loads(source)
    functions = []
    for index, row in enumerate(raw['functions']):
        ranges = [dict(va=r['start_va'], **{k: v for k, v in r.items()
                       if k != 'start_va'}) for r in row['chunk_byte_ranges']]
        chunks = [dict(start_va=r['va'], end_va=hex(int(r['va'], 16) + r['size']),
                       is_main=r['va'] == row['seed_va']) for r in ranges]
        functions.append(dict(va=row['seed_va'], end_va=row['end_va'], name=row['name'],
                              status='原证机械适配；语义分级见函数审阅清单.json',
                              assembly=[dict(va=i['site_va'], text=i['text'],
                                             is_code=i['is_code']) for i in row['assembly']],
                              pseudocode=row['pseudocode'],
                              decompile_error=row['decompile_error'],
                              declared_chunks=chunks, chunk_byte_ranges=ranges,
                              bytes_match_disk=all(r['matching'] for r in ranges),
                              source=dict(path='证据/bounded_raw.json',
                                          sha256=hashlib.sha256(source).hexdigest(),
                                          json_pointer='/functions/' + str(index)),
                              range_note='声明完整单块；不把owner局部窗改造成完整函数'))
    output = dict(schema='richonline-formal-bounded-adaptation-1',
                  disk_sha256=raw['disk_sha256'], functions=functions,
                  source_sha256=hashlib.sha256(source).hexdigest(),
                  scope='仅seed_va/site_va与块start_va机械适配va；原文与原块不变')
    (HERE / 'formal_functions.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status='PASS', functions=len(functions))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
