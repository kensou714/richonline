"""七主体机械适配；所有声明块保留，语义分级由正文和清单负责。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    source = (HERE / 'bounded_raw.json').read_bytes()
    raw = json.loads(source)
    digest = hashlib.sha256(source).hexdigest()
    functions = []
    for index, row in enumerate(raw['functions']):
        ranges = [dict(va=r['start_va'], **{k: v for k, v in r.items()
                       if k != 'start_va'}) for r in row['chunk_byte_ranges']]
        functions.append(dict(
            va=row['seed_va'], end_va=row['end_va'], name=row['name'],
            status='原证机械适配；语义分级见函数审阅清单.json',
            assembly=[dict(va=i['site_va'], text=i['text'], is_code=i['is_code'])
                      for i in row['assembly']],
            pseudocode=row['pseudocode'], decompile_error=row['decompile_error'],
            declared_chunks=[dict(start_va=r['va'],
                                  end_va=hex(int(r['va'], 16) + r['size']),
                                  is_main=r['va'] == row['seed_va']) for r in ranges],
            chunk_byte_ranges=ranges,
            bytes_match_disk=all(r['matching'] is True for r in ranges),
            source=dict(path='证据/bounded_raw.json', sha256=digest,
                        json_pointer='/functions/' + str(index)),
            range_note='保留全部声明块；主块end_va不包含离散尾块；owner局部窗不作完整函数'))
    output = dict(schema='richonline-formal-bounded-adaptation-1',
                  disk_sha256=raw['disk_sha256'], source_sha256=digest,
                  functions=functions,
                  scope='仅seed_va/site_va及块start_va机械适配；原文与全部声明块不变')
    (HERE / 'formal_functions.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'status': 'PASS', 'functions': len(functions)}


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
