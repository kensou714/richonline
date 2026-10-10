"""机械适配固定原证；保留所有原字段与 JSON Pointer，不采集 IDA。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]


def main():
    raw = (HERE / 'bounded_raw.json').read_bytes()
    bounded = json.loads(raw)
    rows = []
    for index, source in enumerate(bounded['functions']):
        pointer = '/functions/' + str(index)
        row = dict(source)
        row.update(va=source['seed_va'], source_file='bounded_raw.json',
                   source_pointer=pointer,
                   source_field_pointers={key: pointer + '/' + key for key in source},
                   byte_ranges=source['chunk_byte_ranges'],
                   declared_chunks=[dict(start_va=chunk['start_va'],
                                         end_va=hex(int(chunk['start_va'], 16) + chunk['size']),
                                         is_main=chunk['start_va'] == source['seed_va'])
                                    for chunk in source['chunk_byte_ranges']])
        rows.append(row)
    result = dict(disk_sha256=bounded['disk_sha256'], source_file='bounded_raw.json',
                  source_sha256=hashlib.sha256(raw).hexdigest(),
                  scope='八个新原证的无损适配；是否完成语义审阅以清单为准', functions=rows)
    (HERE / 'formal_functions.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    path = '专题/TeachMode对象与消费者/证据/teachmode_raw.json'
    historical_raw = (DOCS / path).read_bytes()
    source = json.loads(historical_raw)['functions'][75]
    assert source['va'] == '0x6b77b0'
    row = dict(source)
    row.update(source_path=path, source_pointer='/functions/75',
               source_sha256=hashlib.sha256(historical_raw).hexdigest(),
               source_field_pointers={key: '/functions/75/' + key for key in source},
               assembly=[dict(site_va=item['va'], text=item['text'], is_code=True,
                              bytes_hex=item['hex'], size=item['size'])
                         for item in source['instructions']],
               chunk_byte_ranges=[dict(start_va=chunk['va'], **{key: value for key, value in chunk.items() if key != 'va'})
                                  for chunk in source['chunks']],
               declared_chunks=[dict(start_va=chunk['va'], end_va=hex(int(chunk['va'], 16) + chunk['size']),
                                     is_main=chunk['va'] == source['va']) for chunk in source['chunks']])
    result = dict(disk_sha256=bounded['disk_sha256'],
                  scope='历史仅导出记录的本批审阅适配；非新增导出', functions=[row],
                  sources=[dict(path=path, source_sha256=row['source_sha256'])])
    (HERE / 'reused_functions.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print('adapted: 8 new, 1 historical')


if __name__ == '__main__':
    main()
