"""独审者编写的只读IDA复验；由持有有效租约的作者代理执行，不更改数据库。"""
import hashlib
import json
from pathlib import Path

BASE = Path(r'F:\大富翁online\Richonline\docs\逆向资料\专题\40C7系列事件\证据')
review = json.loads((BASE / 'function_review.json').read_text('utf-8'))
counts = dict(unique_functions=0, function_entries=0, declared_chunks=0,
              instruction_addresses=0, byte_comparisons=0, undeclared_ranges=0)
seen = set()


def check_bytes(row):
    key = 'idb_hex' if 'idb_hex' in row else 'idb_bytes'
    expected = row[key]
    assert db.bytes.get_bytes_at(int(row['va'], 16), row['size']).hex() == expected, row['va']
    counts['byte_comparisons'] += 1


for source in review['sources']:
    evidence = json.loads((BASE / source).read_text('utf-8'))
    for item in evidence['functions']:
        va = int(item['va'], 16)
        f = db.functions.get_at(va)
        assert f is not None and f.start_ea == va, item['va']
        chunks = list(db.functions.get_chunks(f))
        assert [(c.start_ea, c.end_ea) for c in chunks] == [
            (int(c['start_va'], 16), int(c['end_va'], 16)) for c in item['declared_chunks']
        ], item['va']
        actual = {i.ea for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
        expected = {int(i['va'], 16) for i in item['assembly']}
        assert actual == expected, (item['va'], sorted(actual - expected), sorted(expected - actual))
        if va not in seen:
            seen.add(va)
            counts['declared_chunks'] += len(chunks)
            counts['instruction_addresses'] += len(actual)
        counts['function_entries'] += 1
        for row in item['byte_ranges']:
            check_bytes(row)
    for row in evidence['thunks']:
        check_bytes(row)

for row in json.loads((BASE / 'undeclared_ranges.json').read_text('utf-8'))['ranges']:
    start, end = int(row['va'], 16), int(row['end_va'], 16)
    assert db.functions.get_at(start) is None, row['va']
    actual = {i.ea for i in db.instructions.get_between(start, end)}
    assert actual == {int(i['va'], 16) for i in row['assembly']}, row['va']
    for byte_range in row['byte_ranges']:
        check_bytes(byte_range)
    counts['undeclared_ranges'] += 1

data = json.loads((BASE / 'data_audit.json').read_text('utf-8'))
for row in data['records'] + data['virtual_thunks']:
    check_bytes(row)
for row in json.loads((BASE / 'binding.json').read_text('utf-8'))['entries']:
    for key in ('thunk_audit', 'handler_thunk_audit', 'registration_write_audit'):
        check_bytes(row[key])
counts['unique_functions'] = len(seen)
print(json.dumps(dict(passed=True, counts=counts,
                     script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     scope='独审脚本，由作者在其有效IDA租约代理只读执行；并非独审者直接持有租约。'),
                 ensure_ascii=True))
