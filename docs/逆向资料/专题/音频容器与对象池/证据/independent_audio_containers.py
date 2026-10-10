"""独审只读核完整IDA块、当前PE、指令集合和复制表，结果不修改作者证据。"""
import hashlib
import itertools
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(db):
    import idautils
    import ida_bytes

    source = HERE / 'audio_containers.json'
    data = json.loads(source.read_text(encoding='utf-8'))
    image = Path(data['input']).read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    assert sha == data['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]
    ranges, main_ranges, context_ranges, counts = [], [], [], {'comparisons': 0}

    def check(row):
        start, size = int(row['va'], 16), row['size']
        mapping = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= start and start + size <= base + rva + raw]
        assert len(mapping) == 1, hex(start)
        rva, off = mapping[0]
        offset = off + start - base - rva
        raw = image[offset:offset + size]
        assert raw.hex() == row['ida_hex'] == row['disk_hex'], hex(start)
        assert raw == db.bytes.get_bytes_at(start, size), hex(start)
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        ranges.append((start, start + size))
        counts['comparisons'] += 1
        return raw

    for kind, functions, group_ranges in [('main', data['functions'], main_ranges),
                                          ('context', data['contexts'], context_ranges)]:
        counts[kind + '_functions'] = len(functions)
        counts[kind + '_chunks'] = counts[kind + '_instructions'] = 0
        for row in functions:
            va = int(row['va'], 16)
            f = db.functions.get_at(va)
            assert f and f.start_ea == va, hex(va)
            declared = {(int(c['va'], 16), int(c['end'], 16)) for c in row['chunks']}
            actual = {(c.start_ea, c.end_ea) for c in db.functions.get_chunks(f)}
            assert declared == actual == set(idautils.Chunks(va)), hex(va)
            addresses = {i.ea for start, end in actual for i in db.instructions.get_between(start, end)
                         if ida_bytes.is_code(ida_bytes.get_full_flags(i.ea))}
            code_heads = {ea for start, end in actual for ea in idautils.Heads(start, end)
                          if ida_bytes.is_code(ida_bytes.get_full_flags(ea))}
            assert addresses == code_heads, hex(va)
            assert addresses == {int(i['va'], 16) for i in row['instructions']}, hex(va)
            for chunk in row['chunks']:
                check(chunk)
                group_ranges.append((int(chunk['va'], 16), int(chunk['end'], 16)))
            for instruction in row['instructions']:
                assert db.bytes.get_bytes_at(int(instruction['va'], 16), instruction['size']).hex() == instruction['hex']
            counts[kind + '_chunks'] += len(actual)
            counts[kind + '_instructions'] += len(addresses)
    seen_thunks = set()
    for row in data['thunks']:
        raw = check(row)
        va = int(row['va'], 16)
        assert va not in seen_thunks
        seen_thunks.add(va)
        assert len(raw) == 5 and raw[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
    copy = next(f for f in data['functions'] if f['va'] == '0x9213a0')
    copy_addresses = {int(i['va'], 16) for i in copy['instructions']}
    crt_source = HERE.parents[1] / 'CRT复制与重叠边界/证据/crt_copy.json'
    crt = json.loads(crt_source.read_text(encoding='utf-8'))
    crt_copy = next(f for f in crt['functions'] if int(f['va'], 16) == 0x9213A0)
    assert [(c['va'], c['size'], c['ida_hex']) for c in copy['chunks']] == [
        (c['va'], c['size'], c['idb_hex']) for c in crt_copy['chunk_byte_ranges']]
    for row in data['copy_tables']:
        raw = check(row)
        targets = list(struct.unpack('<' + 'I' * (len(raw) // 4), raw))
        assert targets == [int(t, 16) for t in row['targets']]
        assert all(t in copy_addresses for t in targets)
        assert any(start <= int(row['va'], 16) and int(row['va'], 16) + len(raw) <= end
                   for start, end in main_ranges)

    def union_size(spans):
        result = []
        for start, end in sorted(set(spans)):
            if result and start <= result[-1][1]:
                result[-1][1] = max(end, result[-1][1])
            else:
                result.append([start, end])
        return sum(end - start for start, end in result)

    # 这里只枚举合法容器状态，列表预期由切片建立；不执行原机器码。
    model_cases = 0
    for count in range(1, 17):
        original = list(range(count))
        for index in range(count):
            expected_insert = original[:index] + [999] + original[index:]
            for capacity in (count, count + 3):
                slots = original[:] + [None] * (capacity - count)
                if capacity <= count:
                    slots = slots[:index] + [999] + slots[index:] + [None] * 31
                else:
                    moved = slots[index:count]
                    slots[index + 1:count + 1] = moved
                    slots[index] = 999
                assert slots[:count + 1] == expected_insert
                model_cases += 1
            slots = original[:]
            slots[index:count - 1] = slots[index + 1:count]
            assert slots[:count - 1] == original[:index] + original[index + 1:]
            model_cases += 1
    counts.update(e9_thunks=len(seen_thunks), copy_tables=len(data['copy_tables']),
                  copy_table_bytes=sum(t['size'] for t in data['copy_tables']),
                  unique_spans=len(set(ranges)), main_union_bytes=union_size(main_ranges),
                  context_union_bytes=union_size(context_ranges), unique_byte_coverage=union_size(ranges),
                  container_model_cases=model_cases)
    result = dict(execution_source='独审代理自身IDA租约；数据库只读', disk_sha256=sha,
                  source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), counts=counts,
                  crt_reuse=dict(source_sha256=hashlib.sha256(crt_source.read_bytes()).hexdigest(),
                                 va='0x9213a0', size=829, equal=True,
                                 chunk_sha256=copy['chunks'][0]['sha256']),
                  failures=0, limitation='静态PE/IDA及合法状态模型；模型非机器码仿真或实机。')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                                   encoding='utf-8', newline='\n')
    return result
