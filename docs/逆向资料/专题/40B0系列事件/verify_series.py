"""复核保存的IDA字节与当前PE；生成明确分级的逐函数清单。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for i in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        _, rva, length, offset = struct.unpack_from('<IIII', blob, pe + 24 + size + i * 40 + 8)
        sections.append((rva, length, offset))

    def check(region):
        va, n = int(region['va'], 16), region['size']
        disk = None
        for rva, length, offset in sections:
            delta = va - base - rva
            if 0 <= delta and delta + n <= length:
                disk = blob[offset + delta:offset + delta + n]
                break
        saved = bytes.fromhex(region['idb_hex'])
        return disk == saved and len(saved) == n and region['disk_hex'] == saved.hex() and region['matching']

    functions, thunks, ranges, declared_chunks = {}, {}, {}, set()
    failures = []
    for file in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(file.read_text(encoding='utf-8'))
        for function in data.get('functions', []):
            chunks = function.get('declared_chunks', [])
            assert chunks, file.name + ':' + function['va'] + '缺少声明块清单'
            # 显式检查声明主块和SEH尾块逐字节均由原证区间覆盖，不能只看主范围。
            for chunk in chunks:
                start, end = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                assert start < end
                declared_chunks.add((function['va'], start, end))
                cursor = start
                for region in sorted(function['byte_ranges'], key=lambda r: int(r['va'], 16)):
                    low, high = int(region['va'], 16), int(region['va'], 16) + region['size']
                    if low <= cursor < high:
                        cursor = min(high, end)
                    if cursor == end:
                        break
                assert cursor == end, file.name + ':' + function['va'] + '声明块原证遗漏' + hex(cursor)
            functions.setdefault(function['va'], {'function': function, 'evidence': []})['evidence'].append('证据/' + file.name)
            for region in function['byte_ranges']:
                ranges[(region['va'], region['size'])] = region
                if not check(region):
                    failures.append(file.name + ':' + region['va'])
        for region in data.get('thunks', []):
            thunks[region['va']] = region
            if not check(region):
                failures.append(file.name + ':' + region['va'])
        for region in data.get('regions', []):
            if not check(region):
                failures.append(file.name + ':' + region['va'])
    notes = json.loads((HERE / 'manual_conclusions.json').read_text(encoding='utf-8'))
    assert not set(notes) - set(functions), '人工结论缺少函数原证'
    registration = json.loads((HERE / '证据/registration_and_data.json').read_text(encoding='utf-8'))
    bridges = {item['target']: item for item in registration['registration']}
    reviews = []
    for va, data in sorted(functions.items(), key=lambda item: int(item[0], 16)):
        function = data['function']
        if va in notes:
            status = '静态局部语义已审阅'
            conclusion, unknown = notes[va]['conclusion'], notes[va]['unknown']
        elif va in bridges:
            status = '回复或本地分派桥接已核对'
            row = bridges[va]
            conclusion = row['code'] + '的cdecl分派桥，以ECX游戏对象和一个栈参数转thiscall业务处理。'
            unknown = '桥接本身不证明包长校验或完整业务效果，目标清单另列。'
        else:
            status = '仅导出'
            conclusion = '本群的直接依赖原证，保留伪码、汇编、调用与当前PE字节；未提升为完整业务审阅。'
            unknown = '完整分支与外部资源仍待专题分析；原证导出不计作完成。'
        reviews.append({'va': va, 'name': function['name'], 'status': status,
                        'conclusion': conclusion, 'unknown': unknown,
                        'evidence': data['evidence'], 'document': '00_阅读入口.txt'})
    (HERE / '函数审阅清单.json').write_text(json.dumps(reviews, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    undefined = [{'va': '0x6332f0', 'end_va': '0x63341b', 'status': '未定义代码范围局部已审阅',
                  'conclusion': '动画17启动，复制目标、固定减量5、记录tick/未破坏、取图像并设置相机/坐标。',
                  'unknown': 'IDA未声明入口；不增加已声明函数覆盖数，未创建函数或修改数据库。',
                  'evidence': '证据/registration_and_data.json', 'document': '02_地产字段与动画执行.txt'}]
    (HERE / '未定义范围审阅.json').write_text(json.dumps(undefined, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    resources = json.loads((HERE / '资源原证.json').read_text(encoding='utf-8'))
    for resource in resources:
        if hashlib.sha256((ROOT / resource['path']).read_bytes()).hexdigest() != resource['sha256']:
            failures.append(resource['path'])
    report = {'disk_sha256': hashlib.sha256(blob).hexdigest(), 'declared_functions': len(functions),
              'unique_ranges': len(ranges), 'declared_chunks': len(declared_chunks),
              'declared_chunks_fully_covered': True,
              'instruction_bytes': sum(r['size'] for r in ranges.values()),
              'unique_thunks': len(thunks), 'extra_regions': len(registration['regions']),
              'undefined_ranges': len(undefined), 'resources': len(resources),
              'states': dict(Counter(r['status'] for r in reviews)), 'failures': failures,
              'scope': '当前PE与已保存IDA字节三方核对；无运行验证，语义结论为人工局部审阅'}
    (HERE / '专题验证.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    assert not failures, '原证字节或资源哈希不一致'


if __name__ == '__main__':
    main()
