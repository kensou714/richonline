"""核验当前EXE、完整声明块、指令范围、跳板和显式审阅清单。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + index * 40 + 8)
                for index in range(count)]

    def require(value, message):
        if not value:
            raise ValueError(message)

    def check(span):
        address = int(span['va'], 16)
        raw = None
        for _, rva, size, offset in sections:
            relative = address - base - rva
            if 0 <= relative and relative + span['size'] <= size:
                raw = blob[offset + relative:offset + relative + span['size']]
                break
        require(raw is not None and raw.hex() == span.get('disk_hex', span['idb_hex']) == span['idb_hex'], '字节不符：' + span['va'])
        if 'target' in span:
            require(raw[0] == 0xE9 and address + 5 + struct.unpack_from('<i', raw, 1)[0] == int(span['target'], 16), '跳板不符')

    def read(name):
        return json.loads((HERE / name).read_text(encoding='utf-8'))

    data, recheck, review = [read(name) for name in
                            ('证据/functions.json', '证据/ida_recheck.json', '函数审阅清单.json')]
    require(data['disk_sha256'] == recheck['disk_sha256'] == digest, '指纹不符')
    require(not recheck['mismatches'], 'IDA复读不符')
    functions = {f['va']: f for f in data['functions']}
    checked = {f['va']: f for f in recheck['functions']}
    require(len(functions) == len(data['functions']) and functions.keys() == checked.keys(), '复读函数集合不符')
    require(len(review['functions']) == len(functions) and
            {f['va'] for f in review['functions']} == functions.keys(), '审阅函数集合不符')
    instruction_count = instruction_bytes = chunk_count = declared_bytes = 0
    for va, function in functions.items():
        for span in function['byte_ranges'] + function['chunk_byte_ranges']:
            check(span)
        chunks = function['declared_chunks']
        require([(int(c['start_va'], 16), int(c['end_va'], 16)) for c in chunks] ==
                [(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in function['chunk_byte_ranges']], '声明块原证缺失')
        for row in function['assembly']:
            address = int(row['va'], 16)
            require(any(int(c['start_va'], 16) <= address and address + row['size'] <= int(c['end_va'], 16)
                        for c in chunks), '指令越界')
        size = sum(row['size'] for row in function['assembly'])
        require(checked[va]['declared_chunks'] == chunks and
                checked[va]['instruction_count'] == len(function['assembly']) and
                checked[va]['instruction_bytes'] == size, '复读统计不符')
        instruction_count += len(function['assembly'])
        instruction_bytes += size
        chunk_count += len(chunks)
        declared_bytes += sum(c['size'] for c in function['chunk_byte_ranges'])
    for thunk in data['thunks']:
        check(thunk)
    contract = read('证据/回调与常量.json')
    for row in contract['callbacks'] + contract['constants']:
        check(row)
    require(all(row['target'] in functions for row in contract['callbacks']), '参数回调目标未导出')
    references = read('证据/引用闭合.json')
    calls = {(row['site'], row['target']) for f in data['functions'] for row in f['calls']}
    thunks = {(row['va'], row['target']) for row in data['thunks']}
    for row in references:
        require((row['source'], row['target']) in (thunks if row['e9_bridge'] else calls), '引用闭合缺少原证')
    for item in review['functions']:
        require(all(item.get(key) for key in ('va', 'status', 'conclusion', 'unknown', 'evidence')), '审阅边界缺失')
    for path in HERE.glob('*.txt'):
        require(all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines()), '非注释式正文')
    result = dict(disk_sha256=digest, function_count=len(functions), chunk_count=chunk_count,
                  instruction_count=instruction_count, instruction_bytes=instruction_bytes,
                  declared_chunk_bytes=declared_bytes, thunk_count=len(data['thunks']),
                  callback_bridge_count=len(contract['callbacks']), constant_count=len(contract['constants']),
                  reference_count=len(references),
                  current_bytes_match=True, ida_recheck_matches=True,
                  scope='完整函数块、字节与台账的静态核验；不代表已验证运行时节拍、网络延迟或暂停行为')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
