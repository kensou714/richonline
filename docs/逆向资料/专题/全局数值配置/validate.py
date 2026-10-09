"""核对当前EXE机器字节、完整块指令范围及配置严格解码结果。"""
import hashlib
import json
import struct
from pathlib import Path

from inspect_resource import HERE, ROOT, inspect


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    require(blob[pe:pe + 4] == b'PE\0\0', '不是PE')
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional + index * 40
        vs, rva, rs, off = struct.unpack_from('<IIII', blob, at + 8)
        sections.append({'name': blob[at:at + 8].rstrip(b'\0').decode('ascii'),
                         'virtual_size': vs, 'rva': rva, 'raw_size': rs, 'raw_offset': off})

    def disk(va, size):
        for section in sections:
            relative = va - base - section['rva']
            if 0 <= relative and relative + size <= section['raw_size']:
                return blob[section['raw_offset'] + relative:section['raw_offset'] + relative + size]
        raise ValueError('无磁盘原始映射：' + hex(va))

    def check(span):
        raw = disk(int(span['va'], 16), span['size'])
        require(raw.hex() == span['disk_hex'] == span['idb_hex'], '字节不符：' + span['va'])
        if 'target' in span:
            require(raw[0] == 0xE9 and int(span['target'], 16) ==
                    int(span['va'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0], '跳板目标不符')

    functions = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    require(functions['disk_sha256'] == digest, 'EXE指纹不符')
    instruction_count = instruction_bytes = chunk_count = 0
    for function in functions['functions']:
        for span in function['byte_ranges']:
            check(span)
        chunk_count += len(function['declared_chunks'])
        for chunk in function['declared_chunks']:
            require(any(int(chunk['start_va'], 16) <= int(row['va'], 16) < int(chunk['end_va'], 16)
                        for row in function['assembly']), '声明块未保存指令')
        for row in function['assembly']:
            address = int(row['va'], 16)
            require(any(int(c['start_va'], 16) <= address and address + row['size'] <= int(c['end_va'], 16)
                        for c in function['declared_chunks']), '指令越出函数块')
            require(any(int(c['va'], 16) <= address and address + row['size'] <= int(c['va'], 16) + c['size']
                        for c in function['byte_ranges']), '指令没有字节证据')
            instruction_count += 1
            instruction_bytes += row['size']
    for thunk in functions['thunks']:
        check(thunk)
    saved = json.loads((HERE / '证据/resource.json').read_text(encoding='utf-8'))
    require(saved == inspect(), '配置解码或字段发生变化')
    require([item['index'] for item in saved['items']] == list(range(38)), '当前索引集合变化')
    refs = json.loads((HERE / '证据/references.json').read_text(encoding='utf-8'))
    require(refs['disk_sha256'] == digest, '引用证据指纹不符')
    require({r['function'] for r in refs['references'] if r['function']} <=
            {f['va'] for f in functions['functions']}, '引用消费者缺少函数原证')
    recheck = json.loads((HERE / '证据/ida_recheck.json').read_text(encoding='utf-8'))
    require(recheck['disk_sha256'] == digest and not recheck['mismatches'], 'IDA复核指纹或结果不符')
    saved_functions = {f['va']: f for f in functions['functions']}
    checked_functions = {f['va']: f for f in recheck['functions']}
    require(len(saved_functions) == len(functions['functions']) and
            len(checked_functions) == len(recheck['functions']), '函数地址重复')
    require(saved_functions.keys() == checked_functions.keys(), 'IDA复核函数集合不符')
    for va, function in saved_functions.items():
        checked = checked_functions[va]
        require(checked['declared_chunks'] == function['declared_chunks'] and
                checked['instruction_count'] == len(function['assembly']) and
                checked['instruction_bytes'] == sum(row['size'] for row in function['assembly']),
                'IDA复核块或指令统计不符：' + va)
    review = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    require(len(review['functions']) == len(saved_functions) and
            {f['va'] for f in review['functions']} == saved_functions.keys(), '审阅清单函数集合不符')
    require(all(all(f.get(key) for key in ('status', 'conclusion', 'unknown', 'evidence'))
                for f in review['functions']), '审阅清单缺少状态或证据边界')
    for path in HERE.glob('*.txt'):
        require(all(not line.strip() or line.startswith('//') for line in
                    path.read_text(encoding='utf-8').splitlines()), '正文不是注释式：' + path.name)
    section = next(s for s in sections if s['rva'] <= 0xA87080 - base <
                   s['rva'] + max(s['virtual_size'], s['raw_size']))
    require(0xA87080 - base - section['rva'] >= section['raw_size'], '配置起点现有磁盘映射，需重审')
    result = {'disk_sha256': digest, 'function_count': len(functions['functions']),
              'chunk_count': chunk_count, 'instruction_count': instruction_count,
              'instruction_bytes': instruction_bytes, 'thunk_count': len(functions['thunks']),
              'reference_count': len(refs['references']), 'resource_item_count': 38,
              'resource_sha256': saved['source_sha256'], 'configuration_pe_section': section,
              'current_bytes_match': True,
              'ida_recheck_function_count': len(checked_functions),
              'ida_recheck_matches': True, 'review_function_count': len(review['functions']),
              'scope': '仅机器字节、导出结构与资源解码验证；不代表全部消费者语义或实机行为已验证'}
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
