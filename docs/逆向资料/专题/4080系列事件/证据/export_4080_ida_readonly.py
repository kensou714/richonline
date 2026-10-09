"""在本代理的 IDA 租约执行：只读函数、指令与数据，仅写本专题原证。"""
from pathlib import Path
import hashlib
import json
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_nalt
import idautils

BASE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def read_range(start, end):
    raw = ida_bytes.get_bytes(start, end-start)
    if raw is None or len(raw) != end-start:
        raise ValueError(f'无法读取完整区间 {start:#x}..{end:#x}')
    return {'start': hex(start), 'end': hex(end), 'bytes_hex': raw.hex(), 'sha256': digest(raw)}


def disassemble(chunks):
    return [{'address': hex(ea), 'text': ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0))}
            for chunk in chunks for ea in idautils.Heads(int(chunk['start'], 16), int(chunk['end'], 16))]


def main():
    annotations = json.loads((BASE / 'review_annotations.json').read_text(encoding='utf-8'))
    functions = []
    ranges = []
    for item in annotations['entries']:
        ea = int(item['address'], 16)
        if item['kind'] == 'code_range':
            if ida_funcs.get_func(ea) is not None:
                raise ValueError(f'代码区间 {ea:#x} 现已有函数定义，应重新审阅范围')
            chunks = [read_range(ea, int(item['end'], 16))]
            ranges.append({'address': item['address'], 'name': '未定义函数代码区间',
                           'review_scope': item['conclusion'], 'chunks': chunks,
                           'assembly': disassemble(chunks), 'pseudocode': []})
            continue
        function = ida_funcs.get_func(ea)
        if function is None or function.start_ea != ea:
            raise ValueError(f'不是所记录函数入口 {ea:#x}')
        chunks = [read_range(start, end) for start, end in idautils.Chunks(ea)]
        pseudocode = []
        error = None
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is None:
                raise ValueError('Hex-Rays未返回函数')
            pseudocode = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
        except Exception as exc:
            error = str(exc)
        functions.append({'address': item['address'], 'name': ida_funcs.get_func_name(ea),
                          'review_scope': item['conclusion'], 'chunks': chunks,
                          'assembly': disassemble(chunks), 'pseudocode': pseudocode,
                          'decompile_error': error,
                          'xrefs_to': [{'site': hex(x.frm), 'iscode': bool(x.iscode)}
                                       for x in idautils.XrefsTo(ea, 0)]})
    # 跳板只识别直接5/6字节jmp；识别并不将目标业务自动标为完成。
    thunk_addresses = set(annotations['extra_thunks'])
    for function in functions + ranges:
        for instruction in function['assembly']:
            if instruction['text'].startswith('call'):
                for xref in idautils.XrefsFrom(int(instruction['address'], 16), 0):
                    target = ida_funcs.get_func(xref.to)
                    if xref.iscode and target and target.start_ea == xref.to:
                        if target.end_ea-target.start_ea <= 6:
                            thunk_addresses.add(hex(target.start_ea))
    thunks = []
    for address in sorted(thunk_addresses, key=lambda value: int(value, 16)):
        ea = int(address, 16)
        function = ida_funcs.get_func(ea)
        if not function or function.start_ea != ea:
            raise ValueError(f'跳板入口丢失 {address}')
        raw = ida_bytes.get_bytes(ea, function.end_ea-ea)
        thunks.append({'address': address, 'assembly': ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0)),
                       'bytes_hex': raw.hex(), 'sha256': digest(raw),
                       'targets': [hex(x.to) for x in idautils.XrefsFrom(ea, 0) if x.iscode]})
    data = []
    for address in annotations['vtables']:
        raw = ida_bytes.get_bytes(int(address, 16), 12)
        data.append({'address': address, 'scope': 'start/end/tick三项虚表原证',
                     'bytes_hex': raw.hex(), 'sha256': digest(raw)})
    source = {'binary': 'RnClient.exe',
              'database_input_sha256': ida_nalt.retrieve_input_file_sha256().hex().upper(),
              'functions': functions, 'code_ranges': ranges, 'thunks': thunks, 'data_ranges': data}
    (BASE / '4080_IDA原证.json').write_text(json.dumps(source, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'functions': len(functions), 'code_ranges': len(ranges),
                      'thunks': len(thunks), 'data_ranges': len(data)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
