"""从已核汇编与伪码还原65个输出事件，不推测尚无调用者的事件用途。"""
from pathlib import Path
import json
import re
import struct

BASE = Path(__file__).resolve().parent
core = json.loads((BASE/'core.json').read_text('utf-8'))
f = next(f for f in core['functions'] if f['va']=='0x7dcfe0')
pseudo = '\n'.join(f['pseudocode']) if isinstance(f['pseudocode'],list) else f['pseudocode']
data = json.loads((BASE/'data_audit.json').read_text('utf-8'))
resource = json.loads((BASE/'resource.json').read_text('utf-8'))
strings = {e['indx']:e['win32'] for e in resource['entries']}
rows = []
for event in list(range(64))+[128]:
    if event==128:
        block = pseudo[pseudo.index('if ( *a2 == 128 )'):pseudo.index('    result = this;',pseudo.index('if ( *a2 == 128 )'))]
        start,end = 0x7DDCD3,0x7DDCEB
    else:
        start = int(data['switch_targets'][event],16)
        end = int(data['switch_targets'][event+1],16) if event<63 else 0x7DDC9F
        block = re.search(r'      case '+str(event)+r':\n(.*?)(?=      case |      default:)',pseudo,re.S)[1]
    values = {}
    for name,index in re.findall(r'(v\d+) = \(const char \*\)sub_60EBD1\(a1: (\d+)\);',block):
        values[name] = dict(kind='resource',index=int(index))
    for name,index in re.findall(r'(v\d+) = (?:\(const char \*\))?a2\[(\d+)\];',block):
        values[name] = dict(kind='parameter',offset=int(index)*4)
    call = re.search(r'j__sprintf\(Buffer: .*?, Format: ".*?", (.*?)\);',block)[1]
    arguments = []
    for argument in call.split(', '):
        match = re.fullmatch(r'(?:\(const char \*\))?a2\[(\d+)\]',argument)
        arguments.append(dict(kind='parameter',offset=int(match[1])*4) if match else values[argument])
    instructions = [i for i in f['assembly'] if start<=int(i['va'],16)<end]
    format_ins = [i for i in instructions if 'push    offset a' in i['text'] and '%s' in i['text']]
    assert len(format_ins)==1,(event,format_ins)
    address = int(format_ins[0]['va'],16)
    span = next(r for r in f['byte_ranges'] if int(r['va'],16)<=address<int(r['va'],16)+r['size'])
    raw = bytes.fromhex(span['idb_hex'])
    offset = address-int(span['va'],16)
    assert raw[offset]==0x68
    format_va = hex(struct.unpack_from('<I',raw,offset+1)[0])
    fmt = data['strings'][format_va]['ascii']
    specifiers = re.findall('%[sd]',fmt)
    assert len(specifiers)==len(arguments)
    rendered = fmt
    for spec,arg in zip(specifiers,arguments):
        if arg['kind']=='resource':
            value = strings[arg['index']]
        else:
            arg['type'] = 'NUL结尾字符串指针' if spec=='%s' else '有符号32位整数'
            value = '{参数+'+str(arg['offset'])+('字符串}' if spec=='%s' else '整数}')
        rendered = rendered.replace(spec,value,1)
    rows.append(dict(event=event,branch_va=hex(start),channel='Game' if event==128 else 'Sys',
                     format_va=format_va,format=fmt,arguments=arguments,template=rendered,
                     minimum_record_bytes=max([4]+[a['offset']+4 for a in arguments if a['kind']=='parameter']),
                     fixed_output_cp950_bytes=len(rendered.encode('cp950')) if not any(a['kind']=='parameter' for a in arguments) else None,
                     source_pseudocode=block.splitlines()))
result = dict(formatter='0x7dcfe0',record_layout='首DWORD事件号；其余DWORD按具体事件作指针或整数',
              no_output_ranges=['64..127','129..255','负数或大于255'],events=rows)
(BASE/'event_dictionary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines = ['// 事件号与参数字典','//','// 参数偏移相对传入记录；字符串为本进程32位指针，不是网络线上字段。',
         '// 以下文字保持当前CP950资源的繁体原文；每条末尾由格式串添加LF。',
         '// 0..63写Sys；128写Game；其它事件清空临时首字节后不输出。','//']
for row in rows:
    params = [str(a['offset'])+'='+a['type'] for a in row['arguments'] if a['kind']=='parameter']
    lines.append('// '+str(row['event']).rjust(3)+'  '+('；'.join(params) if params else '无附加参数'))
    lines.append('//      '+row['template'].rstrip('\n'))
(BASE.parent/'02_事件参数字典.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps(dict(events=len(rows),static_max_bytes=max(r['fixed_output_cp950_bytes'] or 0 for r in rows))))
