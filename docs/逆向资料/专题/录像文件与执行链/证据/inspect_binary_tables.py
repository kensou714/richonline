"""从当前PE读取F11分支表和主状态表，不通过修改内存试运行。"""
import hashlib,json,re,struct
from pathlib import Path
ROOT=Path(r'F:\大富翁online\Richonline');OUT=Path(__file__).resolve().parent
b=(ROOT/'RnClient.exe').read_bytes();pe=struct.unpack_from('<I',b,60)[0]
n=struct.unpack_from('<H',b,pe+6)[0];opt=struct.unpack_from('<H',b,pe+20)[0]
base=struct.unpack_from('<I',b,pe+52)[0]
sections=[struct.unpack_from('<IIII',b,pe+24+opt+40*i+8) for i in range(n)]
def at(va,size):
    for _,rva,raw,off in sections:
        d=va-base-rva
        if 0<=d and d+size<=raw:return b[off+d:off+d+size]
    raise ValueError(hex(va))
def target(va):
    try:
        raw=at(va,5)
    except ValueError:
        return None
    return va+5+int.from_bytes(raw[1:],'little',signed=True) if raw[0]==0xe9 else va
def row(va,size):return dict(va=hex(va),size=size,disk_hex=at(va,size).hex())
assert at(0x7062B0,3)==b'\xff\x24\x85'
jumpbase=int.from_bytes(at(0x7062B3,4),'little')
switch=[]
for command in (90,91,92,150,151,160,161,201,202):
    index=at(0x706E82+command-90,1)[0]
    dst=int.from_bytes(at(jumpbase+index*4,4),'little')
    switch.append(dict(command=command,index=index,target=hex(dst)))
assert len({x['target'] for x in switch if x['command'] in (150,151,160,161)})==1
assert at(0x624D93,3)==b'\xff\x14\x95'
table=int.from_bytes(at(0x624D96,4),'little')
states=[]
for i in range(16):
    pointer=int.from_bytes(at(table+4*i,4),'little')
    states.append(dict(index=i,pointer=hex(pointer),resolved=hex(target(pointer)) if pointer and target(pointer) is not None else None))
strings=[]
for match in re.finditer(rb'[\x20-\x7e]{4,}',b):
    if re.search(rb'rcd|replay|record|run_|video',match[0],re.I):
        va=next((base+rva+match.start()-off for _,rva,size,off in sections if off<=match.start()<off+size),None)
        strings.append(dict(va=hex(va) if va else None,text=match[0].decode('ascii')))
result=dict(disk_sha256=hashlib.sha256(b).hexdigest(),switch_rows=switch,
    state_table_window=states,state_table_window_warning='只读64B窗口，不据此指定表长度；0/null保留原值。',
    raw_ranges=[row(0x7062B0,7),row(0x706E82,113),row(jumpbase,7*4),row(0x624D93,7),row(table,64),row(0x60EAFF,5)],
    digest_helper_bridge=dict(va='0x60eaff',target=hex(target(0x60EAFF))),
    ascii_candidates=strings,string_scope='当前PE可打印ASCII连续4字节以上；不覆盖混合编码/逐字构造/压缩资源。')
(OUT/'binary_tables.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(switch_rows=switch,state_table_window=states,ascii_candidates=strings),ensure_ascii=True))
