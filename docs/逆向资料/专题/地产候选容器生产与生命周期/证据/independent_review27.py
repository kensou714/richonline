"""第二十七批地产容器独立审阅。

本脚本不连接 IDA，也不修改原证；只用当前 RnClient.exe、作者 bounded_raw
以及已经冻结的旧中文/异常尾块原证做可重复核验。结论中的“新”按全量资料
去重，而不是按本批重新采证次数计算。
"""
from __future__ import annotations

import hashlib
import json
import struct
import argparse
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

ROOT = Path(__file__).resolve().parents[5]
TOPIC = Path(__file__).resolve().parents[1]
RAW_PATH = TOPIC / "证据" / "bounded_raw.json"
PE = ROOT / "RnClient.exe"
EXPECTED_PE = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
LEGACY_PATH = ROOT / "docs/逆向资料/专题/地图与路径/证据/map_runtime_core.json"
CLEANUP_PATH = ROOT / "docs/逆向资料/全量分析/异常尾块与清理契约/cleanup_targets_full.json"
RAW_SHA = "dfd483b21b8b4211368295e6af6e52cab0532bd972fba62395a693d033309495"
LEGACY_SHA = "5f5edfd13986b030fde915284725add0bf36285274f3f1bcb581c1a5c13f2de4"
CLEANUP_SHA = "a496de5fc366a794677e2b7274c36de7389de4da99614d79be99cf881681f4c2"
MD = Cs(CS_ARCH_X86, CS_MODE_32)
MD.detail = True


class ByteAudit:
    """独立按 PE 节表映射 VA；每条声明只核其实际磁盘 raw 范围。"""
    def __init__(self):
        self.disk = PE.read_bytes()
        die(hashlib.sha256(self.disk).hexdigest() != EXPECTED_PE, "PE 指纹变化")
        pe = struct.unpack_from('<I', self.disk, 0x3C)[0]
        self.base = struct.unpack_from('<I', self.disk, pe + 52)[0]
        table = pe + 24 + struct.unpack_from('<H', self.disk, pe + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.disk, table + 40 * i + 8)
                         for i in range(struct.unpack_from('<H', self.disk, pe + 6)[0])]
        self.ranges = {}
        self.count = 0

    def read(self, va, size):
        candidates = [(rva, off) for _, rva, length, off in self.sections
                      if 0 <= va - self.base - rva and va - self.base - rva + size <= length]
        die(len(candidates) != 1, f"非唯一可读 raw 区间 {va:#x}/{size}")
        rva, off = candidates[0]
        offset = off + va - self.base - rva
        return self.disk[offset:offset + size]

    def check(self, va, size, idb_hex, disk_hex, where, digest=None):
        die(size <= 0, where + '：空区间')
        b = bytes.fromhex(idb_hex)
        die(len(b) != size or b != bytes.fromhex(disk_hex) or b != self.read(va, size), where + '：当前 PE/IDB/记录字节不一致')
        if digest:
            die(hashlib.sha256(b).hexdigest() != digest, where + '：范围哈希不符')
        key = (va, size)
        die(key in self.ranges and self.ranges[key] != b.hex(), where + '：同范围冲突')
        self.ranges[key] = b.hex()
        self.count += 1
        return list(MD.disasm(b, va))


def verify_bytes(raw, legacy, cleanup):
    audit = ByteAudit()
    def walk(obj, pointer=''):
        if isinstance(obj, dict):
            if {'start_va', 'size', 'idb_hex', 'disk_hex'} <= obj.keys():
                die(obj.get('matching') is not True, pointer + '：未声明匹配')
                audit.check(int(obj['start_va'], 16), obj['size'], obj['idb_hex'], obj['disk_hex'], pointer, obj.get('sha256'))
            for k, v in obj.items():
                walk(v, pointer + '/' + str(k))
        elif isinstance(obj, list):
            for k, v in enumerate(obj):
                walk(v, pointer + '/' + str(k))
    walk(raw)
    summary = []
    for f in raw['functions']:
        ins = []
        for block in f['chunk_byte_ranges']:
            ins += list(MD.disasm(bytes.fromhex(block['disk_hex']), int(block['start_va'], 16)))
        die([x.address for x in ins] != [int(x['site_va'],16) for x in f['assembly']], '两主体反汇编边界不符')
        die(sum(x.size for x in ins) != sum(x['size'] for x in f['chunk_byte_ranges']), '两主体存在未解码尾字节')
        summary.append({'va': f['seed_va'], 'bytes': sum(x.size for x in ins), 'instructions': len(ins)})
    for f in raw['legacy_reused_byte_audits']:
        index = int(f['source_pointer'].split('/')[-1])
        old = legacy['函数'][index]
        die(f['source_sha256'] != LEGACY_SHA or f['original_status'] != '已逐函数分析', '中文来源身份不符')
        die(old['地址'] != f['seed_va'] or old['状态'] != '已逐函数分析', '中文旧函数地位变化')
        cursor = int(f['seed_va'], 16)
        die(len(old['完整汇编']) != len(f['instruction_audits']), '四体旧指令数量不符')
        for i, row in enumerate(f['instruction_audits']):
            original = old['完整汇编'][i]
            die(row['source_pointer'] != f"/函数/{index}/完整汇编/{i}", '中文指令 JSONPointer 不符')
            die(row['site_va'] != original['地址'] or row['text'] != original['汇编'], '中文来源逐指令文本不符')
            b = original['字节核验']
            die(not b['匹配'] or b['IDB字节'] != row['current_idb_hex'] or b['磁盘字节'] != row['current_disk_hex'], '旧/新核验字节不符')
            va = int(row['site_va'],16)
            die(va != cursor, '四旧体连续性丢失')
            ins = audit.check(va, row['size'], row['current_idb_hex'], row['current_disk_hex'], row['source_pointer'], row['sha256'])
            die(len(ins)!=1 or ins[0].size != row['size'], '旧指令解码边界不符')
            cursor += row['size']
        die(cursor != int(f['seed_va'],16)+f['main_size'], '旧函数尾部不符')
        summary.append({'va':f['seed_va'],'bytes':f['main_size'],'instructions':len(f['instruction_audits'])})
    for index in (9, 10):
        f = cleanup['functions'][index]
        ins = []
        for b in f['byte_ranges']:
            ins += audit.check(int(b['va'],16),b['size'],b['idb_hex'],b['disk_hex'],f'cleanup/functions/{index}')
        die([x.address for x in ins] != [int(x['va'],16) for x in f['assembly']], '释放来源指令边界不符')
        summary.append({'va':f['va'],'bytes':sum(x.size for x in ins),'instructions':len(ins),'note':'旧释放链；7ECD80 与本批重复，不累加为新函数'})
    # 旧地图仅复用连续局部范围；明确补齐当前 owner 窗口间的空隙。
    windows = [(0,0x7DE357,0x7DE38C),(1,0x7DED3E,0x7DED73),
               (3,0x7DF542,0x7DF566),(3,0x7DF9BC,0x7DF9DD),
               (3,0x7DFBF1,0x7DFC96),(3,0x7DFCB6,0x7DFCCC),(3,0x7DFB21,0x7DFB65),
               (0,0xA153EE,0xA153FC),(1,0xA15414,0xA15430)]
    owner_records=[]
    for index,start,end in windows:
        rows=[x for x in legacy['函数'][index]['完整汇编'] if start<=int(x['地址'],16)<end]
        cursor=start
        for row in rows:
            va=int(row['地址'],16);b=row['字节核验'];size=len(bytes.fromhex(b['IDB字节']))
            die(va!=cursor or not b['匹配'],'局部 owner 证据有洞')
            ins=audit.check(va,size,b['IDB字节'],b['磁盘字节'],f'legacy/functions/{index}/{va:#x}')
            die(len(ins)!=1 or ins[0].size!=size,'局部 owner 解码不符')
            cursor+=size
        die(cursor!=end,'局部 owner 末边界不符')
        owner_records.append({'source_pointer':f'/函数/{index}','start_va':hex(start),'end_va':hex(end),'instructions':len(rows)})
    # 当前四桥来自本批 IDA；其余生产链桥仅离线核磁盘，不提升为本批 IDA 原证。
    bridges={0x6004B4:0x7ECF70,0x605A9F:0x7ECD50,0x60E528:0x7ECD80,0x60B576:0x91F6D0,
             0x60C9D5:0x7ECDB0,0x603F74:0x7ECE30,0x607084:0x63F540,0x606D69:0x692030}
    for va,target in bridges.items():
        b=audit.read(va,5)
        die(b[0]!=0xE9 or va+5+struct.unpack_from('<i',b,1)[0]!=target,f'桥目标错误 {va:#x}')
    return audit, {'byte_records':audit.count,'unique_ranges':len(audit.ranges),'decoded_functions':summary,'old_local_windows':owner_records,'bridges':{hex(k):hex(v) for k,v in bridges.items()}}


def signed(value, bits=32):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class Machine:
    """有限 x86 解释器；只执行本专题原证所列指令，外部分配/复制/释放显式合成。"""
    aliases = {'al':('eax',0,8),'ah':('eax',8,8),'ax':('eax',0,16),
               'cl':('ecx',0,8),'cx':('ecx',0,16),'dl':('edx',0,8),'dx':('edx',0,16)}

    def __init__(self, code, args=(), this=0x200000, fail_alloc=False):
        self.code = code
        self.regs = dict.fromkeys(('eax','ebx','ecx','edx','esi','edi','ebp','esp'),0)
        self.regs.update(ecx=this,esp=0x300100)
        self.memory = {}
        self.writes = []
        self.calls = []
        self.zf = self.sf = self.of = False
        self.fail_alloc = fail_alloc
        self.allocations = []
        self.put(0x300100,0xFEEDFACE,4)
        for i,arg in enumerate(args):self.put(0x300104+4*i,arg,4)

    def getreg(self,name):
        base,shift,bits=self.aliases.get(name,(name,0,32))
        return (self.regs[base]>>shift)&((1<<bits)-1)

    def setreg(self,name,value):
        base,shift,bits=self.aliases.get(name,(name,0,32));mask=((1<<bits)-1)<<shift
        self.regs[base]=(self.regs[base]&~mask)|((value<<shift)&mask)

    def get(self,addr,size):
        return sum(self.memory.get((addr+i)&0xFFFFFFFF,0)<<(8*i) for i in range(size))

    def put(self,addr,value,size):
        for i in range(size):self.memory[(addr+i)&0xFFFFFFFF]=(value>>(8*i))&255
        self.writes.append((addr&0xFFFFFFFF,size,value&((1<<(size*8))-1)))

    def address(self,ins,op):
        m=op.mem
        return ((self.getreg(ins.reg_name(m.base)) if m.base else 0)+(self.getreg(ins.reg_name(m.index))*m.scale if m.index else 0)+m.disp)&0xFFFFFFFF

    def value(self,ins,op):
        if op.type==X86_OP_REG:return self.getreg(ins.reg_name(op.reg))
        if op.type==X86_OP_IMM:return op.imm
        if op.type==X86_OP_MEM:return self.get(self.address(ins,op),op.size)
        die(True,'未知操作数')

    def assign(self,ins,op,v):
        if op.type==X86_OP_REG:self.setreg(ins.reg_name(op.reg),v)
        elif op.type==X86_OP_MEM:self.put(self.address(ins,op),v,op.size)
        else:die(True,'不可写操作数')

    def run(self,start,stop=None):
        pc=start
        for steps in range(1000):
            if pc==stop:return self.regs['eax']
            die(pc not in self.code,f'有限模型越出函数 {pc:#x}')
            i=self.code[pc];ops=i.operands;mn=i.mnemonic;pc+=i.size
            v=lambda n:self.value(i,ops[n])
            if mn=='push':self.regs['esp']-=4;self.put(self.regs['esp'],v(0),4)
            elif mn=='pop':self.assign(i,ops[0],self.get(self.regs['esp'],4));self.regs['esp']+=4
            elif mn in ('mov','movsx','movzx'):
                self.assign(i,ops[0],signed(v(1),ops[1].size*8) if mn=='movsx' else v(1))
            elif mn in ('add','sub','shl','imul'):
                a,b=(v(1),v(2)) if len(ops)==3 else (v(0),v(1))
                out={'add':lambda:a+b,'sub':lambda:a-b,'shl':lambda:a<<b,'imul':lambda:a*b}[mn]()
                self.assign(i,ops[0],out)
            elif mn in ('cmp','test'):
                a,b=v(0),v(1);mask=(1<<(ops[0].size*8))-1
                result=(a-b if mn=='cmp' else a&b)&mask
                self.zf=result==0;self.sf=bool(result&(mask//2+1))
                self.of=bool(((a^b)&(a^result)&(mask//2+1))) if mn=='cmp' else False
            elif mn in ('je','jne','jl','jge','jmp'):
                take={'je':self.zf,'jne':not self.zf,'jl':self.sf!=self.of,'jge':self.sf==self.of,'jmp':True}[mn]
                if take:pc=v(0)
            elif mn=='call':
                target=v(0);sp=self.regs['esp'];a=[self.get(sp+4*k,4) for k in range(3)]
                self.calls.append({'site':hex(i.address),'target':hex(target),'args':a})
                if target==0x609997:
                    if self.fail_alloc:raise MemoryError('合成分配异常')
                    out=0x500000+len(self.allocations)*0x10000
                    self.allocations.append((out,a[0]));self.regs['eax']=out
                elif target==0x60E3E8:
                    die(a[2]>1000,'有限模型拒绝巨大复制')
                    b=[self.get(a[1]+n,1) for n in range(a[2])]
                    for n,x in enumerate(b):self.put(a[0]+n,x,1)
                    self.regs['eax']=a[0]
                elif target in (0x601CD3,0x60B576):pass
                else:die(True,f'未合成外部调用 {target:#x}')
            elif mn=='ret':
                die(self.get(self.regs['esp'],4)!=0xFEEDFACE,'栈不平衡')
                self.regs['esp']+=4+(v(0) if ops else 0)
                return self.regs['eax']
            else:die(True,f'未支持指令 {i.address:#x} {mn}')
        die(True,'有限模型超过步数')


def instruction_models(audit,legacy,cleanup):
    code={}
    for va,size in ((0x7ECD50,31),(0x7ECDB0,95),(0x7ECE30,216),(0x63F540,90),(0x692030,114),(0x7ECF70,77),(0x7DFB21,68)):
        code.update({i.address:i for i in MD.disasm(audit.read(va,size),va)})
    # 两谓词各枚举完整 BYTE 域；比较源于真实反汇编指令，而非作者谓词重写。
    pred={}
    for start,field,want in ((0x63F540,0,{11,12}),(0x692030,1,{8,9,10})):
        out=[]
        for byte in range(256):
            m=Machine(code,args=(3,));m.put(0x200038,0x400000,4);m.put(0x400000+3*0x44+field,byte,1)
            result=m.run(start)&255
            die(result!=int(byte in want),f'完整 BYTE 域谓词不符 {start:#x}/{byte}')
            out.append(result)
        pred[start]=out
    distribution={'none':0,'plus46c':0,'plus47c':0}
    for k in range(256):
        for s in range(256):
            dest='none' if not pred[0x63F540][k] else 'plus47c' if pred[0x692030][s] else 'plus46c'
            distribution[dest]+=1
    die(distribution!={'none':65024,'plus46c':506,'plus47c':6},'分流完整 BYTE 笛卡尔积不符')
    # K=-1 与 K=12/S=0 的勘误，执行真实局部条件和 BYTE 写地址。
    normal=[]
    for file_k,k,s,expected in ((12,12,0,255),(12,12,1,1),(-1,255,8,255),(0x10C,12,0,255),(11,11,0,0)):
        m=Machine(code);m.regs['ebp']=0x300200;m.put(0x300200-0x1CC,file_k,4);m.put(0x300200-0x28,3,4);m.put(0x300200-0x14,0x200000,4)
        m.put(0x200038,0x400000,4);r=0x400000+3*0x44;m.put(r,k,1);m.put(r+1,s,1)
        m.run(0x7DFB21,0x7DFB65)
        die(m.get(r,1)!=k or m.get(r+1,1)!=expected,'K/S 归一化写入模型不符')
        normal.append({'file_k':file_k,'k':k,'s':s,'output_s':expected})
    scenarios=[]
    # 构造/释放不重置前三字段。
    for start,pointer in ((0x7ECD50,0x400000),(0x7ECF70,0x400000),(0x7ECF70,0)):
        m=Machine(code)
        for at,value in ((0,7),(4,32),(8,16),(12,pointer)):m.put(0x200000+at,value,4)
        m.run(start)
        die([m.get(0x200000+i,4) for i in (0,4,8,12)]!=[7,32,16,0],'构造/释放字段范围不符')
        scenarios.append({'entry':hex(start),'pointer':pointer,'after':[7,32,16,0],'calls':m.calls})
    m=Machine(code,args=(32,16));m.put(0x20000C,0x400000,4);m.run(0x7ECDB0)
    die([m.get(0x200000+i,4) for i in (0,4,8,12)]!=[0,32,16,0x500000],'初始化字段错误')
    die(any(x['target']=='0x601cd3' for x in m.calls),'初始化意外删除旧数组')
    scenarios.append({'entry':'0x7ecdb0','allocation_bytes':m.allocations[0][1],'old_pointer_released':False})
    # 满表、未满、零/负增长、损坏 n>cap：记录真实写地址，越界只是合成风险证据。
    for n,cap,grow in ((0,32,16),(32,32,16),(2,2,0),(2,2,-1),(4,2,1),(0,-1,2)):
        m=Machine(code,args=(0xABCD8000,))
        for at,val in ((0,n),(4,cap),(8,grow),(12,0x400000)):m.put(0x200000+at,val,4)
        for i in range(max(cap,0)*2):m.put(0x400000+i,i,1)
        if cap<0:continue  # 巨量 memcpy 不在解释器有限域，保留为静态回绕边界。
        out=m.run(0x7ECE30);p=m.get(0x20000C,4)
        die(out!=n or m.get(0x200000,4)!=n+1 or m.get(p+2*n,2)!=0x8000,'追加值/返回下标不符')
        copies=[x for x in m.calls if x['target']=='0x60e3e8']
        die(bool(copies)!=(n>=cap),'扩容分支不符')
        if copies:die(copies[0]['args'][2]!=cap*2,'扩容复制数量不是旧容量')
        scenarios.append({'entry':'0x7ece30','n':n,'cap':cap,'grow':grow,'return':out,'copied_bytes':copies[0]['args'][2] if copies else 0,'allocated_bytes':m.allocations[0][1] if m.allocations else None,'append_inside_new_allocation':2*n+2<=m.allocations[0][1] if m.allocations else True})
    # 非空旧指针在分配抛出前仍保留；不推广为所有后端行为。
    m=Machine(code,args=(1,),fail_alloc=True)
    for at,val in ((0,2),(4,2),(8,1),(12,0x400000)):m.put(0x200000+at,val,4)
    try:m.run(0x7ECE30)
    except MemoryError:pass
    else:die(True,'合成分配异常未触发')
    die([m.get(0x200000+i,4) for i in (0,4,8,12)]!=[2,2,1,0x400000],'异常前对象被改写')
    return {'scope':'512 次真实谓词指令有限解释；65536 组合分流；5 个真实归一化局部窗口；容器外部分配/复制/释放合成，不运行游戏',
            'predicate_cases':512,'classification_cases':65536,'distribution':distribution,'normalization_cases':normal,'container_cases':scenarios,'allocation_throw_case':'在 allocator 调用处合成抛出；旧字段仍保留，不证明真实分配策略',
            'word_boundary_cases':[{'j':j,'word':j&65535,'signed16':signed(j,16)} for j in (0,32767,32768,65535,65536)]}


def die(condition, message: str) -> None:
    if condition:
        raise AssertionError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(raw, va: int):
    for item in raw["functions"]:
        if int(item["seed_va"], 16) == va:
            return item
    die(True, f"缺少函数 {va:#x}")


def asm_map(item):
    return {int(x["site_va"], 16): x["text"] for x in item["assembly"]}


def verify_new(raw, cleanup):
    f1 = function(raw, 0x7ECD50)
    f2 = function(raw, 0x7ECD80)
    die(f1["end_va"] != "0x7ecd6f", "7ECD50 边界变化")
    die(f2["end_va"] != "0x7ecda4", "7ECD80 边界变化")
    a1, a2 = asm_map(f1), asm_map(f2)
    die(a1.get(0x7ECD61) != "mov     dword ptr [eax+0Ch], 0", "构造器未清零 +0C")
    die(a1.get(0x7ECD68) != "mov     eax, [ebp+var_4]", "构造器返回值窗口变化")
    die(a2.get(0x7ECD91) != "call    sub_6004B4", "析构包装器未调用 6004B4")
    die(a2.get(0x7ECD9B) != "call    j___RTC_CheckEsp", "析构包装器边界/尾部变化")
    old = next((x for x in cleanup["functions"] if x["va"].lower() == "0x7ecf70"), None)
    die(old is None, "缺少 7ECF70 释放后端旧原证")
    oa = {int(x["va"], 16): x["text"] for x in old["assembly"]}
    expected = {
        0x7ECF8A: "cmp     dword ptr [eax+0Ch], 0",
        0x7ECF9D: "call    operator delete[](void *)",
        0x7ECFA8: "mov     dword ptr [ecx+0Ch], 0",
    }
    for ea, text in expected.items():
        die(oa.get(ea) != text, f"7ECF70 {ea:#x} 语义变化")
    return {
        "7ecd50": {"bytes": sum(x["size"] for x in f1["chunk_byte_ranges"]), "role": "本批唯一全量新函数：容器根构造，+0C=0"},
        "7ecd80": {"bytes": sum(x["size"] for x in f2["chunk_byte_ranges"]), "role": "本批重采：仅调用 6004B4；与旧 7ECF70 释放后端闭合"},
        "7ecf70": {"bytes": old["byte_ranges"][0]["size"], "role": "旧原证复用：释放 +0C 指针并置空"},
    }


def verify_legacy(raw):
    expected = {0x7ECDB0: (5, 95), 0x7ECE30: (4, 216), 0x63F540: (8, 90), 0x692030: (9, 114)}
    got = {(int(x["seed_va"], 16), x["source_pointer"]): x for x in raw["legacy_reused_byte_audits"]}
    result = []
    for va, (index, size) in expected.items():
        item = got.get((va, f"/函数/{index}"))
        die(item is None, f"缺少四体旧中文复核 {va:#x}")
        die(item["main_size"] != size or item["audited_instruction_bytes"] != size, f"旧体大小不符 {va:#x}")
        die(any(not x["matching"] for x in item["instruction_audits"]), f"旧体字节不匹配 {va:#x}")
        result.append({"va": hex(va), "source_pointer": item["source_pointer"], "bytes": size})
    return result


def verify_owner(raw):
    sites = {int(x["site_va"], 16): x for x in raw["explicit_owner_windows"]}
    required = (0x7DFBF8, 0x7DFC4E, 0x7DFC7C, 0x7DFC91, 0x7DFCC7)
    for site in required:
        die(site not in sites, f"缺少生产路径 owner 窗口 {site:#x}")
    text = {int(r["site_va"], 16): r["text"] for x in sites.values() for r in x["assembly"]}
    checks = {
        0x7DFBF8: "call    sub_607084",
        0x7DFC4E: "call    sub_606D69",
        0x7DFC7C: "call    sub_603F74",
        0x7DFC91: "call    sub_603F74",
        0x7DFCC7: "jmp     loc_7DF9C5",
    }


def verify_formal(audit,raw):
    formal=json.loads((TOPIC/'证据/formal_functions.json').read_text('utf-8'))
    reviews=json.loads((TOPIC/'函数审阅清单.json').read_text('utf-8'))
    sources={}
    def resolve(source):
        base=TOPIC if source['base']=='topic' else ROOT/'docs/逆向资料'
        p=base/source['path'];digest=sha(p)
        die(digest!=source['sha256'],'formal 来源 SHA 不符')
        sources[str(p.relative_to(ROOT)).replace('\\','/')]=digest
        node=json.loads(p.read_text('utf-8'))
        for part in source['json_pointer'].split('/')[1:]:node=node[int(part)] if isinstance(node,list) else node[part]
        return node
    for key,count in (('functions',2),('legacy_reused_functions',4),('historical_dependencies',2)):
        die(len(formal[key])!=count,'formal 分层数量不符')
        for item in formal[key]:
            if key=='legacy_reused_functions':
                # 旧中文状态/结论以字符串隔离，避免中央递归扫描再次计审阅。
                die('source_record' in item or not isinstance(item.get('source_record_json'),str),'旧中文原文未隔离')
                record=json.loads(item['source_record_json'])
            else:
                record=item['source_record']
            die(resolve(item['source'])!=record,'formal 不是无损来源记录')
    for i,item in enumerate(formal['functions']):
        die(item['source_record']!=raw['functions'][i],'两完整主体源映射不符')
        die(item['assembly']!=[dict(va=r['site_va'],text=r['text'],is_code=r['is_code']) for r in raw['functions'][i]['assembly']],'formal 汇编字段漂移')
        die(item['pseudocode']!=raw['functions'][i]['pseudocode'] or item['decompile_error']!=raw['functions'][i]['decompile_error'],'formal 反编译原文被改写')
    die(len(formal['caller_windows'])!=10,'正式有限窗口数量变化')
    for item in formal['caller_windows']:
        original=resolve(item['source']);rows=[original['完整汇编'][i] for i in item['source_indices']]
        die(rows!=item['source_rows'],'窗口旧行索引失真')
        die(item['assembly']!=[dict(va=r['地址'],text=r['汇编']) for r in rows],'窗口汇编失真')
        lo,hi=int(item['start_va'],16),int(item['end_va'],16);cursor=lo
        for row in rows:
            b=row['字节核验'];size=len(bytes.fromhex(b['IDB字节']))
            die(int(row['地址'],16)!=cursor or b['匹配'] is not True,'正式窗口间隙/匹配标记错误')
            audit.check(cursor,size,b['IDB字节'],b['磁盘字节'],'formal有限窗口')
            cursor+=size
        die(cursor!=hi,'正式窗口结束不符')
        b=item['byte_audit'];audit.check(lo,hi-lo,b['idb_hex'],b['disk_hex'],'formal窗口总范围',b['sha256'])
    bridges={0x60C9D5:0x7ECDB0,0x607084:0x63F540,0x606D69:0x692030,0x603F74:0x7ECE30,
             0x609997:0x91BD80,0x60E3E8:0x9213A0,0x601CD3:0x91F7E0,0x608F51:0x7E73F0}
    die(len(formal['offline_navigation_bridges'])!=8,'正式离线桥数量不符')
    for row in formal['offline_navigation_bridges']:
        va=int(row['va'],16);b=bytes.fromhex(row['disk_hex'])
        die(va not in bridges or b!=audit.read(va,5) or b[0]!=0xE9,'离线桥当前字节不符')
        target=va+5+struct.unpack_from('<i',b,1)[0]
        die(target!=bridges[va] or target!=int(row['target_va'],16),'离线桥目标不符')
        die(hashlib.sha256(b).hexdigest()!=row['sha256'],'离线桥指纹不符')
    die(len(reviews['functions'])!=6 or len(reviews['dependency_contracts'])!=5 or len(reviews['windows'])!=3,'清单层次数量不符')
    die({int(x['va'],16) for x in reviews['functions']}!={0x7ECD50,0x7ECD80,0x6004B4,0x60B576,0x605A9F,0x60E528},'清单错误扩展新审函数')
    for item in reviews['functions']+reviews['dependency_contracts']:
        path,pointer=item['evidence'].split('#');resolve({'base':'topic','path':path,'sha256':sha(TOPIC/path),'json_pointer':pointer})
    die(sha(TOPIC/'证据/export_bounded.py')!=raw['prepared_wrapper_sha256'],'采证 wrapper 哈希不符')
    return {'sources':sources,'formal_windows':10,'manifest_functions':6,'dependency_contracts':5,'partial_owners':3,'offline_navigation_bridges':8}


def verify_previous_selection(audit):
    path=ROOT/'docs/逆向资料/专题/地图地产候选筛选/证据/bounded_raw.json'
    digest='dbf28909a2e4328fd31158367ecb9c806fbfd6554e32e38b11a9eadb8084f635'
    die(sha(path)!=digest,'第二十六批五筛选器原证变化')
    raw=json.loads(path.read_text('utf-8'));code={}
    for f in raw['functions']:
        for b in f['chunk_byte_ranges']:
            ins=audit.check(int(b['start_va'],16),b['size'],b['idb_hex'],b['disk_hex'],'旧五筛选器块',b['sha256'])
            code.update({x.address:x for x in ins})
    for ea in (0x7E46C5,0x7E47B1,0x7E4895,0x7E4995,0x7E4A91):
        die(code[ea].mnemonic!='movsx' or code[ea].op_str!='eax, ax','旧筛选 WORD 符号扩展变化')
    for ea in (0x7E4717,0x7E47F8):die(code[ea].mnemonic!='jge','前二筛选同值不替换门变化')
    for ea in (0x7E48F7,0x7E49F7,0x7E4AE0):die(code[ea].mnemonic!='jg','后三筛选同值替换门变化')
    for ea in (0x7E48E6,0x7E49E6,0x7E4ACF):die(code[ea].mnemonic!='jle','后三筛选正值门变化')
    return {'path':str(path.relative_to(ROOT)).replace('\\','/'),'sha256':digest,'scope':'复核旧五主体块和signed16/同值/正值门，依赖消费沿用第二十六批已冻结契约；非五新函数'}
    for site, insn in checks.items():
        die(text.get(site) != insn, f"生产路径 {site:#x} 指令变化")
    return {
        "record_loop": "j=0，7DF9C5 每轮+1，7DF9D4 与 M+24 比较；顺序来自输入记录顺序",
        "plus47c": "7DFC4E 返回真后在 7DFC7C 追加 WORD(j)",
        "plus46c": "7DFC4E 返回假后在 7DFC91 追加 WORD(j)",
        "retry": "7DFCC7 回到 7DF9C5；不得推断失败后重排或跳过顺序",
    }


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--final',action='store_true');args=parser.parse_args()
    die(sha(PE) != EXPECTED_PE, "当前 PE SHA256 不符")
    for path,digest in ((RAW_PATH,RAW_SHA),(LEGACY_PATH,LEGACY_SHA),(CLEANUP_PATH,CLEANUP_SHA)):
        die(sha(path)!=digest,f'冻结来源哈希变化：{path.name}')
    raw = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    die(raw["disk_sha256"] != EXPECTED_PE, "bounded_raw 声明的 PE 不符")
    cleanup = json.loads(CLEANUP_PATH.read_text(encoding="utf-8"))
    legacy=json.loads(LEGACY_PATH.read_text(encoding='utf-8'))
    audit,byte_report=verify_bytes(raw,legacy,cleanup)
    formal_report=verify_formal(audit,raw)
    selection_report=verify_previous_selection(audit)
    byte_report['including_formal_byte_records']=audit.count
    byte_report['including_formal_unique_ranges']=len(audit.ranges)
    result = {
        "status": "PASS" if args.final else "原证与有限模型通过；待终稿绑定",
        "disk_sha256": EXPECTED_PE,
        "raw_sha256": sha(RAW_PATH),
        "cleanup_source_sha256": sha(CLEANUP_PATH),
        "functions": verify_new(raw, cleanup),
        "legacy_reused": verify_legacy(raw),
        "owner_model": verify_owner(raw),
        "byte_audit": byte_report,
        "formal_audit": formal_report,
        "previous_selection_audit":selection_report,
        "instruction_models":instruction_models(audit,legacy,cleanup),
        "new_function_count": 1,
        "re_sampled_function_count": 1,
        "legacy_reused_function_count": 4,
        "scope": "本批新增函数按全量原证去重计数；生产路径是有限 owner 窗口；未证明所有运行期调用者、异常路径和实机行为",
    }
    if args.final:
        required=['01_容器字段与生命周期.txt','02_地图生产顺序与筛选闭环.txt','03_来源分层与复核边界.txt','函数审阅清单.json','证据/formal_functions.json','证据/author_validation.json','04_独立审阅.txt']
        for path in required:die(not (TOPIC/path).is_file(),f'终稿缺文件 {path}')
        result['final_binding_sha256']={str(p.relative_to(TOPIC)).replace('\\','/'):sha(p) for p in sorted(TOPIC.rglob('*')) if p.is_file() and p.suffix in ('.txt','.json','.py') and p.name!='independent_validation27.json'}
        for p in TOPIC.rglob('*.txt'):
            for n,line in enumerate(p.read_text('utf-8-sig').splitlines(),1):die(bool(line.strip()) and not line.lstrip().startswith('//'),f'非注释排版 {p.name}:{n}')
    out = TOPIC / "证据" / "independent_validation27.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({'status':result['status'],'bytes':byte_report,'models':result['instruction_models'],'bindings':len(result.get('final_binding_sha256',{}))}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
