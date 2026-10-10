"""第28批地图候选回调独审：只读原证及当前PE，不连接IDA，不运行游戏。"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_MEM

HERE=Path(__file__).resolve().parent
TOPIC=HERE.parent
ROOT=HERE.parents[4]
DOCS=ROOT/'docs/逆向资料'
EXPECTED='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA='73c4b8febe7b40beed41ab6602dde5dbd8a27fc66dbc79a807686dc8ec23d490'
MD=Cs(CS_ARCH_X86,CS_MODE_32);MD.detail=True


def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(ok,why):
    if not ok:raise AssertionError(why)
def load(p):return json.loads(p.read_text('utf-8'))
def at(node,pointer):
    for part in pointer.split('/')[1:]:node=node[int(part)] if isinstance(node,list) else node[part]
    return node


# 只复用已冻结独审的PE映射与寄存器/内存基元；本专题调用分支、契约和样例独立编写。
BASE_PATH=DOCS/'专题/地产候选容器生产与生命周期/证据/independent_review27.py'
BASE_SHA='cbd2183fb2af869d73adc9696e58fd286027eb6334f5b23d150ca4928b990376'
require(digest(BASE_PATH)==BASE_SHA,'冻结独审基础源码已变化')
BASE=runpy.run_path(str(BASE_PATH))


class VM(BASE['Machine']):
    """只解释已核字节；call由显式hook合成，真实动态可达性不在此模型证明。"""
    def __init__(self,code,args=(),hook=None):
        super().__init__(code,args=args)
        self.hook=hook
        self.steps=0
        self.cf=False

    def run(self,start,stop=None):
        pc=start
        for step in range(5000):
            self.steps=step
            if pc==stop:return self.regs['eax']
            require(pc in self.code,f'解释范围外 {pc:#x}')
            i=self.code[pc];o=i.operands;mn=i.mnemonic;pc+=i.size
            v=lambda n:self.value(i,o[n])
            if mn=='push':self.regs['esp']-=4;self.put(self.regs['esp'],v(0),4)
            elif mn=='pop':self.assign(i,o[0],self.get(self.regs['esp'],4));self.regs['esp']+=4
            elif mn in ('mov','movzx','movsx'):
                self.assign(i,o[0],BASE['signed'](v(1),o[1].size*8) if mn=='movsx' else v(1))
            elif mn=='lea':self.assign(i,o[0],self.address(i,o[1]))
            elif mn in ('add','sub','imul','xor','or'):
                a,b=(v(1),v(2)) if len(o)==3 else (v(0),v(1))
                out={'add':lambda:a+b,'sub':lambda:a-b,'imul':lambda:a*b,'xor':lambda:a^b,'or':lambda:a|b}[mn]()
                self.assign(i,o[0],out)
            elif mn=='sete':self.assign(i,o[0],int(self.zf))
            elif mn in ('cmp','test'):
                a,b=v(0),v(1);mask=(1<<(o[0].size*8))-1
                r=(a-b if mn=='cmp' else a&b)&mask
                self.zf=r==0;self.sf=bool(r&(mask//2+1));self.of=bool((a^b)&(a^r)&(mask//2+1)) if mn=='cmp' else False
                self.cf=(a&mask)<(b&mask) if mn=='cmp' else False
            elif mn in ('je','jne','jl','jge','ja','jmp'):
                take={'je':self.zf,'jne':not self.zf,'jl':self.sf!=self.of,'jge':self.sf==self.of,'ja':not self.cf and not self.zf,'jmp':True}[mn]
                if take:pc=v(0)
            elif mn=='call':
                target=v(0);sp=self.regs['esp'];args=[self.get(sp+4*k,4) for k in range(4)]
                self.calls.append({'site':hex(i.address),'target':hex(target),'ecx':self.regs['ecx'],'args':args})
                if target==0x60B576:continue
                require(self.hook is not None,f'缺少外部hook {target:#x}')
                value,cleanup=self.hook(self,target,args,i.address)
                self.regs['eax']=value&0xFFFFFFFF;self.regs['esp']+=cleanup
            elif mn=='ret':
                require(self.get(self.regs['esp'],4)==0xFEEDFACE,'ABI栈不平衡')
                self.regs['esp']+=4+(v(0) if o else 0)
                return self.regs['eax']
            else:raise AssertionError(f'未支持指令 {i.address:#x} {mn}')
        raise AssertionError('有限模型超过步数：可能为合成环链')


def verify_raw():
    require(digest(HERE/'bounded_raw.json')==RAW_SHA,'本批raw指纹变化')
    raw=load(HERE/'bounded_raw.json');audit=BASE['ByteAudit']();code={};sources={};functions=[]
    require(raw['disk_sha256']==EXPECTED,'原证二进制身份不符')
    require(raw['prepared_wrapper_sha256']==digest(HERE/'export_bounded.py'),'wrapper指纹变化')
    def walk(node,path=''):
        if isinstance(node,dict):
            if {'start_va','size','idb_hex','disk_hex'}<=node.keys():
                require(node['matching'] is True,'字节未匹配 '+path)
                audit.check(int(node['start_va'],16),node['size'],node['idb_hex'],node['disk_hex'],path,node.get('sha256'))
            for key,value in node.items():walk(value,path+'/'+str(key))
        elif isinstance(node,list):
            for i,value in enumerate(node):walk(value,path+'/'+str(i))
    walk(raw)
    for f in raw['functions']:
        ins=[]
        for block in f['chunk_byte_ranges']:ins+=list(MD.disasm(bytes.fromhex(block['disk_hex']),int(block['start_va'],16)))
        require([x.address for x in ins]==[int(x['site_va'],16) for x in f['assembly']],'新主体指令边界不符')
        require(sum(x.size for x in ins)==sum(x['size'] for x in f['chunk_byte_ranges']),'新主体丢字节')
        code.update({x.address:x for x in ins});functions.append({'va':f['seed_va'],'bytes':sum(x.size for x in ins),'instructions':len(ins),'origin':'本批新原证'})
    for f in raw['reused_source_byte_audits']:
        p=DOCS/f['source_path'];require(digest(p)==f['source_sha256'],'旧源SHA变化')
        original=at(load(p),f['source_pointer']);sources[f['source_path']]=digest(p);ins=[]
        require(int(original.get('va',original.get('地址')),16)==int(f['seed_va'],16),'旧来源入口不符')
        for b in f['current_byte_audits']:
            old=at(load(p),b['source_pointer']);chinese='字节核验' in old
            oldbytes=old['字节核验'] if chinese else old
            oldidb=oldbytes['IDB字节'] if chinese else oldbytes['idb_hex'];olddisk=oldbytes['磁盘字节'] if chinese else oldbytes['disk_hex']
            require(oldidb==b['current_idb_hex'] and olddisk==b['current_disk_hex'],'旧/新补核字节不等')
            ins+=audit.check(int(b['start_va'],16),b['size'],b['current_idb_hex'],b['current_disk_hex'],b['source_pointer'],b['sha256'])
        asm=original.get('assembly',original.get('完整汇编'))
        require([x.address for x in ins]==[int(x.get('va',x.get('地址')),16) for x in asm],'旧体全部声明块解码不符')
        code.update({x.address:x for x in ins});functions.append({'va':f['seed_va'],'bytes':sum(x.size for x in ins),'instructions':len(ins),'origin':'旧原证当前补核'})
    require(len(raw['explicit_owner_windows'])==12 and len(raw['verified_direct_bridges'])==4,'原证边界数量不符')
    for b in raw['verified_direct_bridges']:
        va=int(b['start_va'],16);blob=bytes.fromhex(b['idb_hex'])
        require(len(blob)==5 and blob[0]==0xE9 and va+5+struct.unpack_from('<i',blob,1)[0]==int(b['target_va'],16),'E9桥目标错误')
    return raw,audit,code,{'functions':functions,'source_files':sources,'raw_range_records':audit.count,'raw_unique_ranges':len(audit.ranges)}


def new_models(code):
    cases=[]
    for title,ptr0,ptr4,callback,returns,want,visits in [
        ('NULL回调',0x400000,1,0,[],0,0),('首槽为空',0,1,0x900000,[],0,0),('第二槽为空',0x400000,0,0x900000,[],0,0),
        ('全未中',0x400000,1,0x900000,[0,0,0],0,3),('首节点命中',0x400000,1,0x900000,[1,1,1],1,1),
        ('第二节点命中',0x400000,1,0x900000,[0,1,1],1,2),('高24位非零仍命中',0x400000,1,0x900000,[0x100,0,0],1,1),
        ('负回调值仍命中',0x400000,1,0x900000,[0xFFFFFFFF,0,0],1,1),('C加4仅非零门',0x400000,0xDEADBEEF,0x900000,[0,0,1],1,3)]:
        seen=[]
        def hook(m,target,args,site):
            require(target==callback and args[1]==0x500000,'回调目标/上下文ABI错误')
            require(args[0]==0x400000+len(seen)*0x1000,'链式node实参错误')
            seen.append(args[0]);return returns[len(seen)-1],0
        m=VM(code,args=(callback,0x500000),hook=hook);m.put(0x200000,ptr0,4);m.put(0x200004,ptr4,4)
        for i in range(3):m.put(0x400000+i*0x1000+0x80,0x400000+(i+1)*0x1000 if i<2 else 0,4)
        got=m.run(0x6BA170)
        require(got==want and len(seen)==visits and m.regs['esp']==0x30010C,'搜索返回/首命中/RET8错误')
        cases.append({'case':title,'return_eax':got,'visited':seen})
    cmpcases=[]
    for returned,want in ((0,1),(1,0),(-1,0),(0x100,0)):
        seen=[]
        def hook(m,target,args,site):
            require(target==0x61038C and args[:2]==[0x500000,0x400000],'strcmp方向应context,node')
            seen.append(args[:2]);return returned,0
        m=VM(code,args=(0x400000,0x500000),hook=hook);out=m.run(0x6AAA40)
        require(out==want and len(seen)==1 and m.regs['esp']==0x300104,'比较器完整DWORD返回/cdecl清栈不符')
        cmpcases.append({'strcmp_return':returned,'callback_eax':out,'strcmp_arguments':seen[0]})
    return {'search_cases':cases,'comparison_cases':cmpcases,'scope':'真实函数指令解释，外部回调/strcmp及RTC为显式合成；无实机执行'}


ROUTES=[(0x6A55A3,0x514,3),(0x6A55EB,0x520,0),(0x6A5633,0x524,0),(0x6A567B,0x528,0),
        (0x6A56C3,0x52C,1),(0x6A570B,0x530,1),(0x6A5753,0x534,1),(0x6A579B,0x538,2),(0x6A57E3,0x53C,2),(0x6A582B,0x540,2)]


def owner_models(code):
    cases=[]
    for mode in (0,1,2,3,4,-1):
        eligible=[i for i,r in enumerate(ROUTES) if r[2]==mode]
        # 每个入口可被先前失败推进到；成功后立即停止本类后续尝试。
        for hit in eligible+[None]:
            for mode_ret in (1,0x100):
                seen=[];checks=[];fallback=[]
                def hook(m,target,args,site):
                    if target==0x6055F9:
                        n=next(i for i,r in enumerate(ROUTES) if r[0]==site)
                        require(args[:2]==[0x603FC9,0x500000] and m.regs['ecx']==0x600000+n*0x100,'十路搜索实参错误')
                        seen.append(n);return (0x100 if n==hit else 0),8
                    if site in [r[0]+0x10 for r in ROUTES]:
                        require(args[0]==0x500000 and m.regs['ecx']==0x200000,'模式门实参错误')
                        checks.append(site);return mode_ret,4
                    if site==0x6A586D:
                        require(args[0]==0xCAFEBABE,'兜底实参不是共享记录+38h')
                        fallback.append(site);return 0,0
                    raise AssertionError(f'未知owner外部call {site:#x}/{target:#x}')
                m=VM(code,hook=hook);bp=0x300800;m.regs.update(ebp=bp,esp=0x300000)
                for off,val in ((-0x18,0x210000),(-0x14,0x200000),(-0x1C,0x500000),(8,2)):m.put(bp+off,val,4)
                m.put(0x210000,mode,4);m.put(0x2005D8,0x700000,4);m.put(0x700000+2*124+0x38,0xCAFEBABE,4)
                for i,r in enumerate(ROUTES):m.put(0x200000+r[1],0x600000+i*0x100,4)
                m.run(0x6A5577,0x6A5883)
                passed=hit is not None and mode_ret&255!=0
                want=eligible[:eligible.index(hit)+1] if passed else eligible
                require(seen==want and bool(fallback)==(not passed),'十路顺序/停试/兜底门错误')
                require(m.get(bp-0x5E5,1)==int(passed) and m.regs['esp']==0x300000,'owner返回位或调用栈不符')
                cases.append({'mode':mode,'selected_route':hit,'mode_return':mode_ret,'search_order':seen,'fallback':bool(fallback),'local_success':int(passed)})
    # 成功门后的16字节比较，枚举每个位置的不等，并覆盖完全相等。
    comparisons=[]
    for bad in [None]+list(range(16)):
        def hook(m,target,args,site):
            require(site==0x6A5898 and args[0]==0x500000 and m.regs['ecx']==0x300800-0x5E0,'文件读取调用参数错误')
            return 0x520000,4
        m=VM(code,hook=hook);bp=0x300800;m.regs.update(ebp=bp,esp=0x300000)
        m.put(bp-0x5E5,1,1);m.put(bp-0x1C,0x500000,4);m.put(bp-0x20,0x510000,4)
        for i in range(16):m.put(0x510000+i,i,1);m.put(0x520000+i,i if i!=bad else i^255,1)
        m.run(0x6A5883,0x6A58EB)
        require(m.get(bp-0x5E5,1)==int(bad is None),'16字节比较结果错误')
        require(m.get(bp-0x5EC,4)==(16 if bad is None else bad),'比较未首个不等即停')
        comparisons.append({'mismatch':bad,'success':bad is None,'comparison_cursor':m.get(bp-0x5EC,4)})
    return {'route_cases':cases,'digest_byte_cases':comparisons,'scope':'owner限定6A5577..6A58EB实际指令；查询、模式和读取后端合成，不把16字节解释为MD5认证'}


def boundary_models(audit,code):
    p=HERE/'boundary_data/bounded_raw.json';require(digest(p)=='ef82406b0030c94dc2739e8a1673d6fadaf69c0c2a4906be391dfdefe25034e7','补采数据指纹变化')
    data=load(p);require(not data['functions'] and not data['seeds'],'纯数据补采不能新增主体')
    require(len(data['data_windows'])==6,'数据窗数量变化')
    for b in data['data_windows']:audit.check(int(b['start_va'],16),b['size'],b['idb_hex'],b['disk_hex'],'补采数据',b['sha256'])
    table=struct.unpack('<4I',audit.read(0x6AAB34,16));require(table==(0x6AAADC,0x6AAAEE,0x6AAB06,0x6AAAD0),'模式表顺序错误')
    require(audit.read(0xA2D950,7)==b'Map\\%s\0' and audit.read(0xA2D970,3)==b'rb\0','格式串不符')
    require(struct.unpack('<2I',audit.read(0x7E727A,8))==(1,0x7E7282),'RTC头错误')
    require(struct.unpack('<iII',audit.read(0x7E7282,12))==(-76,64,0x7E728E),'RTC容量不是64')
    require(audit.read(0x7E728E,14)==b'szFullMapName\0','RTC变量名不符')
    cases=[]
    for mode in (0,1,2,3,4,0xFFFFFFFF):
        for cls in (0,1,2,3,4,0xFFFFFFFF):
            # 从真实模式分派进入，前置两个查询的结果以局部栈值合成。
            m=VM(code);bp=0x300800;m.regs.update(ebp=bp,esp=0x300000,eax=0xABCDEF00)
            m.put(bp-0x10,mode,4);m.put(bp-0xC,cls,4)
            for i,target in enumerate(table):m.put(0x6AAB34+i*4,target,4)
            m.run(0x6AAAC0,0x6AAB24)
            expected=cls in ({0,3},{0,1,3},{0,1,2,3},{3})[mode] if mode<=3 else False
            require((m.regs['eax']&255)==int(expected),'模式矩阵不符')
            cases.append({'mode':mode,'class':cls,'return_al':m.regs['eax']&255,'eax_upper24':m.regs['eax']>>8})
    # 读文件局部真实指令：fopen NULL和fread返回0后仍走fclose，未添加本体不存在的保护。
    io=[]
    for stream,written,return_count in ((0,0,0),(0x880000,0,0),(0x880000,7,0),(0x880000,16,1)):
        observed=[]
        def hook(m,target,args,site):
            observed.append({'site':hex(site),'args':args})
            if site==0x7E721C:return stream,0
            if site==0x7E7236:
                require(args==[0x200008,16,1,stream],'fread实参错误')
                for i in range(written):m.put(0x200008+i,i,1)
                return return_count,0
            if site==0x7E7242:
                require(args[0]==stream,'fclose流参数错误');return 0,0
            raise AssertionError('未知文件调用')
        m=VM(code,hook=hook);bp=0x300800;m.regs.update(ebp=bp,esp=0x300000);m.put(bp-8,0x200000,4)
        for i in range(16):m.put(0x200008+i,0xCC,1)
        m.run(0x7E7213,0x7E7250)
        require(m.regs['eax']==0x200008 and len(observed)==3,'文件后端没有按预期无条件继续')
        require([m.get(0x200008+i,1) for i in range(16)]==list(range(written))+[0xCC]*(16-written),'短读残留模型错误')
        io.append({'stream':stream,'written':written,'read_return':return_count,'return_pointer':hex(m.regs['eax']),'remaining_cc_bytes':16-written,'calls':observed})
    # 旧构造全体指令字节核验；不把该旧函数重新计为本批完整审阅。
    p=DOCS/'专题/地图与路径/证据/map_runtime_core.json'
    require(digest(p)=='5f5edfd13986b030fde915284725add0bf36285274f3f1bcb581c1a5c13f2de4','地图构造旧源变化')
    f=load(p)['函数'][0];rows=f['完整汇编'];constructor=[]
    for row in rows:
        b=row['字节核验'];constructor+=audit.check(int(row['地址'],16),len(bytes.fromhex(b['IDB字节'])),b['IDB字节'],b['磁盘字节'],'旧构造初值边界')
    # 对本体this别名作有限追踪：所有对象直接写均排除+8..17；callee不可据此作全局不写声明。
    regs={};writes=[];callees=[]
    for ins in constructor:
        if ins.address>=0xA00000:continue
        ops=ins.operands
        if ins.mnemonic=='mov' and len(ops)==2:
            dst,src=ops
            if dst.type==X86_OP_REG:
                name=ins.reg_name(dst.reg)
                if src.type==X86_OP_MEM and ins.reg_name(src.mem.base)=='ebp' and src.mem.disp==-16:regs[name]=0
                else:regs.pop(name,None)
            elif dst.type==X86_OP_MEM and ins.reg_name(dst.mem.base) in regs:
                off=regs[ins.reg_name(dst.mem.base)]+dst.mem.disp
                require(not (off<24 and off+dst.size>8),'旧构造本体写摘要区')
                writes.append(off)
        elif ins.mnemonic=='add' and ops[0].type==X86_OP_REG:
            name=ins.reg_name(ops[0].reg)
            if name in regs:regs[name]+=ops[1].imm
        elif ins.mnemonic=='call':
            if 'ecx' in regs:callees.append({'site':hex(ins.address),'this_offset':regs['ecx']})
            for name in ('eax','ecx','edx'):regs.pop(name,None)
    require(code[0x6A5516].operands[1].imm==0x179 and code[0x6A551B].operands[1].imm==0xCCCCCCCC,'调用者栈填充值变化')
    return {'data_sha256':digest(HERE/'boundary_data/bounded_raw.json'),'jump_table':[hex(x) for x in table],
            'rtc_buffer':{'name':'szFullMapName','ebp_offset':-76,'capacity':64,'slot_gap':68},'mode_matrix_cases':cases,
            'file_io_cases':io,'constructor_direct_write_offsets':writes,'constructor_subobject_calls':callees,
            'initial_value_boundary':'6A54F0调试栈填充覆盖Q+8，7DE310本体无摘要字段写；未越权宣称所有下游callee无副作用或所有地图实例默认CC'}


def verify_formal(audit,code,raw):
    formal=load(HERE/'formal_functions.json');sources={}
    def source(s):
        p=(TOPIC if s['base']=='topic' else DOCS)/s['path']
        require(digest(p)==s['sha256'],'formal来源指纹错误');sources[str(p.relative_to(ROOT)).replace('\\','/')]=digest(p)
        return at(load(p),s['json_pointer'])
    require(len(formal['functions'])==2 and len(formal['legacy_reused_functions'])==4 and len(formal['helper_contracts'])==7,'formal分层数量错误')
    for i,f in enumerate(formal['functions']):
        require(source(f['source'])==f['source_record']==raw['functions'][i],'新来源对象非无损')
        require(f['assembly']==[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in raw['functions'][i]['assembly']],'新汇编失真')
        require(f['pseudocode']==raw['functions'][i]['pseudocode'] and f['chunk_byte_ranges']==raw['functions'][i]['chunk_byte_ranges'],'新伪码/块失真')
    helper_stats=[]
    for f in formal['legacy_reused_functions']+formal['helper_contracts']:
        require('source_record' not in f and isinstance(f.get('source_record_json'),str),'历史对象未隔离')
        node=json.loads(f['source_record_json']);require(source(f['source'])==node,'历史对象反序列化非无损')
        if f not in formal['helper_contracts']:continue
        ins=[]
        if '完整汇编' in node:
            for row in node['完整汇编']:
                b=row['字节核验'];ins+=audit.check(int(row['地址'],16),len(bytes.fromhex(b['IDB字节'])),b['IDB字节'],b['磁盘字节'],'formal中文helper')
        else:
            for b in node.get('chunk_byte_ranges',node.get('byte_ranges',[])):
                ins+=audit.check(int(b.get('start_va',b.get('va')),16),b['size'],b['idb_hex'],b['disk_hex'],'formal英文helper',b.get('sha256'))
        require([i.address for i in ins]==[int(x.get('va',x.get('地址')),16) for x in node.get('assembly',node.get('完整汇编'))],'helper反汇编边界错误')
        code.update({i.address:i for i in ins});helper_stats.append({'va':f['va'],'instructions':len(ins),'bytes':sum(i.size for i in ins)})
    require(formal['caller_windows']==raw['explicit_owner_windows'] and formal['bridges']==raw['verified_direct_bridges'] and formal['calls']==raw['calls'],'formal导航不是原证副本')
    # 与中央常见递归识别同宽度检查，源隔离不应形成带status/conclusion的新审阅对象。
    def review_hits(node):
        if isinstance(node,dict):
            hit=int(('va' in node or '地址' in node) and ('status' in node or '状态' in node) and ('conclusion' in node or '结论' in node))
            return hit+sum(review_hits(v) for v in node.values())
        if isinstance(node,list):return sum(review_hits(v) for v in node)
        return 0
    require(review_hits(formal)==0,'formal嵌套旧审阅污染')
    return {'source_files':sources,'helper_stats':helper_stats,'history_objects_isolated':11}


def helper_models(code):
    cases=[]
    for count,results,expected in [(0,[],0xFFFFFFFF),(-1,[],0xFFFFFFFF),(3,[1,1,1],0xFFFFFFFF),(3,[0,0,0],10),(3,[1,0,0],11)]:
        visited=[]
        def hook(m,target,args,site):
            require(site==0x7E9657 and args[:2]==[0x400000+len(visited)*276,0x500000],'分类查询strcmp方向或276步长错误')
            visited.append(args[0]);return results[len(visited)-1],0
        m=VM(code,args=(0x500000,),hook=hook);m.put(0x200000,0x400000,4);m.put(0x200004,count,4)
        for i in range(3):m.put(0x400000+i*276+0x108,10+i,4)
        got=m.run(0x7E9610)
        require(got==expected,'分类查询首匹配返回/FFFFFFFF哨兵错误')
        cases.append({'count':count,'return_eax':hex(got),'visited':visited})
    fallback=[]
    for value in (0,1,2,3,4,0xFFFFFFFF,0x103):
        m=VM(code,args=(value,));got=m.run(0x63E1A0)
        require(got==int(value==3),'兜底仅完整DWORD==3错误')
        fallback.append({'argument':value,'return_eax':got})
    return {'classification_first_match_cases':cases,'fallback_cases':fallback}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--final',action='store_true');args=parser.parse_args()
    raw,audit,code,result=verify_raw()
    result.update(status='原证模型预核通过；等待作者终稿',disk_sha256=EXPECTED,raw_sha256=RAW_SHA,
                  independent_base_sha256=BASE_SHA,new_models=new_models(code),owner_models=owner_models(code),boundary_models=boundary_models(audit,code))
    if (HERE/'formal_functions.json').is_file():
        result['formal_audit']=verify_formal(audit,code,raw)
        result['helper_models']=helper_models(code)
    if args.final:
        for name in ('formal_functions.json','author_validation.json'):
            require((HERE/name).is_file(),'终稿缺少 '+name)
        require((TOPIC/'04_独立审阅.txt').is_file(),'缺少独审报告')
        review=load(TOPIC/'函数审阅清单.json')
        require(len(review['functions'])==6,'显式函数清单应2新主体+4桥')
        require({int(x['va'],16) for x in review['functions']}=={0x6BA170,0x6AAA40,0x6055F9,0x603FC9,0x61038C,0x60B576},'清单污染其他主体')
        for p in TOPIC.rglob('*.txt'):
            require(all(not line.strip() or line.lstrip().startswith('//') for line in p.read_text('utf-8-sig').splitlines()),'正文非中文注释式排版 '+p.name)
        result['status']='PASS'
        result['final_binding_sha256']={str(p.relative_to(TOPIC)).replace('\\','/'):digest(p) for p in sorted(TOPIC.rglob('*')) if p.is_file() and p.suffix in ('.txt','.py','.json') and p.name!='independent_validation28.json'}
    result['total_range_records']=audit.count;result['total_unique_ranges']=len(audit.ranges)
    (HERE/'independent_validation28.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps({'status':result['status'],'functions':result['functions'],'range_records':audit.count,'unique_ranges':len(audit.ranges),'routes':len(result['owner_models']['route_cases'])},ensure_ascii=False))


if __name__=='__main__':main()
