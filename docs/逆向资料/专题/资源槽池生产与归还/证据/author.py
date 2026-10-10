"""本专题无损来源隔离、审阅清单与离线证据核验；不访问IDA。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
DOCS=ROOT/'docs/逆向资料'
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA='32bb1c22c33bd0ca58ba757e74943af2d1da4eb0514d7114c61c2f834ee0ca80'
NEW=['0x6d75a0','0x62eae0','0x6dfc30','0x6dfd50','0x6d7690','0x6dbdf0']
OLD=[
 ('专题/角色与精灵动画/证据/动画管理与骰子_IDA原始导出.json','/functions/24','0x6dfca0'),
 ('专题/图像资源/证据/20261009_图像加载函数群.json','/functions/18','0x6d7660'),
 ('专题/图像资源/证据/20261009_图像加载函数群.json','/functions/19','0x6dfd10'),
 ('专题/4019系列事件/证据/resource_loader_scope.json','/functions/0','0x6d8130'),
 ('专题/40B0系列事件/证据/monster_helpers.json','/functions/0','0x627760'),
 ('专题/4060系列事件/证据/callees.json','/functions/10','0x91f6d0'),
]


def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_bytes())
def put(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n','utf-8')
def ptr(o,p):
    for k in p.strip('/').split('/'):
        o=o[int(k)] if isinstance(o,list) else o[k]
    return o
def vaof(o):return o.get('seed_va',o.get('va',o.get('address')))


class Image:
    def __init__(self):
        self.data=(ROOT/'RnClient.exe').read_bytes();assert sha(self.data)==SHA
        p=struct.unpack_from('<I',self.data,60)[0]
        self.base=struct.unpack_from('<I',self.data,p+52)[0]
        t=p+24+struct.unpack_from('<H',self.data,p+20)[0]
        self.sections=[struct.unpack_from('<4I',self.data,t+40*i+8) for i in range(struct.unpack_from('<H',self.data,p+6)[0])]
        self.cs=Cs(CS_ARCH_X86,CS_MODE_32)
    def disk(self,v,n):
        if isinstance(v,str):v=int(v,16)
        hits=[(r,o) for _,r,z,o in self.sections if self.base+r<=v and v+n<=self.base+r+z]
        assert len(hits)==1,(hex(v),n)
        r,o=hits[0];return self.data[o+v-self.base-r:o+v-self.base-r+n]
    def ins(self,v,n):
        b=self.disk(v,n);a=list(self.cs.disasm(b,int(v,16) if isinstance(v,str) else v))
        assert len(a)==1 and a[0].size==n,(v,b.hex())
        return a[0].mnemonic+' '+a[0].op_str


def adapt(source,path,pointer,bounded):
    v=vaof(source)
    chunks=source.get('chunk_byte_ranges',source.get('chunks',source.get('byte_ranges')))
    current=None
    if not chunks:
        indexes=[i for i,r in enumerate(bounded['current_chunk_audits']) if r['seed_va']==v]
        assert len(indexes)==1
        index=indexes[0];chunks=bounded['current_chunk_audits'][index]['chunk_byte_ranges']
        current=dict(source_path='专题/资源槽池生产与归还/证据/bounded_raw.json',source_pointer='/current_chunk_audits/'+str(index),source_sha256=RAW_SHA)
    normalized=[]
    for c in chunks:
        start=c.get('start_va',c.get('va',c.get('start')))
        size=c.get('size',int(c['end'],16)-int(start,16) if 'end' in c else None)
        normalized.append(dict(start_va=start,size=size,original=c))
    assembly=source.get('assembly',source.get('instructions'))
    row=dict(va=v,source_path=path,source_pointer=pointer,source_sha256=sha((DOCS/path).read_bytes()),
             source_record_json=json.dumps(source,ensure_ascii=False,separators=(',',':')),
             source_field_pointers={k:pointer+'/'+k for k in source},
             normalized_chunks=normalized,
             normalized_assembly=[dict(site_va=a.get('site_va',a.get('va',a.get('address',a.get('ea')))),text=a['text'],is_code=a.get('is_code',True),original=a) for a in assembly])
    row['declared_chunks']=source.get('declared_chunks',[dict(start_va=c['start_va'],end_va=hex(int(c['start_va'],16)+c['size']),is_main=c['start_va']==v) for c in normalized])
    if current:row['current_bytes_source']=current
    return row


def generate():
    bounded=read(HERE/'bounded_raw.json');assert sha((HERE/'bounded_raw.json').read_bytes())==RAW_SHA
    path='专题/资源槽池生产与归还/证据/bounded_raw.json'
    rows=[adapt(r,path,'/functions/'+str(i),bounded) for i,r in enumerate(bounded['functions'])]
    assert [r['va'] for r in rows]==NEW
    put(HERE/'formal_functions.json',dict(disk_sha256=SHA,functions=rows))
    rows=[]
    for path,p,v in OLD:
        source=ptr(read(DOCS/path),p);assert vaof(source)==v
        rows.append(adapt(source,path,p,bounded))
    put(HERE/'reused_functions.json',dict(disk_sha256=SHA,functions=rows))


SPECS=[
 ('完整局部分析','分配30000个DWORD，依次push 29999..0；正常路径返回this；异常尾仅记录清理跳转。','分配失败与push返回均未在本体检查；尾目标62EB20语义及完整生命周期未闭。',[0x6D75DB,0x6D75E3,0x6D75E8,0x6D75F4,0x6D75FA,0x6D75FE,0x6D7607,0xA12AF3]),
 ('完整局部分析','只把this+0基址与+8计数清零，返回this；+4容量未写。','自动CDBVariant名字不证明原类型；未分配前capacity无有效初值保证。',[0x62EAF1,0x62EAFA,0x62EB01]),
 ('完整局部分析','清count，保存capacity，容量左移2后分配，原返回指针直接保存base，ret4。','无容量有效域/移位溢出/NULL/旧base释放门；底层分配器异常语义未展开。',[0x6DFC4A,0x6DFC57,0x6DFC5D,0x6DFC61,0x6DFC72,0x6DFC81]),
 ('完整局部分析','signed count>=capacity，xor EAX后setnl AL，精确返回0或1。','不是slot有效域或去重检查；负count非法状态不受该谓词修复。',[0x6DFD64,0x6DFD67,0x6DFD69,0x6DFD6C]),
 ('完整局部分析','ECX原pool、一个栈DWORD转发6DFCA0，正常RTC保留结果，ret4。','伪码stdcall省略ECX；不额外检查slot或归还状态。',[0x6D769E,0x6D76A2,0x6D76A5,0x6D76B7]),
 ('完整局部分析','向C+40归还slot，随后无条件清BYTE[C+92A4C+slot]；保留push返回。','失败也清BYTE；本体不清C+580CC反向表，无slot边界门；BYTE业务意义未闭。',[0x6DBE05,0x6DBE08,0x6DBE10,0x6DBE13,0x6DBE27]),
 ('既有窄契约复用','满池谓词AL真返回0，否则base[count]=slot、count++、返回1。','不检查重复slot、slot范围、base非空或负count；泛型其他实例不等同资源池。',[0x6DFCB1,0x6DFCB6,0x6DFCCF,0x6DFCDE,0x6DFCE1]),
 ('既有窄契约复用','ECX原pool转发6DFD10，正常RTC保留弹出DWORD。','不增加空池门。',[0x6D7671,0x6D767B]),
 ('既有窄契约复用','count先减一并写回，再读base[count]，无空池门。','空池会形成-1索引路径，不宣称实机已越界。',[0x6DFD24,0x6DFD2A,0x6DFD38]),
 ('部分分析','15个取槽/登记站跨12配置文件，均用同一Destination+40池，slot写记录+4后反向表保存记录地址。','全loader仅机械核，语义限15站与类别/派生条件；不含完整配置解析失败与全部初始化。',[0x6D8443,0x6D8540,0x6D8544,0x6D8546,0x6D854A,0x6D8553,0x6D85D4,0x6D8A5F,0x6D8D25,0x6D8D50,0x6D904F,0x6D907A,0x6D919F,0x6D91A3,0x6D91A9,0x6D924D,0x6D9483,0x6D94AE,0x6D95DF,0x6D95E3,0x6D95E9,0x6D9699,0x6D98D5,0x6D9E1B,0x6DA361]),
 ('既有窄契约复用','627760为配置根访问器，连接地图及75C580窗口的ECX身份。','单例构造整体、线程行为与其他子系统生命周期不扩审。',[0x627790,0x627799,0x6277E0]),
 ('既有窄契约复用','RTC正常相等路径直接返回并保留EAX。','诊断失败分支不展开。',[0x91F6D0,0x91F6D2]),
]


def ledger():
    rows=[]
    for filename in ('formal_functions.json','reused_functions.json'):
        for i,r in enumerate(read(HERE/filename)['functions']):
            status,conclusion,unknown,addresses=SPECS[len(rows)];asm={a['site_va']:a['text'] for a in r['normalized_assembly']}
            anchors=[dict(va=hex(v),original_text=asm[hex(v)]) for v in addresses]
            rows.append(dict(va=r['va'],status=status,conclusion=conclusion,unknown=unknown,source_path=r['source_path'],source_pointer=r['source_pointer'],source_sha256=r['source_sha256'],declared_chunks=r['declared_chunks'],evidence_ref=dict(file=filename,pointer='/functions/'+str(i)),semantic_anchors=anchors))
    put(HERE.parent/'函数审阅清单.json',dict(disk_sha256=SHA,functions=rows[:6],historical_contracts=rows[6:],scope='6新完整局部本体、6旧窄/局部复用；窗口与桥不加函数审阅。'))


def validate():
    img=Image();bounded=read(HERE/'bounded_raw.json');assert sha((HERE/'bounded_raw.json').read_bytes())==RAW_SHA
    counts=dict(byte_ranges=0,instructions=0,owner_items=0,anchors=0)
    decoded={};sources={};listing=[];hashes={}
    def audit(c):
        v=c.get('start_va',c.get('va',c.get('start')))
        n=c.get('size',int(c['end'],16)-int(v,16) if 'end' in c else None)
        raw=img.disk(v,n)
        for k in ('disk_hex','idb_hex','ida_hex','bytes_hex'):
            if k in c:assert raw.hex()==c[k].lower(),(v,k)
        if 'sha256' in c:assert sha(raw)==c['sha256'].lower()
        assert c.get('matching',c.get('equal',True)) is True
        counts['byte_ranges']+=1;return raw
    for filename in ('formal_functions.json','reused_functions.json'):
        sources[filename]=read(HERE/filename);hashes[filename]=sha((HERE/filename).read_bytes())
        for r in sources[filename]['functions']:
            raw=(DOCS/r['source_path']).read_bytes();assert sha(raw)==r['source_sha256']
            original=ptr(json.loads(raw),r['source_pointer']);assert json.loads(r['source_record_json'])==original
            assert r['source_field_pointers']=={k:r['source_pointer']+'/'+k for k in original}
            assert not {'status','conclusion','unknown','original_record'}&r.keys()
            assert r==adapt(original,r['source_path'],r['source_pointer'],bounded)
            decoded[r['va']]={};listing.append('// '+r['va'])
            for c in r['normalized_chunks']:
                b=audit(c['original']);start=int(c['start_va'],16);end=start+c['size'];assert len(b)==c['size']
                a=[x for x in r['normalized_assembly'] if start<=int(x['site_va'],16)<end];assert int(a[0]['site_va'],16)==start
                for i,x in enumerate(a):
                    v=int(x['site_va'],16);stop=int(a[i+1]['site_va'],16) if i+1<len(a) else end
                    assert x['is_code'] and not x['text'].lstrip().startswith(('db ','dw ','dd '))
                    text=img.ins(v,stop-v);decoded[r['va']][x['site_va']]=text;counts['instructions']+=1;listing.append('// '+hex(v)+' '+text)
    for r in bounded['current_chunk_audits']:
        for c in r['chunk_byte_ranges']:audit(c)
    def call(c):
        site=int(c.get('site_va',c.get('site')),16);target=int(c.get('target_va',c.get('target')),16);b=img.disk(site,6)
        if b[:2]==b'\xff\x15':assert struct.unpack_from('<I',b,2)[0]==target
        else:assert b[0] in (0xe8,0xe9) and site+5+struct.unpack_from('<i',b,1)[0]==target
        for bridge in c.get('bridges',c.get('thunks',[])):
            assert target==int(bridge,16);b=img.disk(target,5);assert b[0]==0xe9;target+=5+struct.unpack_from('<i',b,1)[0]
        assert target==int(c.get('implementation_va',c.get('implementation')),16)
    for c in bounded['calls']:call(c)
    for r in sources['reused_functions.json']['functions']:
        for c in json.loads(r['source_record_json']).get('calls',[]):call(c)
    for c in bounded['verified_direct_bridges']:
        b=audit(c);v=int(c['start_va'],16);assert b[0]==0xe9 and len(b)==5 and v+5+struct.unpack_from('<i',b,1)[0]==int(c['target_va'],16)
    windows=bounded['explicit_owner_windows']+[e['owner_window'] for es in bounded['incoming'].values() for e in es if 'owner_window' in e]
    for w in windows:
        stop=None
        for a in w['assembly']:
            b=audit(a['bytes']);v=int(a['site_va'],16);assert stop is None or stop==v;stop=v+len(b)
            assert a['is_code'];img.ins(v,len(b));counts['owner_items']+=1
    assert not bounded['strings'] and not bounded['data_windows']
    for ref in bounded['reuse_sources']:assert sha((DOCS/ref['path']).read_bytes())==ref['source_sha256']
    manifest=read(HERE.parent/'函数审阅清单.json');assert len(manifest['functions'])==6 and len(manifest['historical_contracts'])==6
    for r in manifest['functions']+manifest['historical_contracts']:
        src=ptr(sources[r['evidence_ref']['file']],r['evidence_ref']['pointer']);assert r['va']==src['va'] and r['source_sha256']==src['source_sha256'] and r['declared_chunks']==src['declared_chunks']
        byva={a['site_va']:a['text'] for a in src['normalized_assembly']}
        for a in r['semantic_anchors']:assert byva[a['va']]==a['original_text'] and a['va'] in decoded[r['va']];counts['anchors']+=1
    allcode={v:t for d in decoded.values() for v,t in d.items()}
    expected={'0x6d75db':'0x7530','0x6d75e8':'0x752f','0x6d75fe':'jl','0x62eaf1':'[eax], 0','0x62eafa':'[ecx + 8], 0','0x6dfc5d':'shl','0x6dfd69':'[ecx + 4]','0x6dfd6c':'setge al','0x6dbe13':'byte ptr [ecx + 0x92a4c], 0','0x6dfd24':'sub ecx, 1'}
    for v,t in expected.items():assert t in allcode[v],(v,allcode[v])
    site_module=__import__('runpy').run_path(str(HERE/'shared_sites.py'))
    assert read(HERE/'shared_sites.json')==site_module['inspect']()
    for p in HERE.parent.glob('*.txt'):assert all(not s.strip() or s.startswith('//') for s in p.read_text('utf-8').splitlines())
    (HERE/'review_assembly.txt').write_text('\n'.join(listing)+'\n','utf-8')
    result=dict(status='PASS',disk_sha256=SHA,bounded_sha256=RAW_SHA,**counts,new_bodies=6,
                new_instructions=sum(len(decoded[v]) for v in NEW),new_bytes=sum(c['size'] for r in bounded['functions'] for c in r['chunk_byte_ranges']),
                historical_records=6,shared_loader_sites=15,file_categories=12,formal_bridges=len(bounded['verified_direct_bridges']),direct_calls=len(bounded['calls']),window_records=len(windows),sources_sha256=hashes,
                scope='旧源整记录JSON字符串隔离；12审阅仅manifest；无运行态证明')
    put(HERE/'validation.json',result);print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    import sys
    if '--generate' in sys.argv:generate();ledger()
    validate()
