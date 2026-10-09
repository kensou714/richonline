"""复验静态原证与资源，生成人工逐入口局部审阅清单；不执行游戏。"""
import collections
import hashlib
import json
import struct
from pathlib import Path
from inspect_resources import collect

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REVIEW = {
0x67DA40:'消费6003的UI号、显示/隐藏位、+16通知和等待；不读取+20。',
0x6E4640:'持管理器临界区，对已存在UI对象同步调虚表+16；未见文本所有权操作。',
0x70B700:'找ID1后未判空调+144，再调自身+164；只有局部通知链已核。',
0x8E2C10:'按ID查根、子项与兄弟，失败返回0。',
0x90B800:'标准label构造写A3131C虚表并初始化文本子对象与布局字段。',
0x8F8040:'先8E0650转码，再同步调控件虚表+148，未保存窄字符串指针。',
0x8E0650:'清20KiB暂存区，优先调用上下文+52回调，否则CP_ACP转换；回调容量不能当真实上限。',
0x90BFF0:'把宽文本复制目标指定为label+88，再调用两项布局更新。',
0x8E1800:'相同内容沿用副本；内容变化释放旧值，分配并逐WCHAR复制后重建测宽。',
0x8E22C0:'根控件先询问上下文+80创建回调再落默认工厂，成功挂根链。',
0x64FA50:'按Size浅拷贝至288B局部，再按值交队列；不复制指针目标。',
0x64FB10:'等待字段写G+12，tick写G+16。',
0x6FAEF0:'调用基类构造再写UI4虚表A24610。',
0x8E24D0:'核对type1分配250h并调用标准label构造；其余类型只保存原证。',
0x6E1D90:'UI基类构造写虚表及少数初值，不初始化整个对象。',
0x8E1620:'文本副本建立后分配测宽数组并再次转码；完整富文本布局未复原。',
0x6980F0:'核对固定288B队列元素搬运及入队，不存在按6003深拷贝文本分支。',
0x6E2E60:'核对15项回调注册及转码回调6E5F90；本函数没有注册+80。',
0x8E0080:'上下文构造清+52/+80，部分宽缓冲清零仅800h；不替代运行期8E0650清零。',
0x8E8660:'非零参数写上下文+52转换回调。',
0x6E5F90:'经64F250/81BAB0获得共享转换结果，再wcscpy到调用者目标；未使用容量参数。',
0x64F250:'懒分配C10h共享对象并复用ABABBC，未见清零或同步。',
0x81BAB0:'CP_ACP转换到对象+1040，容量1024 WCHAR，未检查结果。',
0x8E23F0:'子控件先询问上下文+80再落默认工厂，设置父/子/兄弟链。',
0x6E1E40:'加载资源根并保存对象+4；本文只核UI4资源加载链。',
0x90B8F0:'释放label+88/+96，回收+92节点，重置文本子对象后进入基类析构。',
0x902060:'非NULL时先label析构再operator delete释放对象。',
0x8E0ED0:'只核基类清理入口与文本/子控件所有权相关操作，全部焦点和图像状态未展开。',
0x8EA2B0:'遍历根控件调+120释放，随后释放ACC3C4节点池与上下文。',
0x67F680:'RTC确认栈文本128B；格式化后直接同步通知UI4，没有将此栈地址入6003队列。',
0x66FC80:'本专题只核6003文本来自A7C140、Size24、+20=128；完整送神逻辑见40C1专题。',
0x6932B0:'构造6003并清+4/+5/+6与+8/+12/+16/+20，不为文本分配内存。',
0x6E6F40:'槽4工厂分配48h，成功调用6FAEF0，失败返回0。',
0x6E6080:'只核管理器槽4工厂绑定，不把其他槽算语义完成。',
0x6E3B40:'只核对象创建、资源加载与显示链；失败与prev/dvs完整行为见界面专题。',
0x6E2CD0:'只核上下文创建与6E2E60注册先于界面资源加载。',
0x8E4AD0:'仅导出：UI根资源解析器，沿用界面专题，不据导出提升覆盖。',
0x8E4DC0:'仅导出：子资源递归解析器，沿用界面专题。',
0x8E06F0:'仅导出：type字符串映射，沿用界面专题。',
0x6BFA00:'EnterCriticalSection包装。',
0x6BFA40:'LeaveCriticalSection包装。',
}
PARTIAL = {0x8E24D0,0x8E1620,0x6980F0,0x6E1E40,0x8E0ED0,0x66FC80,0x6E6080,0x6E3B40,0x6E2CD0}
EXPORTED = {0x8E4AD0,0x8E4DC0,0x8E06F0}
for va, offset in ((0x8E8580,8),(0x8E85A0,12),(0x8E86A0,16),(0x8E86C0,20),
                   (0x8E8540,0),(0x8E8560,4),(0x8E85C0,36),(0x8E86E0,24),
                   (0x8E8700,28),(0x8E8620,44),(0x8E8720,64),(0x8E85E0,60),
                   (0x8E8680,56),(0x8E8740,32)):
    REVIEW[va]=f'仅在参数非零时将参数写入上下文+{offset}回调字段；不写+80创建回调。'

def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    offset = pe+24+struct.unpack_from('<H',blob,pe+20)[0]
    sections = [struct.unpack_from('<IIII',blob,offset+40*i+8) for i in range(struct.unpack_from('<H',blob,pe+6)[0])]
    unique, checks, entries, thunks = {}, 0, {}, {}
    def check(r):
        nonlocal checks
        ea, size = int(r['va'],16),r['size']
        actual = None
        for _,rva,rs,ro in sections:
            delta=ea-base-rva
            if 0<=delta and delta+size<=rs:
                actual=blob[ro+delta:ro+delta+size].hex();break
        assert actual == r['idb_hex'] == r['disk_hex'] and r['matching'],r['va']
        unique[(ea,size)]=r
        checks += 1
    for source in ('initial.json','lifecycle.json','locks.json','registration_setters.json'):
        evidence=json.loads((HERE/'证据'/source).read_text(encoding='utf-8'))
        assert evidence['disk_sha256']==sha
        for f in evidence['functions']:
            ea=int(f['va'],16)
            assert ea in REVIEW and ea not in entries
            for r in f['byte_ranges']:check(r)
            ranges=[(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['byte_ranges']]
            for chunk in f['declared_chunks']:
                assert all(any(a<=v<b for a,b in ranges) for v in range(int(chunk['start_va'],16),int(chunk['end_va'],16))), (f['va'],chunk)
            status='仅导出' if ea in EXPORTED else '局部路径已核' if ea in PARTIAL else '局部语义已审阅'
            entries[ea]=dict(va=f['va'],status=status,conclusion=REVIEW[ea],
                unknown='未实机；完整线程、异常分配、全生产者与间接写者图未闭合。',evidence='证据/'+source)
        for t in evidence['thunks']:
            check(t)
            raw=bytes.fromhex(t['idb_hex'])
            assert raw[0]==0xe9 and hex(int(t['va'],16)+5+int.from_bytes(raw[1:],'little',signed=True))==t['target']
            thunks[t['va']]=t
    assert set(entries)==set(REVIEW)
    data=json.loads((HERE/'证据/data.json').read_text(encoding='utf-8'))
    assert data['disk_sha256']==sha
    for r in data['byte_ranges']:check(r)
    assert data['rtcs'][0]['sizes']==[128,8,12,8] and data['rtcs'][2]['sizes']==[288]
    for rtc in data['rtcs']:
        raw=bytes.fromhex(next(r['idb_hex'] for r in data['byte_ranges'] if r['va']==rtc['va']))
        count, pointer=struct.unpack_from('<II',raw)
        assert pointer==int(rtc['va'],16)+8 and count==len(rtc['sizes'])
        assert [struct.unpack_from('<I',raw,12+12*i)[0] for i in range(count)]==rtc['sizes']
    for mapping in data['vtable_dispatch']:
        row=next(r for r in data['byte_ranges'] if r['va']==mapping['vtable'])
        pointer=struct.unpack_from('<I',bytes.fromhex(row['idb_hex']),mapping['offset'])[0]
        assert pointer==int(mapping['thunk'],16)
        thunk=next(r for r in data['byte_ranges'] if r['va']==mapping['thunk'])
        raw=bytes.fromhex(thunk['idb_hex'])
        assert raw[0]==0xe9 and pointer+5+int.from_bytes(raw[1:],'little',signed=True)==int(mapping['implementation'],16)
    assert collect()==json.loads((HERE/'证据/resources.json').read_text(encoding='utf-8'))
    for p in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in p.read_text(encoding='utf-8').splitlines()),p.name
    (HERE/'函数审阅清单.json').write_text(json.dumps(dict(scope='UI4提示文本生命周期；不含实机和全局线程证明',functions=list(entries.values())),ensure_ascii=False,indent=2),encoding='utf-8')
    result=dict(disk_sha256=sha,functions=len(entries),statuses=dict(collections.Counter(r['status'] for r in entries.values())),
        unique_e9_thunks=len(thunks),byte_comparisons=checks,unique_byte_ranges=len(unique),
        total_unique_bytes=sum(r['size'] for r in unique.values()),undeclared_ranges=1,resources=2,
        declared_chunks_covered=True,all_current_disk_bytes_match=True,doc_format_passed=True,
        boundary='静态字节和资源复核不代表实机成功。')
    (HERE/'验证结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
