"""重验当前磁盘、资源及文档格式，并生成逐函数审阅清单。"""
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
TOPIC = BASE.parent
ROOT = BASE.parents[4]

# 数字是正文文件序号；每个入口显式说明已读范围，避免把导出量当作完成量。
REVIEWS = {
 '0x63f390': (1, '读G+3672+slot身份字节，控制文案前缀和部分模式展示。'),
 '0x693a50': (1, '返回角色现金与存款的32位和；400E在清理后读取。'),
 '0x6be240': (1, '写单例首BYTE；只有非零值才更新两处Tick。'),
 '0x6fb850': (3, 'UI36公共窗口构造后设置虚表A25F40。'),
 '0x6fb920': (4, 'UI38公共窗口构造后设置虚表A260E0。'),
 '0x712610': (1, '调用两处开关与公共刷新，并给UI0构造事件64记录。'),
 '0x7be160': (2, '核入口双标志、资金清零、清理调用顺序、特殊槽分流及计数/活动位写入。'),
 '0x7c0c00': (1, '模式4且槽等于G+116时为真；核ECX指向G+1628的模式对象。'),
 '0x629e10': (2, '模式谓词直接比较参数是否为4。'),
 '0x63e560': (4, '判断槽是否等于对象+8的本地槽。'),
 '0x63f470': (4, '判断槽是否等于G+3624的当前行动槽。'),
 '0x65c0d0': (4, '空包本地调用或合法GmsvID时清状态并设主状态7。'),
 '0x693620': (2, '将G+3640+slot在局记录BYTE写为输入值。'),
 '0x7be450': (2, '离线清理按旧活动位决定回收和减数；末尾清两标志并保存旧活动位。'),
 '0x7d6340': (2, '写G+3656+slot，离线调用者传旧活动位。'),
 '0x63ec70': (2, '仅清68字节格记录+3所有者，不清建筑等级。'),
 '0x71e4c0': (4, '为录像确认界面的ID1/2注册事件5、10回调。'),
 '0x71e610': (4, '录像取消关窗；确认关窗并设主状态14。'),
 '0x7e3e60': (2, '条件移除关联列表，清所有者、重置显示资源，按格类调用后继。'),
 '0x65c700': (4, '400A区分本地退出与普通离线，更新记录和聊天，并解除部分等待。'),
 '0x65cb30': (1, '400C可空包调用，清UI/声音/行动角色/pending/单例并联动UI状态。'),
 '0x65cc00': (1, '400D获胜文案及动画排队；未直接写战绩胜者位。'),
 '0x65cf40': (1, '400E先退场清理再按条件排破产/败退表现；资金文案用清理后余额。'),
 '0x65d390': (1, '400F可先排平局提示，随后总是排UI29战绩显示4000毫秒。'),
 '0x65d520': (4, '4010按+6分支延迟重排或启动界面并进入回合入口。'),
 '0x65e460': (3, '401B按signed槽写R+140/144/148/152至155及G+1500数组。'),
 '0x6e8140': (3, 'UI36分配0x4C并构造，失败返回0。'),
 '0x6e8260': (4, 'UI38分配0x48并构造，失败返回0。'),
 '0x63e990': (2, '读取地图对象+24模式值后交629E10比较4。'),
 '0x63f680': (2, '直接写DWORD[P+1504]现金。'),
 '0x63f6b0': (2, '直接写DWORD[P+1508]存款。'),
 '0x63e7d0': (2, '读G+3632+slot活动BYTE，无范围检查。'),
 '0x63efe0': (2, '清BYTE[P+1472+slot]关系槽。'),
 '0x64efa0': (2, '读G+3640+slot在局记录BYTE，无范围检查。'),
 '0x6935f0': (2, '写G+3632+slot活动BYTE。'),
 '0x71e040': (3, 'UI36读取本地R+153选择控件1/2并记录窗口+72Tick。'),
 '0x71e120': (3, '按100*elapsed/2000更新控件10进度，上夹100；不执行离房。'),
 '0x71e540': (4, '窗口可操作时Enter触发录像确认ID2，Esc触发取消ID1。'),
 '0x7d9cc0': (2, '扫描this+1到+32，将匹配槽字节写为-1。'),
 '0x7e6200': (2, '核所有者清理、多个位置集合失效、设施关联清理和公共尾循环。'),
 '0x7f9560': (2, '核六个角色状态字节清零、8槽双向关系清理与两个尾部setter。'),
 '0x629c90': (3, '懒创建0x14794字节游戏对象A7672C，存在时直接返回。'),
 '0x727820': (3, '读DWORD[G+3616]槽计数。'),
 '0x7284d0': (3, '返回G+156玩家记录数组基址。'),
 '0x7284f0': (3, '返回G+1436，战绩读取其+64+4*i。'),
 '0x7285d0': (3, '返回G+64，战绩读取其+64基准数值。'),
 '0x6e7d50': (3, 'UI29分配0x1134并构造，失败返回0。'),
 '0x6fb5e0': (3, 'UI29设置虚表A25990，并构造8个0x21C字节展示对象。'),
 '0x717a90': (3, '注册战绩行绘制回调，初始化提示Tick/标志并关闭UI44。'),
 '0x717c70': (3, '核玩家记录三数值、胜败标志、显示背景、行索引与后续提示使能。'),
 '0x718810': (3, '核控件绘制分类、正负数展示、IpBonus文本路径及300毫秒提示变色。'),
}
PARTIAL = {
 '0x712610':'两个开关与公共刷新对象的全部产品含义未展开。',
 '0x7be160':'各模式辅助状态的完整枚举、特殊模式后继与越界可达性未闭合。',
 '0x7be450':'各模式辅助清理完整业务与后继回调未展开。',
 '0x7e3e60':'三条件与末尾格类附加清理的完整业务语义未恢复。',
 '0x65d520':'7C0C50完整回合调度及1800毫秒后继未在本批展开。',
 '0x7e6200':'设施回调、特殊模式全语义与所有集合容量保证未完成。',
 '0x7f9560':'尾部两个状态setter业务名称尚未恢复。',
 '0x717c70':'奖励、继续关卡与模式后继仅导航；不声称整函数全审。',
 '0x718810':'IpBonus浮点ABI和业务公式未复核，不作为服务端结算算法。',
}


def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I',blob,60)[0]
    count = struct.unpack_from('<H',blob,pe+6)[0]
    opt = struct.unpack_from('<H',blob,pe+20)[0]
    base = struct.unpack_from('<I',blob,pe+52)[0]
    sections = [struct.unpack_from('<IIII',blob,pe+24+opt+i*40+8) for i in range(count)]
    def disk(ea,size):
        for _,rva,raw_size,offset in sections:
            q=ea-base-rva
            if 0<=q and q+size<=raw_size:
                return blob[offset+q:offset+q+size]
        raise ValueError(hex(ea))
    audits=[]; manifest=[]; unique=set()
    def check(row,kind):
        raw=bytes.fromhex(row['idb_hex']); ea=int(row['va'],16)
        ok=raw==disk(ea,len(raw))
        audits.append({'kind':kind,'ea':row['va'],'size':len(raw),'matching':ok})
        assert ok, row['va']
    documents={int(p.name[:2]):p.name for p in TOPIC.glob('0[1-4]_*.txt')}
    for path in sorted(BASE.glob('endgame_*.json')):
        data=json.loads(path.read_text(encoding='utf-8'))
        for f in data.get('functions',[]):
            ea=f['va']; number,conclusion=REVIEWS[ea]
            manifest.append({'ea':ea,'name':f['name'],
                'status':'静态局部语义已审阅' if ea in PARTIAL else '静态函数语义已审阅',
                'conclusion':conclusion,'unknown':PARTIAL.get(ea,'实机可达性、上游输入约束及间接依赖另证。'),
                'document':documents[number], 'evidence':'证据/'+path.name+'/functions/'+ea,
                'boundary':'仅静态审阅；完整原证含汇编与字节，不等于实机复现。'})
            for span in f['byte_ranges']:
                check(span,'function'); start=int(span['va'],16)
                unique.update(range(start,start+span['size']))
        for t in data.get('thunks',[]): check(t,'thunk')
        for row in data.get('rows',[]): check(row,'table_or_thunk')
    assert len(manifest)==len(REVIEWS)==len({m['ea'] for m in manifest})
    errors=[(p.name,i) for p in TOPIC.glob('*.txt') for i,l in enumerate(p.read_text(encoding='utf-8').splitlines(),1) if l.strip() and not l.startswith('//')]
    assert not errors
    resources=json.loads((BASE/'界面与文案样本.json').read_text(encoding='utf-8'))
    for r in resources['records']:
        assert hashlib.sha256((ROOT/r['source']).read_bytes()).hexdigest()==r['sha256']
    (TOPIC/'函数审阅清单.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    report={'disk_sha256':hashlib.sha256(blob).hexdigest(),'function_records':len(manifest),
        'partial_function_records':len(PARTIAL),'unique_instruction_bytes':len(unique),
        'text_format_errors':errors,'resources_verified':len(resources['records']),
        'runtime_test':'未运行客户端，未连接服务端，仅只读静态核验。','audits':audits}
    (BASE/'validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='audits'},ensure_ascii=True))


if __name__=='__main__':
    main()
