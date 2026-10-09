"""生成投资专题显式审阅清单，并对保存字节重新核验当前磁盘。"""
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
TOPIC = BASE.parent
ROOT = BASE.parents[4]

# 每项结论均只覆盖本专题实际审阅的控制流，不把整份大函数导出当成全部完成。
REVIEWS = {
    '0x65daa0': ('入口请求', '4012校验GmsvID、错位重插head，保存中途位并建立UI43/pending27。', '错位最终可达和UI到期回调未实测。'),
    '0x6e8530': ('界面资源', 'UI43工厂分配0x48并调用6FBA60，分配失败返回0。', '全局工厂注册见界面专题。'),
    '0x7bc600': ('入口请求', '构造6字节002B，写C48低WORD和选择BYTE，仅本地行动者发送并关UI43。', '返回不代表传输完成，未证明任意选择值获服务端接受。'),
    '0x662780': ('入口请求', '4040值1才标记投资格并按关卡本金扣款；所有值清pending并恢复移动或插6080。', '没有本地一次性校验；网络重放可达性未验证。'),
    '0x6fba60': ('界面资源', '公共窗口构造后设虚表A264F0，无额外投资金额字段初始化。', '公共构造详细职责由界面专题负责。'),
    '0x71f820': ('界面资源', '为ID1和ID2注册事件5回调，状态2另注册事件10回调。', '事件编号不直接等于Windows鼠标消息，回调完整语义未展开。'),
    '0x71f8b0': ('界面资源', '读取关卡1316/1320、格式化文案345后写控件3；RTC证明局部128字节。', '格式化无容量参数；实际ACP和文本换行预处理未实测。'),
    '0x63f300': ('界面资源', '直接返回游戏对象G+3576处当前关卡指针。', '指针初始化、切换与生命周期未由getter证明。'),
    '0x7fac40': ('投资格状态', '在前count个signed WORD位置中首个匹配项设置标志1，未找到不写。', '重复位置和前缀空洞未在此函数校验。'),
    '0x7faad0': ('投资格状态', '固定复制18字节位置，清9标志，统计非-1个数，不压紧。', '实际地图收集顺序和Src长度保证未闭合。'),
    '0x7fab70': ('投资格状态', '前count内匹配位置返回BYTE标志，未找到返回1。', '有效计数和无空洞由调用者保证。'),
    '0x7fabe0': ('投资格状态', '前count内存在零返回0，否则1；空集合返回1。', '零计数进入投资收益分支的真实地图可达性未知。'),
    '0x7facb0': ('投资格状态', '清前count项投资标志，不改位置数组和计数。', '入队失败后没有本函数层回滚；队列可达性另证。'),
    '0x7acdd0': ('界面资源', '仅核investBase/investReturn可选键，经atoi写61868字节关卡记录+1316/+1320。', '大函数其余资源字段、缺键初值及边界未完成。'),
    '0x7b01a0': ('界面资源', '另一关卡集合的两投资键同样写记录+1316/+1320。', '其余加载字段及调用时的文件路径不因局部分支而确认。'),
    '0x7c54b0': ('投资格状态', '仅kind67：全投资则排6060现金奖励与文案后清标志，否则未投且现金>本金时返回0。', '其余格类和返回0后完整服务器请求路径未展开。'),
    '0x7f5d90': ('投资格状态', '仅途中kind67：门控后奖励/清标志，或未投且现金>本金时暂停并提交002A。', '整个移动状态机及非67格类不属于本批完成范围。'),
    '0x693320': ('投资格状态', '6060构造写首WORD并清字节3至6；角色、金额由调用者填写。', '未消费填充不能猜成网络字段。'),
    '0x693920': ('入口请求', '只写首WORD002A，用于申请投资选择流程。', '其余字段由调用者填充。'),
    '0x63e4d0': ('入口请求', '比较角色P+1488有符号BYTE是否等于7。', '角色状态7完整业务名称未恢复。'),
    '0x63e500': ('入口请求', '比较角色P+1499有符号BYTE是否非零。', '字段产品名称未恢复。'),
    '0x67fa90': ('投资格状态', '6060用记录+2有符号BYTE选角色，投资+3/+5非零分支增加现金。', '扣款分支附加判据/500等待的完整业务以及其它用途仅导航。'),
}
REUSED = {
    '0x693b50': ('入口请求', '4012本地记录构造器，用于错位重排前建立栈记录。', '最终8字节被原报文复制覆盖。'),
    '0x693b80': ('入口请求', '写G+83833中途投资标志，输入低BYTE不归一化。', '字段生命周期的全部写入来源未穷尽。'),
    '0x7d6170': ('入口请求', '002B构造器只写首WORD。', '填充来自发送函数栈初始化。'),
    '0x71f9d0': ('界面资源', '状态2下F9先于Esc，按下沿提交1/0后明确清pending。', '按键驱动与UI关闭交错未实机复现。'),
    '0x71fa70': ('界面资源', '控件1/2分别提交1/0，未显式清pending；其它控件无请求。', '继承声音/外观回调完整语义见界面体系。'),
    '0x7bb430': ('入口请求', '保存等待类型、duration、GetTickCount；末个参数不使用。', 'setter不决定何时自动选项。'),
    '0x7bb530': ('入口请求', '只复核pending27的rand()%100>15分支与共同门控/清理。', '全状态动作群参见回合等待专题，不作为本批新增覆盖。'),
    '0x7d5d20': ('入口请求', 'pending!=-1且无符号elapsed>=1000；不比较duration。', '外部自动选择门控另见既有专题。'),
    '0x7f5d10': ('入口请求', '调用内部状态setter(2)后清P+548，途中投资用它暂停。', '完整移动状态定义不由此函数单独证明。'),
}
DOCUMENTS = {'入口请求': '01_入口请求与回复闭环.txt', '界面资源': '02_界面资源与金额来源.txt',
             '投资格状态': '03_投资格状态与回报.txt'}
PARTIAL = {'0x7acdd0', '0x7b01a0', '0x7c54b0', '0x7f5d90', '0x67fa90', '0x7bb530'}


def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 60)[0]
    n = struct.unpack_from('<H', blob, pe+6)[0]
    opt = struct.unpack_from('<H', blob, pe+20)[0]
    segments = [struct.unpack_from('<IIII', blob, pe+24+opt+i*40+8) for i in range(n)]
    def get_disk(ea, size):
        for vs, rva, rawsize, offset in segments:
            q = ea-0x400000-rva
            if 0 <= q and q+size <= rawsize:
                return blob[offset+q:offset+q+size]
        raise ValueError(hex(ea))
    records, audits, unique_bytes = [], [], set()
    movement_path = TOPIC.parent/'移动与动画协议/证据/movement_protocol_core.json'
    movement = json.loads(movement_path.read_text(encoding='utf-8'))
    previous = {f['地址'].lower(): f for f in movement['函数']}
    for path in sorted(BASE.glob('invest_*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        for f in data.get('functions', []):
            ea = f['va'].lower()
            category, conclusion, unknown = REVIEWS[ea]
            records.append({'ea': ea, 'name': f['name'], 'status': '静态局部语义已审阅' if ea in PARTIAL else '静态函数语义已审阅',
                            'conclusion': conclusion, 'unknown': unknown, 'document': DOCUMENTS[category],
                            'evidence': '证据/'+path.name+'/functions/'+ea,
                            'boundary': '仅静态；间接依赖和实机可达性另证',
                            'previous_evidence': '../移动与动画协议/证据/movement_protocol_core.json' if ea in previous else None})
            for span in f['byte_ranges']:
                raw = bytes.fromhex(span['idb_hex']); start = int(span['va'],16)
                ok = raw == get_disk(start,len(raw))
                audits.append({'kind': 'function', 'ea': ea, 'start': span['va'], 'size': len(raw), 'matching': ok})
                unique_bytes.update(range(start,start+len(raw)))
        for row in data.get('thunks', []):
            raw = bytes.fromhex(row['idb_hex'])
            audits.append({'kind': 'thunk', 'ea': row['va'], 'matching': raw == get_disk(int(row['va'],16),len(raw))})
        extra = [data] if 'idb_hex' in data else [v[k] for v in data.get('rows',[]) for k in ['cell','thunk']]
        for row in extra:
            raw = bytes.fromhex(row['idb_hex'])
            audits.append({'kind': 'data', 'ea': row['va'], 'matching': raw == get_disk(int(row['va'],16),len(raw))})
    for ea, (category, conclusion, unknown) in REUSED.items():
        if ea not in previous:
            raise ValueError('复用函数原证缺失 '+ea)
        records.append({'ea': ea, 'name': previous[ea]['名称'], 'status': '静态局部语义已审阅' if ea in PARTIAL else '静态函数语义已审阅',
                        'conclusion': conclusion, 'unknown': unknown, 'document': DOCUMENTS[category],
                        'evidence': '../移动与动画协议/证据/movement_protocol_core.json/函数/'+ea,
                        'boundary': '复用既有完整函数证据；不计本专题新增独立入口'})
    (TOPIC/'函数审阅清单.json').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    errors = [(p.name,i) for p in TOPIC.glob('*.txt') for i,line in enumerate(p.read_text(encoding='utf-8').splitlines(),1)
              if line.strip() and not line.startswith('//')]
    assert not errors and all(a['matching'] for a in audits)
    validation = {'disk_sha256': hashlib.sha256(blob).hexdigest(), 'local_function_records': len(REVIEWS),
                  'reused_records': len(REUSED), 'reviewed_total': len(records),
                  'partial_function_records': len(PARTIAL), 'unique_local_instruction_bytes': len(unique_bytes),
                  'text_format_errors': errors, 'audits': audits,
                  'runtime_test': '未运行客户端，未连接服务端；只读字节核验与资源解包'}
    (BASE/'validation.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in validation.items() if k != 'audits'},ensure_ascii=False))


if __name__ == '__main__':
    main()
