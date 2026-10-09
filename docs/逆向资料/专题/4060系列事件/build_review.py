"""从原证入口建立审阅清单；导出与语义结论严格分级，不推算完成率。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    """此映射只列已经逐项核对的局部结论，未核对依赖保留空结论。"""
    conclusions = {
        0x663870: '4060以signed WORD+4生成资源183的T4提示、当前槽6060加现金、6002声音和6080阶段2续接。',
        0x663A50: '4061以signed WORD+6作提示参数和加现金金额，+4进入三DWORD提示标签；单次T30、6060、6002、6080。',
        0x663C50: '4062采用资源185，字段及记录序列同4061；没有参与者循环。',
        0x663E50: '4063用资源186和资源10拼接signed WORD+4，T4后对当前槽加现金，再声音及阶段2续接。',
        0x664040: '4064用资源187和资源10拼接signed WORD+4；6060的+3/+6使当前槽增加存款。',
        0x664230: '4065由7C0230筛选有效槽；每命中复用全局T30数据及文本、加现金+6和声音，循环后仅一次6080。',
        0x6644C0: '4066采用资源189、signed WORD+6金额和+4标签；单次当前槽加现金，没有4067式角色循环。',
        0x6646C0: '4067由7C03C0筛选有效槽；文本按槽128B分隔，每命中加现金+4并发声音，最后一次6080。',
        0x664930: '4068扫描有效槽排除DWORD当前槽，逐槽signed deposit/10扣存款并32位累计，再给当前槽加存款；+4仅提示标签。',
        0x664BC0: '4069遍历有效槽且P+1494不等于-1者，6000 type10的DWORD+12携带静态槽DWORD地址、+16=4，+8保持构造0取默认时长；末尾6005及6080。',
        0x664DF0: '406A遍历有效槽且P+1495不等于-1者，6000 type12的DWORD+12携带静态槽DWORD地址、+16=4，+8保持构造0取默认时长；末尾6005及6080。',
        0x665020: '406B采用资源194，其余当前槽提示、加现金、声音和阶段2续接形状同4060。',
        0x665200: '406C采用资源195，其余当前槽提示、加现金、声音和阶段2续接形状同4060。',
        0x63E1C0: '返回this+112的地址；本群用作参与者名字参数，不证明字符串长度或编码。',
        0x63E410: '读取DWORD[this+1464]；4069/A截为WORD写6005+2，不解释其业务名称。',
        0x63E5B0: 'ECX加0x640后调用63F940读取队列head，返回插入游标；不是OnInitDialog界面操作。',
        0x63E7D0: '读取BYTE[this+3632+slot]；本群按非0筛选有效参与者槽。',
        0x63EF50: '有符号BYTE[this+1494]不等于-1的布尔谓词；具体状态名称未闭环。',
        0x63EF80: '有符号BYTE[this+1495]不等于-1的布尔谓词；具体状态名称未闭环。',
        0x63F080: '构造器首WORD写6000，清DWORD+8/+12/+16，其余字段由调用者选择性写入。',
        0x63F650: '返回DWORD[this+1508]；结合资金读写调用确认本群使用其作为存款。',
        0x64F710: 'signed WORD GmsvID比较WORD[G+83844]；不符显示Error GmsvID并返回false。',
        0x64FA50: '本地事件复制并插入环形队列；本群用returnMode1取得后一槽，满队列-1未被handler检查。',
        0x693260: '首WORD6002、BYTE+5清0、BYTE+6=1、DWORD+8清0；声音编号、槽和1350字段由handler写入，记录12B。',
        0x6932B0: '首WORD6003；清BYTE+4/+5/+6及DWORD+8/+12/+16/+20；type WORD+2未赋，由handler补成24B提示。',
        0x693320: '首WORD6060；BYTE+3/+4/+5/+6清0。槽BYTE+2及金额DWORD+8由handler补写，不是6005构造器。',
        0x6937D0: '构造器只写首WORD6005；4069/A再写WORD+2，插入记录4B。',
        0x693BE0: '首WORD6080且BYTE+3=-1；handler写BYTE+2=2，续本地阶段2，不是TCP确认。',
        0x69B080: 'signed32比较a与1000*b、5000*b，返回18/17/16；乘法无溢出保护，资源文件映射未闭环。',
        0x7C0230: '逐有效槽将三项计数求和，初始最大0，全部相等最大者置flag并返回命中数；RTC iNum为32B。',
        0x7C03C0: '初始最小为子对象两个signed WORD之和，再按三项计数缩小并标相等槽；可能无命中，非命中数返回。',
        0x7EE330: '仅核7EE635..7EE6AD的13个注册写入，映射A9E260..A9E290至4060..406C桥；整个注册器未全审阅。',
        0x63F940: '读取DWORD[this+12]，原调用ECX=G+0x640，本群作为环形队列head使用。',
        0x67FA90: '6060按signed BYTE+2选择P；+3加款，+4减款，优先+5现金其次+6存款；减现金特定模式可设等待500ms。',
        0x7D64B0: '返回signed WORD[this+42]，仅确认最小筛选初始化的一项来源。',
        0x7D64D0: '返回signed WORD[this+44]，仅确认最小筛选初始化的一项来源。',
        0x7E69B0: '枚举子对象条目，两个谓词同时真且owner等于slot时计数；深层类型谓词未闭环。',
        0x7E6B40: '枚举子对象条目，两个谓词同时真且owner等于slot时计数；与7E69B0第二谓词不同。',
        0x7E6C30: '枚举子对象条目，单谓词真且owner等于slot时计数；计数不等于资产金额。',
        0x63EDF0: '四个子谓词作短路或；67FA90调用时ECX=G+0x65C，只核减现金后等待门槛，不命名深层模式。',
        0x63F620: '返回DWORD[this+1504]，减现金消费者用其判断剩余现金是否<=0。',
        0x64FB10: '写DWORD[this+12]=参数和DWORD[this+16]=GetTickCount；本群调用参数500作为等待毫秒数。',
        0x7F83F0: '条件成立时先通知动画，再扣P+1504现金；负差转入P+1508存款并把现金清零，存款<=0归零。动画内部未审阅。',
        0x7F9F10: 'P+1508减amount，负值归零；条件成立时通知动画，未审阅动画内部。',
        0x7FA050: 'P+1504加amount，32位算术无上限检查；条件成立时通知动画，未审阅动画内部。',
        0x7FA0A0: 'P+1508加amount，32位算术无上限检查；条件成立时通知动画，未审阅动画内部。',
    }
    handlers = [0x663870, 0x663A50, 0x663C50, 0x663E50, 0x664040, 0x664230,
                0x6644C0, 0x6646C0, 0x664930, 0x664BC0, 0x664DF0, 0x665020, 0x665200]
    for i, handler in enumerate(handlers):
        conclusions[0x7F0050 + 0x20 * i] = (
            '双参数cdecl桥以首参数作ECX、次参数原传，调用跳板至' + hex(handler)
            + '；只核ABI与目标，不将wrapper视为业务handler。')
    exported = {}
    for name in ['handlers.json', 'helpers.json', 'callees.json', 'funds.json']:
        data = json.loads((HERE / '证据' / name).read_text(encoding='utf-8'))
        for entry in data['functions']:
            va = int(entry['va'], 16)
            exported.setdefault(va, []).append('证据/' + name)
    if set(conclusions) - set(exported):
        raise ValueError('存在没有函数原证的人工记录')
    rows = []
    for va, paths in sorted(exported.items()):
        reviewed = va in conclusions
        row = {'va': hex(va), 'status': '局部语义已审阅' if reviewed else '仅导出',
               'conclusion': conclusions.get(va), 'evidence': paths,
               'unknown': '未实机验证；上游长度、资源内容、深层谓词、动画和间接UI调用仅在有单独证据时计为闭环。'
                          if reviewed else '仅保存完整原证；本专题未作业务语义审阅，不能计为已分析。'}
        if va in handlers:
            row['code'] = hex(0x4060 + handlers.index(va))
            row['evidence'].append('证据/registration_and_rtc.json')
        elif 0x7F0050 <= va <= 0x7F01D0 and (va - 0x7F0050) % 0x20 == 0:
            row['status'] = '桥接ABI局部核对'
        rows.append(row)
    result = {'scope': '4060..406C入口、本地记录与资金消费者局部静态语义审阅',
              'function_evidence_count': len(exported), 'local_review_count': len(conclusions),
              'warning': '完整原证导出、局部语义审阅与游戏实机验收互不等价；CRT及未审阅依赖保留null结论。',
              'functions': rows,
              'unknown': ['资源183..195内容', '6000 type10/12业务', '6003复制时机',
                          '深层计数类型谓词', '上游长度校验', '多人余额权威与恢复', '实机时序']}
    (HERE / '4060系列事件_审阅清单.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'function_evidence_count': len(exported),
                      'local_review_count': len(conclusions)}, ensure_ascii=False))


if __name__ == '__main__':
    build()
