"""生成显式函数覆盖，未读函数保持仅导出。"""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = json.loads((HERE / '证据/teachmode_raw.json').read_text(encoding='utf-8'))
REVIEWS = {
    '0x628e30': ('完整函数静态审阅', '01_初始化与默认值.txt', 'A76714空时分配8B并构造，返回单例；含异常尾块。', '并发和分配失败外层责任未知。'),
    '0x8102f0': ('完整函数静态审阅', '01_初始化与默认值.txt', 'memset清零完整368B记录。', 'memset库后端未在此新增审阅。'),
    '0x810330': ('完整函数静态审阅', '01_初始化与默认值.txt', '明确写N=0、R=0；自动库名不作为归属。', '不代表每次getter都会重建。'),
    '0x810360': ('既有完整审阅复用', '01_初始化与默认值.txt', '释放并清R，不清N；复用旧专题。', '完整关闭调用链仍未补证。'),
    '0x8103b0': ('既有完整审阅复用并补构造', '01_初始化与默认值.txt', 'TeachMode双遍MAP装载；新增记录默认值原证。', '重载、解析助手、奖励消费者未知。'),
    '0x810d20': ('既有完整审阅复用', '02_访问器与调用者.txt', '按mapName返回数组序号或-1；新增直接调用者原证。', '畸形N/R责任未知。'),
    '0x603fd3': ('跳板原字节核验', '02_访问器与调用者.txt', 'E9到810D20。', '不计独立业务实现。'),
    '0x60f3e2': ('跳板原字节核验', '01_初始化与默认值.txt', 'E9到628E30。', '不计独立业务实现。'),
    '0x623ee0': ('启动局部审阅与既有复用', '00_阅读入口.txt', '623FF3/623FF8/623FFF以TeachMode路径装载本单例。', '其余启动责任沿用既有专题。'),
    '0x6a1270': ('完整函数静态审阅', '02_访问器与调用者.txt', '按当前地图名找序号，区分首项/末项/非-1的界面调用。', '界面编号、外部条件和回调完整语义未知。'),
    '0x6a1530': ('完整函数静态审阅', '02_访问器与调用者.txt', '名称未命中返回0，命中交6A14B0读取字节状态。', '字节2完整业务含义未知。'),
    '0x6a1580': ('完整函数静态审阅', '02_访问器与调用者.txt', '按N扫描状态前缀，满表钳N-1，最终参数<=边界。', '无本地非负参数检查；状态生产者未知。'),
    '0x6a1610': ('完整函数静态审阅', '02_访问器与调用者.txt', '名称未命中返回0，否则交6A1580。', '运行触发和外层范围责任未知。'),
    '0x6a3c60': ('TeachMode相关路径局部审阅', '02_访问器与调用者.txt', '按状态前缀取记录+4名称交后续；N0路径取-1。', '发送/界面助手及其它对象布局未完整审阅。'),
    '0x717c70': ('TeachMode相关分支局部审阅', '02_访问器与调用者.txt', '以另一对象+104的序号和N-1限制UI+4396并触及5132。', '完整函数其它UI逻辑未归入本专题。'),
    '0x767cb0': ('完整函数静态审阅', '02_访问器与调用者.txt', '返回值2分支由当前名查序号，条件成立取下一记录+4名称。', '6A6EB0名称接收语义、虚调用与状态回传未知。'),
    '0x7f3c70': ('TeachMode相关分支局部审阅', '02_访问器与调用者.txt', '在非a3及谓词非0分支，将记录bossName、role/mood和12装备复制到角色。', '序号有效性、完整模式谓词及其它初始化路径未知。'),
    '0x691a70': ('完整函数静态审阅', '02_访问器与调用者.txt', '以this+24值调用63EDD0，作为两处消费者的条件。', '63EDD0未展开，不补模式名称。'),
    '0x6a14b0': ('完整函数静态审阅', '02_访问器与调用者.txt', '另一对象+604字符串非空、无符号长度足够且选中字节2时为真。', '字符串生产者及字节状态含义未知。'),
    '0x6b7790': ('完整函数静态审阅', '02_访问器与调用者.txt', '返回this+0的DWORD，即本调用上下文的N。', '同形getter不能单凭函数体命名所有this。'),
    '0x6b7c30': ('完整函数静态审阅', '02_访问器与调用者.txt', '返回R+368*参数，无本地范围检查。', '参数有效性属于外层责任。'),
    '0x7284b0': ('完整函数静态审阅', '02_访问器与调用者.txt', '返回另一对象+104，消费者作记录序号用。', '序号生产与同步责任未知。'),
}
rows = []
for index, row in enumerate(RAW['functions']):
    review = REVIEWS.get(row['va'])
    status, document, fact, unknown = review or ('仅导出未审阅', None, None, '邻接短函数导航；不作业务结论或新增覆盖。')
    rows.append(dict(va=row['va'], end_va=row['end_va'], status=status, document=document,
                     fact=fact, conclusion=fact,
                     inference='仅正文显式标为推断的条件性结论。' if review else None,
                     unknown=unknown, evidence=f'证据/teachmode_raw.json#/functions/{index}',
                     chunks=len(row['chunks']), instructions=len(row['instructions'])))
result = dict(schema=1, scope='TeachMode对象、访问器与消费者；仅导出不等于已审阅',
              pe_sha256=RAW['disk_sha256'], status_counts=dict(Counter(r['status'] for r in rows)),
              functions=rows)
(HERE / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result['status_counts'], ensure_ascii=False))
