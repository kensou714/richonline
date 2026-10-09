"""保存本专题人工审阅范围；不把邻接导出项自动标成已分析。"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REVIEWED = {
    0x697FC0: '写入物理槽数，清计数与首尾，申请N*288字节',
    0x698050: '288字节按值尾插；满返回0，成功推进尾并递增计数',
    0x6980F0: '在物理位置按较短侧搬移插入；恢复retn 0x128 ABI与返回位置模式',
    0x698640: '以head==next(tail)判满，保留一个空槽',
    0x698680: 'next(i)=(i+1)%N',
    0x6986B0: '前移下标，负值回绕N-1',
    0x64FA50: '复制Size到栈记录，再对G+0x640按值插入；返回模式固定1',
    0x64F870: '按首WORD同步分流八种消息，其他消息进入288字节队列',
    0x7D8010: '无自身空检查的288字节头取出，推进head并递减计数',
    0x7BB290: '三重门控、每次最多取一条、按消息号间接分派',
    0x691BD0: '读取G+0x14777单字节抑制标志，不赋予未证业务名',
    0x7D7F20: '比较head与tail判空',
    0x64FB70: '无符号Tick差值到期清等待时长，返回是否仍等待',
    0x64FB10: '写等待时长及当前Tick',
    0x64FB50: '清等待时长',
    0x7EE330: '向固定表写310个处理入口；表项语义未逐项分析',
}
PARTIAL = {
    0x64F2A0: '已核对G+0x640以256槽初始化；其余游戏初始化未逐调用闭合',
    0x63ACC0: '核对4和10字节记录按返回位置连续插入；其余游戏语义未闭合',
}

def main():
    functions = {}
    for path in sorted(ROOT.glob('第二批_*证据.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        for function in data['functions']:
            va = int(function['va'], 16)
            entry = functions.setdefault(va, dict(
                va=hex(va), status='仅导出', conclusion='邻接初查或扩展候选，尚未语义闭环',
                evidence=[], unknown=['完整调用契约与业务职责尚待逐项分析'],
                document='01_游戏记录队列与消费门控.txt'))
            entry['evidence'].append(path.name)
            if va in REVIEWED:
                entry.update(status='已分析', conclusion=REVIEWED[va],
                             unknown=['静态行为已核对；完整调用前提、并发与实机效果未验证'])
            elif va in PARTIAL:
                entry.update(status='局部已分析', conclusion=PARTIAL[va],
                             unknown=['函数剩余分支及其下游业务契约未闭合'])
    records = list(functions.values())
    result = dict(scope='第二批，人工限定结论，不包括310目标处理器的语义覆盖',
                  counts={s: sum(r['status'] == s for r in records)
                          for s in ['已分析', '局部已分析', '仅导出']},
                  functions=sorted(records, key=lambda r: int(r['va'], 16)))
    (ROOT / '第二批_函数审阅清单.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(result['counts'])

if __name__ == '__main__':
    main()
