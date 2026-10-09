"""记录消费抑制专题的实际人工审阅范围。"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONCLUSIONS = {
    0x67E410: ('已分析', '置消费抑制位，记录Tick，不消费输入记录字段'),
    0x691BD0: ('已分析', '读取单字节消费抑制位'),
    0x7BAE60: ('局部已分析', '核对抑制位与计时字段构造清零，其他嵌套构造未闭合'),
    0x64F780: ('局部已分析', '核对抑制条件及消费入口调用，其余更新子系统未闭合'),
    0x624E80: ('局部已分析', '核对另一消费者入口，其他更新调用未闭合'),
    0x7F1610: ('已分析', 'cdecl双参数转为thiscall，无this偏移，指针原传'),
    0x6501E0: ('局部已分析', '抑制位非零跳过按键与UI72路径'),
    0x650460: ('局部已分析', '核对UI36、两秒Tick阈值和请求状态4；前段文字绘制依赖未全恢复'),
    0x6BAEA0: ('局部已分析', '抑制位门控悬浮信息；完整绘制分支未逐项审阅'),
    0x7BB530: ('局部已分析', '抑制位门控自动选择；各状态策略未逐项闭合'),
    0x629DC0: ('已分析', '直接写全局主状态A6723C并返回输入'),
    0x624CA0: ('局部已分析', '核对按主状态索引函数表，其他每帧更新未逐项闭合'),
    0x62A0F0: ('已分析', '读取全局主状态A6723C'),
}

def main():
    records = {}
    for path in sorted(ROOT.glob('第三批_*证据.json')):
        for function in json.loads(path.read_text(encoding='utf-8'))['functions']:
            va = int(function['va'], 16)
            if va not in CONCLUSIONS:
                raise ValueError('未明确审阅范围：' + hex(va))
            status, conclusion = CONCLUSIONS[va]
            entry = records.setdefault(va, dict(va=hex(va), status=status, conclusion=conclusion,
                evidence=[], document='02_6021抑制与两秒切换链.txt',
                unknown=['实机流程、完整别名写入和线程/重入边界未验证']))
            entry['evidence'].append(path.name)
    result = dict(functions=sorted(records.values(), key=lambda r: int(r['va'], 16)))
    (ROOT / '第三批_函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                               encoding='utf-8')
    print('记录数量：', len(records))

if __name__ == '__main__':
    main()
