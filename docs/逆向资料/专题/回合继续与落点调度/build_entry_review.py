"""汇总主协调者逐函数结论；阶段0/1/2与范围效果由各自清单独立记录。"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# 只纳入已逐项人工阅读的职责；完整原证中的外部依赖不会自动升级。
REVIEWS = {
    0x681380: ('已分析', '本地6080按signed阶段分派0/1/2/6，前三阶段非0才使用更新游标插入后继'),
    0x693be0: ('已分析', '只写WORD6080和BYTE+3=-1，阶段+2由调用者提供'),
    0x660b00: ('局部分支已分析', '4031中+4=-1分支清pending、关UI20、插6080阶段2；其他分支未闭合'),
    0x67b770: ('已分析', '4206校验身份，以signed文本索引构造6003提示，再在返回游标排6080阶段2'),
    0x681890: ('已分析', '6084传signed起始阶段/BYTE参数给7CB3F0，非0且+4开启才插6080阶段6'),
    0x681f60: ('局部已分析', '608F从当前角色位置进入7CBD50，非0才插6080阶段1；范围子函数另清单'),
    0x6932b0: ('已分析', '构造6003，清+4/+5/+6及+8/+12/+16/+20，未清所有填充'),
    0x7cb3f0: ('局部已分析', '完整分支顺序和构造字段已核，按P+1488状态4/3/5/6生成附加地产任务；外部副作用另核'),
    0x63eca0: ('已分析', '地图模式0或模式2且子模式0的短路或谓词'),
    0x63e990: ('已分析', '读取地图+24传模式4比较器'),
    0x63e3e0: ('已分析', '道路数组stride8的+2读取signed WORD地产索引'),
    0x63ec00: ('已分析', '地产数组stride68的+3读取signed BYTE所有者'),
    0x63f100: ('已分析', '地产数组stride68的+6读取signed WORD组号'),
    0x727b40: ('已分析', '角色+1488 BYTE等4'),
    0x63f500: ('已分析', '地产+1类别等1'),
    0x63f5b0: ('已分析', '实参角色槽与地产+3 signed所有者比较'),
    0x63e290: ('已分析', '地产+0类型等11'),
    0x693da0: ('已分析', '地产+1 signed类别在闭区间2..6'),
    0x693e20: ('已分析', '只写WORD6070'),
    0x693f20: ('已分析', '只写WORD6073'),
    0x693e50: ('已分析', '只写WORD6085'),
    0x701530: ('已分析', '角色+1488 BYTE等3'),
    0x7d7400: ('已分析', '角色+1488 BYTE等5'),
    0x63ec30: ('已分析', '地产+3 signed所有者不为-1'),
    0x63f730: ('已分析', '只写WORD6063'),
    0x693d40: ('已分析', '写WORD6071与+5标志1'),
    0x727b70: ('已分析', '角色+1488 BYTE等6'),
    0x7e3df0: ('已分析', '排除地产类别8/9/10且signed等级大于0'),
    0x6945d0: ('已分析', '写WORD6072与+4/+5标志1'),
    0x693260: ('已分析', '写WORD6002、+5=0、+6=1、DWORD+8=0'),
    0x63ed10: ('已分析', '读取地图+24传模式0比较器'),
    0x63ed50: ('已分析', '地图+24==2且地图+108==0'),
    0x629e10: ('已分析', 'cdecl整数实参等4'),
    0x692030: ('已分析', '地产+1类别属于8/9/10'),
    0x680490: ('局部已分析', '6070 signed p/actor/delta，增级及动画4并暂停队列，组效果依赖待深入'),
    0x6806d0: ('局部已分析', '6071移除旧归属后有条件赋予新归属，模式专属同步和集合契约待深入'),
    0x680a90: ('局部已分析', '6072减级刷新并开动画4，+5控制暂停，模式4附加更新待深入'),
    0x680bc0: ('局部已分析', '6073写类别后增级刷新，开动画4并暂停；类型功能依赖待深入'),
    0x681980: ('已分析', '6085仅本地行动者开UI13，所有客户端写pending9及G+83780时长'),
    0x629dd0: ('已分析', 'cdecl整数实参等0'),
    0x63edd0: ('已分析', 'cdecl整数实参等2'),
    0x63f2d0: ('已分析', '将实参低BYTE写入地产+1类别'),
    0x7e4020: ('局部已分析', 'signed等级减DWORD实参写回低BYTE再signed非正归0，类型/归属附加清理待深入'),
    0x694bc0: ('已分析', '动画对象表按40字节步长读+36字段，语义依赖管理器专题'),
}


def main():
    sources = {}
    for name in ('continue_entry', 'continue_sources', 'continue_helpers',
                 'property_effect_predicates', 'property_effect_consumers', 'property_effect_helpers'):
        path = ROOT / '证据' / (name + '.json')
        for row in json.loads(path.read_text(encoding='utf-8'))['functions']:
            assert row['bytes_match_disk'], row['va']
            sources.setdefault(int(row['va'], 16), []).append(path.relative_to(ROOT).as_posix())
    rows = []
    for ea, (status, conclusion) in sorted(REVIEWS.items()):
        rows.append(dict(va=hex(ea), status=status, conclusion=conclusion, evidence=sources[ea],
                         document=['00_6080阶段链与阅读入口.txt', '01_旁路恢复与构造来源.txt',
                                   '02_角色状态附加地产效果.txt'],
                         unknown=['无实机验证；外部输入域、未展开依赖与跨帧时序不在本条证明范围']))
    path = ROOT / '入口及附加效果函数审阅清单.json'
    path.write_text(json.dumps(dict(scope='主协调者函数内结论，跨专题不得自动选最高等级',
                                    functions=rows), ensure_ascii=False, indent=2), encoding='utf-8')
    print('显式审阅条目', len(rows))


if __name__ == '__main__':
    main()
