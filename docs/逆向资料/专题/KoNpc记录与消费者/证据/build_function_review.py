"""显式审阅注解合并原证函数身份；未列出的函数保持仅导出。"""
from pathlib import Path
import json
from collections import Counter

HERE = Path(__file__).resolve().parent
ANNOTATIONS = {
    '0x806a30': ('已审阅', 'NPC节与全部字段写入、记录步长、效果分配、计数与缺项边界；文本解析公共实现不升级为已审阅'),
    '0x8054e0': ('已审阅', '固定30条0x238记录构造、NPC计数初始化；公共vector iterator内部不在此结论'),
    '0x805550': ('局部审阅', '仅NPC效果数组释放循环与计数界限；其余资源销毁依赖未闭合'),
    '0x8073c0': ('已审阅', 'indx查找、30上界、先比较后检查-1、NULL失败'),
    '0x807440': ('已审阅', '参数经ECX读取游戏对象+0x14788，计数范围线性查找'),
    '0x8074c0': ('已审阅', '本体返回0空桩；调用者业务仅局部'),
    '0x8074f0': ('已审阅', 'configIndx查找后绑定indx/newRatio；NULL未保护'),
    '0x807750': ('已审阅', 'benefit优先分派、target=-1条件、NULL保护'),
    '0x807830': ('已审阅', '本体返回0空桩；外部触发名称未命名'),
    '0x807860': ('已审阅', '本体返回0空桩；外部触发名称未命名'),
    '0x807890': ('已审阅', '本体返回0空桩；外部触发名称未命名'),
    '0x8078c0': ('已审阅', '本体返回0空桩；外部触发名称未命名'),
    '0x8078f0': ('已审阅', 'recovery入口返回0空桩'),
    '0x807920': ('已审阅', 'attack入口返回0空桩'),
    '0x807950': ('已审阅', '状态、坐标、曼哈顿距离、tile上界、效果数组、目标排除与现金正负链；触发来源未闭合'),
    '0x661490': ('局部审阅', 'NPC绑定、当前配置与startSpeak文本调用现场；全消息/UI注册及其他分支未审阅'),
    '0x7be160': ('局部审阅', '8074C0调用现场实参-1/-2；其余操作循环未审阅'),
    '0x7be450': ('局部审阅', '8074C0调用现场实参-2；其他状态处理未审阅'),
    '0x7c08d0': ('已审阅', '当前角色cash/dice覆盖与配置NULL缺口；后续两个公共角色调用未命名'),
    '0x7c0c50': ('局部审阅', '默认分支8074C0/807750/807440、speakRatio抽样与speak指针入本地事件描述；其他业务及事件消费显示未闭合'),
    '0x7c3220': ('局部审阅', '8074C0调用现场-1；大型函数其余业务未审阅'),
    '0x63e210': ('已审阅', '游戏对象+1628地址访问器'),
    '0x63e230': ('已审阅', '游戏对象+0xE00+index*4角色指针访问器，无界限检查'),
    '0x63e410': ('已审阅', '角色+1464格号访问器'),
    '0x727820': ('已审阅', '游戏对象+3616角色计数访问器'),
    '0x7c0b60': ('局部审阅', '状态谓词后按当前角色序号取角色指针；63E990未补审'),
    '0x7c0bb0': ('局部审阅', '状态谓词后取当前角色NPC flag；63E990未补审'),
    '0x7c0c00': ('局部审阅', '状态谓词且当前序号等于参数时为真；63E990未补审'),
    '0x7e1600': ('已审阅', '格号对地图+28宽度求余/商，无除零保护'),
    '0x7f83f0': ('局部审阅', '现金扣减、不足转存款、归零与返回；7F36F0显示副作用未补审'),
    '0x7fa050': ('局部审阅', '现金增加与显示flag；7F36F0显示副作用未补审'),
    '0x808cb0': ('已审阅', '游戏对象+0x14788 indx读取'),
    '0x808ce0': ('已审阅', '游戏对象+0x14788 indx写入'),
    '0x808d10': ('已审阅', '游戏对象+0x1478C newRatio写入'),
    '0x63f680': ('已审阅', '角色+1504现金覆盖'),
    '0x727bd0': ('已审阅', '角色+1457 byte覆盖，取参数低byte'),
    '0x7f4550': ('局部审阅', '非NULL配置时复制name/suit/cash与角色标志；其余角色快照/广播依赖未审阅'),
    '0x808a50': ('已审阅', '逐字段初值；newRatio无初始化，文本仅首byte清0'),
}


def main():
    records = {}
    for name in ('reused_functions_raw.json', 'reused_accessors_raw.json', 'npc_methods_raw.json',
                 'npc_consumers_raw.json', 'npc_dependencies_raw.json', 'npc_supplement_raw.json'):
        raw = json.loads((HERE / name).read_text('utf-8'))
        for function in raw['functions']:
            va = function['va']
            if va not in records:
                status, note = ANNOTATIONS.get(va, ('仅导出', '公共运行库或旁邻非NPC函数；本专题未作语义审阅'))
                records[va] = dict(va=va, end_va=function['end_va'], name=function['name'],
                                   status=status, review=note, conclusion=note, evidence=[])
            records[va]['evidence'].append('证据/' + name)
    assert set(ANNOTATIONS) <= set(records)
    ordered = sorted(records.values(), key=lambda r: int(r['va'], 16))
    result = dict(scope='逐函数显式分级；已审阅范围依review限定，局部审阅不计全函数完成，仅导出不计审阅',
                  counts=dict(Counter(r['status'] for r in ordered)), unique_functions=len(ordered), functions=ordered)
    (HERE.parent / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// 逐函数审阅清单：以JSON原表为准；导出/字节匹配不自动提升语义状态。']
    lines += ['// ' + r['va'] + ' [' + r['status'] + '] ' + r['review'] for r in ordered]
    (HERE.parent / '04_逐函数审阅清单.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(unique_functions=len(ordered), counts=result['counts']), ensure_ascii=False))


if __name__ == '__main__':
    main()
