"""从可追溯原证生成审阅清单，未声明窗口单列，复用不计新增函数。"""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
TOPIC = BASE.parent
NEW = {
    '0x6290c0': ('已审阅', '保存 this，调用805550；flags低位为1时调用operator delete后仍返回保存的this。'),
    '0x808ba0': ('已审阅', 'ECX this不变地转交808FD0；伪码未显示this，非无参全局清理。'),
    '0x808bd0': ('已审阅', 'flags位2选数组析构分支，步长0x1A4、this-4计数；位1控制删除，单对象分支调用805430。'),
    '0x808df0': ('已审阅', '保存this；局部一字节对象经809D40返回指针，连同另一局部字节地址转交8093C0；返回保存this。'),
    '0x9dad5f': ('局部审阅', '仅核查9DAE3E条件跳转位移；9DAE3F四字节1478C不是NPC字段访问，其余大型本体未审阅。'),
    '0x808fd0': ('已审阅', 'ECX this传递至809C40；调用包装，不是NPC生成。'),
    '0x8093c0': ('局部审阅', '构造包装依次调用80B2D0、80B250、80AB10并返回this；底层布局和分配内部未闭合。'),
    '0x809d40': ('已审阅', 'ECX赋EAX并返回，未写对象；自动MFC标签不当作业务类身份。'),
    '0x809c40': ('局部审阅', '容器清理包装：迭代清理调用、头节点三个链接取地址后交助手、释放头节点；+4/+8置0。节点递归/分配器内部未知。'),
    '0x80ab10': ('局部审阅', '构造容器头节点，+4保存分配助手返回值，三个链接助手结果写同一头指针、标记助手结果写1、+8置0；助手偏移和allocator未审阅。'),
    '0x80b250': ('局部审阅', 'allocator状态构造包装，80B2D0返回原this、80C8B0内部未闭合。'),
    '0x80b2d0': ('已审阅', 'ECX赋EAX并ret4，忽略输入DWORD，不写对象。'),
}
REUSED = {
    '0x628010': '复核A7671C为0时new0x4588并调用8054E0；已有全局对象单例原证。',
    '0x624080': '仅复核624148..62418B的A7671C非零、直接桥调用6290C0传flags=1和全局置0；其余退出链复用。',
    '0x8054e0': '复用30条0x238记录构造；补核+4570构造包装与+457C/+4580/+4584清零。',
    '0x805550': '补核+4580非零时flags=3交808BD0再清零，按+4584遍历effects释放，+4570交808BA0。分配者和树节点析构内部未知。',
    '0x805430': '复核+0/+80首字节、+100 DWORD及+104起10个DWORD置0；没有释放调用，不能凭析构包装推额外资源所有权。',
    '0x805660': '复用三个资源读取调用短路链，最后806A30返回非零判成功；未新增热重载保证。',
    '0x808cb0': '复用读取游戏对象+0x14788 indx。',
    '0x808ce0': '复用写游戏对象+0x14788 indx。',
    '0x808d10': '复用写游戏对象+0x1478C newRatio；当前字面位移扫描未找到其它真实访问。',
    '0x8073c0': '复用按配置indx线性查找，供绑定链参考，不作生成算法。',
    '0x807440': '复用对象indx取得配置记录；807589未声明窗口新增消费现场单列。',
    '0x8074f0': '复用配置indx和newRatio复制到游戏对象，参数与空指针边界保持旧结论。',
    '0x807830': '复用返回0空桩；本批未声明窗口补证fire选择下标0对应此桥。',
    '0x807860': '复用返回0空桩；本批未声明窗口补证bomb选择下标1对应此桥。',
    '0x807890': '复用返回0空桩；本批未声明窗口补证missile选择下标2对应此桥。',
    '0x8078c0': '复用返回0空桩；本批未声明窗口补证frost选择下标3对应此桥。',
}
UNKNOWN = {
    '0x6290c0': '805550外部依赖的完整释放/异常契约，以及调用者是否使用删除后返回值未闭合。',
    '0x808ba0': '底层809C40节点递归清理和allocator内部未闭合。',
    '0x808bd0': '数组分配者、this-4实际条数来源、eh vector iterator内部和异常释放次序未闭合。',
    '0x808df0': '8093C0底层容器布局、allocator状态意义和分配失败契约未闭合。',
    '0x9dad5f': '除9DAE3E条件跳转误命中排除外，其余大型函数业务及外部调用未展开。',
    '0x808fd0': '转交的809C40节点清理、释放助手内部和异常契约未闭合。',
    '0x8093c0': '80B250、80AB10的allocator状态和节点真实布局未闭合。',
    '0x809d40': '原模板/业务类型身份、局部字节对象的设计意义未闭合。',
    '0x809c40': '迭代器和区间清理内部、三链接助手偏移、节点递归和分配器释放契约未闭合。',
    '0x80ab10': '头节点分配助手、标记/链接地址助手实际偏移和allocator内部未闭合。',
    '0x80b250': '80C8B0内部、allocator状态类型和参数设计意义未闭合。',
    '0x80b2d0': '被忽略DWORD和返回原this的模板/allocator设计意义未闭合。',
    '0x628010': '全部调用者、初始化并发和配置对象首部未构造区域的生存期未在本批展开。',
    '0x624080': '仅复核A7671C清理片段；其它退出对象、线程同步、进程退出时序未在本批展开。',
    '0x8054e0': 'vector constructor iterator内部、异常时部分记录回滚，以及后续加载的完整调用时序未闭合。',
    '0x805550': '+4580数组分配者、计数污染来源、容器节点递归清理和重复调用/异常时序未闭合。',
    '0x805430': '0x1A4附属对象业务身份、清零字段的完整设计意义和上层分配者未闭合。',
    '0x805660': '前两资源读取依赖内部未在本批展开；失败后的部分状态回滚和热重载保证未知。',
    '0x808cb0': 'indx初始化全部来源及别名读取未在本批展开。',
    '0x808ce0': 'indx选择算法、绑定时序及其它间接写入未闭合。',
    '0x808d10': 'newRatio真实生成/读取规则、别名地址和整对象拷贝消费者仍未知，字面扫描不能证明无读取。',
    '0x8073c0': '生成选择算法、坏编号来源及全部动态调用未在本批展开。',
    '0x807440': '对象生命周期、坏绑定indx来源及未声明窗口实际触发入口未闭合。',
    '0x8074f0': '传入indx的完整生产者、newRatio生成规则以及非法indx在上层如何防止未闭合。',
    '0x807830': 'fire空桩原设计意义与未声明harm范围的实际可达性未闭合，不能证明已执行伤害。',
    '0x807860': 'bomb空桩原设计意义与未声明harm范围的实际可达性未闭合，不能证明已执行伤害。',
    '0x807890': 'missile空桩原设计意义与未声明harm范围的实际可达性未闭合，不能证明已执行伤害。',
    '0x8078c0': 'frost空桩原设计意义与未声明harm范围的实际可达性未闭合，不能证明已执行伤害。',
    '0x661490': '旧绑定消费者的完整消息注册、字段+8/+10和后续UI未在本批展开；NPC选择来源未知。',
    '0x7c08d0': '旧cash/dice应用链之后的完整掷骰算法和推进时序未在本批展开。',
    '0x7c0c50': '大型旧消费者的全部分支和本地事件实际执行未在本批展开。',
    '0x806a30': '旧加载器的文本解析共同依赖、day/random/newRatio生成消费和重复加载规则未在本批展开。',
    '0x807750': '旧效果选择链的完整触发时序及全体blood入口未在本批展开。',
    '0x807950': '旧曼哈顿格距/余额效果链的全体blood触发来源和异常资源边界未在本批展开。',
}


def main():
    rows = []
    for filename in ('generation_raw.json', 'lifecycle_dependencies_raw.json', 'lifecycle_leaves_raw.json'):
        value = json.loads((BASE / filename).read_text('utf-8'))
        for index, record in enumerate(value['functions']):
            status, conclusion = NEW[record['va']]
            rows.append(dict(va=record['va'], status=status, conclusion=conclusion,
                unknown=UNKNOWN[record['va']],
                evidence=[f'证据/{filename}#/functions/{index}'],
                ranges=record['declared_chunks'], origin='本批新导出'))
    value = json.loads((BASE / 'reused_evidence.json').read_text('utf-8'))
    for index, item in enumerate(value['reused']):
        record = item['record']
        conclusion = REUSED.get(item['va'], '复用既有消费者原证与旧审阅，本批仅用于调用关系导航，不新增完整语义审阅。')
        status = '局部审阅' if item['va'] in ('0x624080', '0x805550') else '复用审阅'
        rows.append(dict(va=item['va'], status=status, conclusion=conclusion,
            unknown=UNKNOWN[item['va']],
            evidence=[f'证据/reused_evidence.json#/reused/{index}', item['source']],
            ranges=record.get('declared_chunks') or record['byte_ranges'], origin='复用原证'))
    output = dict(scope='声明函数和未声明窗口分别计数；复用不计本批新增函数',
        functions=sorted(rows, key=lambda row: int(row['va'], 16)),
        unrecognized_ranges=[dict(start_va='0x807560', end_va='0x80772e', status='范围已审阅',
            conclusion='从序言至ret4的未声明代码；num执行次数和harm随机选择/20次重抽/顺序fallback/四空桩映射。入口调用者未闭合，不作为NPC生成或独立声明函数。',
            unknown='603DDF当前xref没有调用者；间接调用、网络/回合触发时序和实机执行未闭合。',
            evidence=['证据/unowned_npc_window.json', '证据/window_bridges.json', '证据/window_bridges_disk_audit.json'])])
    (TOPIC / '函数审阅清单.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('review records:', len(rows))


if __name__ == '__main__':
    main()
