"""关联人工逐函数结论与证据；导出、复用与语义审阅分别统计。"""
from pathlib import Path
from collections import Counter
import json

BASE = Path(__file__).parent
SOURCES = ['handlers.json', 'core.json', 'finance_core.json', 'additional_core.json',
           'animation9.json', 'animation9_dependencies.json', 'shared_boundaries.json',
           'ui30_reused.json', 'insurance_dependencies.json', 'bridges_reused.json']
notes = {}
def add(addresses, status, conclusion, unknown):
    for address in addresses.split():
        key = hex(int(address, 16))
        assert key not in notes, key
        notes[key] = dict(review_status=status, conclusion=conclusion, unknown=unknown)

handlers = json.loads((BASE / 'handlers.json').read_text(encoding='utf-8'))['functions']
labels = ['考古宝藏收入', '传家宝收入', '并列最高存款奖励', '闯马路罚款', '钱包遗失',
          '豪雨停留', '垃圾罚款', '缴保险金', '狗只罚款', '冒贷', '海外投资损失',
          '全部卡片道具变卖', '污水罚款', '噪声罚款', '赌博罚款', '涂鸦罚款',
          '慈善捐款', '虐待动物罚款', '掉水沟就医']
for index, f in enumerate(handlers):
    add(f['va'], '局部语义已审阅', f'{0x406d+index:04X} {labels[index]}；字段、事件顺序和条件见01逐项记录。',
        '读取下界非完整网络长度；服务端权威结算及外部最终推进未闭合。')
notes['0x667b10']['prior_scope'] = '音频专题已有提示动作分支；本轮新增医院动画与保险链，不重复累计为首次整函数恢复。'
add('693320 693260 6932b0 693be0 63f080', '复用已审阅',
    '6060/6002/6003/6080/6000构造字段重新核验，填充字节不擅自归零。', '消费者及网络方向分别审阅。')
add('69b040 69b080 69b110', '局部语义已审阅',
    '扣款/收入按1000和5000倍scale取动作；住院天数<6取12，否则10。', '声音/角色资源实际播放未实机验证。')
add('693ce0', '局部语义已审阅', 'this+36累计amount；本组ECX=G+C5C，即G+C80。', '累计项完整生命周期与UI名称未追完。')
add('693220', '复用已审阅', '角色cash+deposit严格大于amount，本组在资金队列消费前比较。', '等额/不足的外部推进未闭合。')
add('7c0540', '局部语义已审阅', '两遍筛选有效且存款并列最高角色；8DWORD临时表、BYTE mask，最大初值0。', '外部role_count<=8约束及负存款来源未证。')
add('694390 63f4a0 63ef50 63ef80 63efb0', '局部语义已审阅',
    'R+1496单BYTE setter；R+1493/1494/1495/1497各自与signed -1比较。', 'A8709C初始化未知；除住院1494外不强命名所有状态。')
add('7f86a0 7f8710 7f9d20 7f8920 6943c0 63f650', '复用已审阅',
    '六字节库存槽ID/数量读取、8槽有效检查、点券增加、整槽扣除和存款getter。', '商品全生命周期复用商店资料；不重复计首次覆盖。')
add('67fa90 67d880 67da40 67d750', '复用已审阅',
    '6060资金、6002提示、6003窗口与6000动画消费及本组参数重新核验。', 'UI/资源完整绘制和网络闭环未在本篇覆盖。')
add('7fa050 7fa0a0 7f83f0 7f9f10 7f36f0 63f620', '复用已审阅',
    '现金存款加减、现金不足补存款、零值边界；R+244内16槽浮动金额环。', '环满覆盖与金融溢出未动态验证。')
add('63edf0 63ee90 63eed0 63e160 63e990', '部分分析',
    'G+65C模式子对象的四谓词OR与下一级字段调用已读。', '底层模式枚举和全部上游来源未本篇展开。')
add('63e410', '复用已审阅', '返回R+1464，407F将当前角色位置传给动画9。', '位置图坐标映射复用地图资料。')
add('627c20 7fea80 6940b0', '复用已审阅',
    '0x14C商品单例、指针字段构造及1128字节条目+60价格读取。', '全加载器和所有商品类型复用商店资料。')
add('7a5c30 694bc0', '复用已审阅',
    '按动画id创建/复用单一对象、启动虚调用与active去重；40字节槽+36默认时长。', '动画管理器生命周期复用角色与精灵动画。')
add('7a6a40 7aa350', '复用已审阅', '动画9分配56字节，构造写虚表A2C040。', '基类构造和分配失败处理不独立展开。')
add('631260', '局部语义已审阅',
    '动画9复制slot/tile/days，图(10,2,26)，x685/step16/state0，音效111。', '所有声音及绘图底层依赖未闭合。')
add('631460', '局部语义已审阅',
    '三阶段入院动画，抵达位置等待1000ms后写住院状态；退出屏幕返回1。', '帧门控底层及实际帧率未实机验证。')
add('631370', '局部语义已审阅',
    '结束补应用住院状态、停音效，调用7CCB90(slot,days-1)，不直接排6080。', '最终回合推进来源未闭合。')
add('7f7ff0', '部分分析',
    '住院状态应用：写R+1494天数、1493=-1、1496=0，先调用位置/角色清理链。', '交通/位置清理函数树未完整展开。')
add('7ccb90', '局部语义已审阅',
    '模式/库存1049/许可三条件，保险2500*参数；6003/6001/6007/6060/6061依次入队。', '6007/6061后续及异常天数未闭合；不是stage2发送器。')
add('63e230 63e210 63e0e0', '复用已审阅',
    'G角色数组与G+65C、G+C14子对象getter；医院调用ECX重新核验。', '子对象全部字段未本篇展开。')
add('7b6f60 7e17c0', '部分分析',
    'tile转换格坐标后按64/48比例计算镜头/屏幕坐标，医院起点定位已读。', '格坐标映射、镜头限制和绘图全树未闭合。')
add('63e7d0 63e1c0 63e5b0 63f940 64f710 64fa50 64fb10', '复用已审阅',
    '有效角色BYTE、角色名+112、队列游标、GmsvID、结构插入与G等待字段重新核验。', '队列全生命周期以基础对象专题为准；data指针非自动深复制。')
add('7192f0 719290', '复用已审阅',
    'UI30三DWORD分派、type0图索引与文本虚调用，关闭仅资源清理。', '文本控件所有权与图索引范围未闭合。')
add('63eca0', '部分分析', '保险模式许可是两个底层谓词OR，ECX=G+65C。', '完整模式定义复用股票/地图资料，本篇不猜枚举名。')
add('7f85c0', '部分分析',
    'ID优先查group0八槽；可选group1八槽要求附加BYTE0，输出slot/group。', 'group1启用谓词尚未完整展开。')
add('800a50', '部分分析',
    '检查ID>=0且<=上界、配置记录有效、类型0及许可谓词。', '许可谓词和资源上界初始化未完整展开。')
add('693420 6944a0 63f6e0', '局部语义已审阅',
    '保险后续构造6001/6007/6061及默认字段；首WORD由指令核验。', '记录完整消费者未在本篇闭合。')

# 清单按入口给出自身职责，不能让分组摘要看起来像每个函数都执行整条链。
individual = {
    '693320': '6060构造：写WORD6060，清BYTE+3..+6；其余字段由调用者补齐。',
    '693260': '6002构造：写WORD6002、BYTE+5=0、BYTE+6=1、DWORD+8=0。',
    '6932b0': '6003构造：写WORD6003、清BYTE+4..+6及DWORD+8/+12/+16/+20。',
    '693be0': '6080构造：写WORD6080及BYTE+3=-1；阶段+2由调用者写。',
    '63f080': '6000构造：写WORD6000，清DWORD+8/+12/+16；动画号和等待由调用者写。',
    '69b040': '扣款动作选择：amount<1000*scale取15，>=5000*scale取13，否则14。',
    '69b080': '收入动作选择：amount<1000*scale取18，>=5000*scale取16，否则17。',
    '69b110': '就医提示选择：days<6返回12，否则返回10。',
    '694390': '角色R+1496单BYTE setter；4072将A8709C低BYTE传入。',
    '63f4a0': '只比较signed BYTE[R+1493]!=-1并返回BOOL；不写状态。',
    '63ef50': '只比较signed BYTE[R+1494]!=-1并返回BOOL；不写状态。',
    '63ef80': '只比较signed BYTE[R+1495]!=-1并返回BOOL；不写状态。',
    '63efb0': '只比较signed BYTE[R+1497]!=-1并返回BOOL；不写状态。',
    '7f86a0': '按group0/1/2选择R+1520/+282/+330，取6*slot处signed WORD物品ID；非法group返回-1。',
    '7f8710': '按group0/1/2选择R+1522/+284/+332，取6*slot处signed WORD数量；非法group返回-1。',
    '7f9d20': '角色DWORD[R+1512]点券+=amount；flag非0时转R+244浮动金额环。',
    '7f8920': 'group0数量WORD减实参；signed<=0则数量0/ID=-1；本地角色刷新UI12。',
    '6943c0': 'unsigned slot<8且group0 signed WORD物品ID!=-1才返回true。',
    '63f650': '只返回DWORD[R+1508]存款。',
    '67fa90': '6060消费：按signed BYTE角色槽应用收入/支出、现金/存款；模式通过且扣后现金<=0时等待500。',
    '67d880': '6002消费：先角色状态映射，后条件UI9/声音/本地UI刷新；显示门控通过才应用等待。',
    '67da40': '6003消费：按显示/隐藏字节操作UI，传data指针，按等待字节写G计时；不读取+20长度。',
    '67d750': '6000消费：按signed WORD动画号启动对象；等待时取指定或配置时长再加100。',
    '7fa050': '角色现金R+1504+=amount；flag非0转R+244正向浮动提示。',
    '7fa0a0': '角色存款R+1508+=amount；flag非0转R+244正向浮动提示。',
    '7f83f0': '现金先减，负值由存款补；耗尽钳0并返回1；可先提交负向浮动提示。',
    '7f9f10': '存款减amount后负值钳0；flag非0转R+244负向浮动提示。',
    '7f36f0': '16槽浮动金额环追加金额/方向/偏移/tick，旧项偏移+=16，尾模16递增。',
    '63f620': '只返回DWORD[R+1504]现金；不是总财富getter。',
    '63edf0': '对同一模式对象依次调用63EE90/63EED0/63E160/63E990并OR，短路返回BOOL。',
    '63ee90': '读取模式对象DWORD+24并转629DF0谓词。',
    '63eed0': '模式对象DWORD+24经63EDD0成立且DWORD+108经629DF0成立才返回true。',
    '63e160': '读取模式对象DWORD+24并转IDA误名COleDocument::GetNextItem谓词；不是四谓词OR。',
    '63e990': '读取模式对象DWORD+24并转629E10谓词。',
    '627c20': '商品单例getter：A766E0空则分配0x14C并构造；尾块含构造异常operator delete清理。',
    '7fea80': '商品配置对象构造：清根指针、计数及多个缓存/数组指针；未加载商品。',
    '6940b0': '返回DWORD[*this+1128*id+60]商品价格；不检查id。',
    '7a5c30': '按动画id惰性创建并调启动虚函数，记录tick；active=0才加入列表；尾块清理构造异常分配。',
    '694bc0': '只返回动画管理器DWORD[this+40*id+36]默认时长。',
    '7a6a40': '动画9工厂：分配56字节并构造；尾块包含构造异常operator delete清理。',
    '7aa350': '动画9构造：调用基类构造后写虚表A2C040；派生状态由启动函数设置。',
    '63e230': '返回DWORD[G+0xE00+4*slot]角色指针。',
    '63e210': '返回G+0x65C模式/地图子对象地址。',
    '63e0e0': '返回G+0xC14镜头相关子对象地址。',
    '7b6f60': 'tile转换格坐标，按64/48中心点减两组视口半宽高，更新镜头坐标。',
    '7e17c0': 'tile转换格坐标，扣镜头偏移并加64/48，输出屏幕x/y。',
    '63e7d0': '只返回BYTE[G+0xE30+slot]参与有效标志；不是窗格IsAutoHideMode。',
    '63e1c0': '只返回R+112字符缓冲地址；406F作为角色名格式化。',
    '63e5b0': '以G+0x640队列为this调用63F940，返回当前游标。',
    '63f940': '只返回队列Q+12 DWORD游标；不是G+12等待时长。',
    '64f710': '比较WORD消息身份与G+83844；不同弹Error GmsvID，再返回比较值。',
    '64fa50': '复制调用者指定结构字节到局部记录，交队列插入器；返回新记录后一物理槽。',
    '64fb10': '写DWORD[G+12]=duration、DWORD[G+16]=GetTickCount，控制基础队列暂停。',
    '7192f0': 'UI30读取type/index/text三DWORD，选新闻图并转文本控件虚表+144；不排stage2。',
    '719290': 'UI30关闭窗口并清当前图像资源；不处理新闻入参或排stage2。',
    '693420': '6001构造：写WORD6001、BYTE+4/+5=0、DWORD+8=0；声音号由调用者写。',
    '6944a0': '6007构造：写WORD6007、BYTE+5=0、DWORD+8=0；不能归为6002。',
    '63f6e0': '6061构造：写WORD6061、BYTE+6=1、BYTE+7/+8/+9=0；库存目标由调用者补。',
}
for address, conclusion in individual.items():
    notes[hex(int(address,16))]['conclusion'] = conclusion

functions = {}
bridges = json.loads((BASE / 'bridges_reused.json').read_text(encoding='utf-8'))['functions']
for f in bridges:
    add(f['va'], '桥接复用', '分派桥接只把消息指针及this转给handler；注册跳板另核。', '桥接自身不携带网络长度/方向证明。')
for source in SOURCES:
    for f in json.loads((BASE / source).read_text(encoding='utf-8'))['functions']:
        functions.setdefault(f['va'], dict(function=f, sources=[]))['sources'].append(source)
assert set(functions) == set(notes), (set(functions)-set(notes), set(notes)-set(functions))
rows = []
for va, item in sorted(functions.items(), key=lambda pair:int(pair[0],16)):
    row = dict(va=va, name_from_idb=item['function']['name'], evidence=['证据/'+s for s in item['sources']],
               full_dependency_closure=False, **notes[va])
    rows.append(row)
counts = Counter(r['review_status'] for r in rows)
(BASE / 'function_review.json').write_text(json.dumps(dict(scope='本专题局部静态审阅；非全依赖闭环或实机验证',
    sources=SOURCES, counts=dict(counts), functions=rows), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
lines = ['// ============================================================================', '// 逐函数审阅与边界',
         '// ============================================================================',
         '// 所有项保留未知边界；桥接复用不计新增业务语义。',
         '// '+ '；'.join(f'{k}={v}' for k,v in counts.items()), '//']
for row in rows:
    lines += [f"// {row['va']} [{row['review_status']}] {row['conclusion']}",
              '//   未闭合：'+row['unknown'], '//   原证：'+', '.join(row['evidence'])]
(BASE.parent / '05_逐函数审阅与边界.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
print(json.dumps(dict(unique_functions=len(rows), counts=dict(counts)), ensure_ascii=True))
