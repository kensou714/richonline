"""由已核对的静态记录生成逐槽导航及审阅索引；不将批量导出计为语义完成。"""
import json
import re
from pathlib import Path

p = Path(__file__).resolve().parent
d = json.loads((p / 'ida_ui_batch2_raw.json').read_text(encoding='utf8'))
v = json.loads((p / 'ui_batch2_verification.json').read_text(encoding='utf8'))
names = ['plane', 'label', 'title', 'button', 'edit', 'radiobutton', 'checkbox',
         'groupbox', 'scrollbar', 'progress', 'listbox', 'slider', 'tree']
sizes = [0x240,0x250,0x250,0x268,0x384,0x268,0x264,0x250,0x490,0x268,0x340,0x32c,0x364]

def save_text(name, lines):
    (p / name).write_text('\n'.join('// ' + line if line else '//' for line in lines) + '\n', encoding='utf8')

lines = ['====================================================================',
         '窗口工厂逐槽导航：160个槽，124对工厂，117条配置',
         '====================================================================',
         '表中的名称来自当前Intf.kpd的file，不把文件名自动翻译为已恢复产品语义。',
         '创建/释放地址均为实现；跳板、构造器及完整资源字段见ui_batch2_verification.json。',
         '本轮仅对同型工厂做结构核对；除91/94外的业务方法不计为深入分析完成。',
         '版本边界及局部字节一致性见控件类型与双资料窗口.txt。', '']
for x in v['slots']:
    f = x['factory']; r = x['resource']
    identity = r['file'] if r else '当前Intf无配置'
    if f:
        lines.append(f"{x['slot']:03d}  {identity:24}  创建{f['create']['target']}  释放{f['destroy']['target']}  大小0x{f['create']['allocation_size']:X}")
    else:
        lines.append(f"{x['slot']:03d}  {identity:24}  0x6E6080未绑定工厂")
lines += ['', '配置有而工厂无：0项。工厂有而当前配置无：135..141，共7项。',
          '36个未绑定槽不代表可直接复用：仍需审计其他硬编码ID、默认对象与销毁调用。',
          '不能只新增file就扩展产品功能；必须有工厂、事件回调和服务端数据消费契约。']
save_text('窗口工厂逐槽导航.txt', lines)

lines = ['====================================================================', '13类控件：虚表、属性解析器和直接字符串引用',
         '====================================================================', '地址是IDB VA；字节比对见ui_batch2_verification.json。',
         '下列字段为解析器的直接字符串引用；继承层公共字段需要沿父解析器合并。',
         '仅确定配置入口与已列偏移，未恢复每个虚方法。完整虚表前缀在原始JSON。', '']
for c, name, size in zip(d['controls'], names, sizes):
    lines += [f"类型{c['type']:02d} {name}；分配0x{size:X}；构造{c['constructor']}；虚表{c['vtable']}；+124解析器{c['parser']}。"]
    texts = list(dict.fromkeys(x['text'] for x in c['direct_string_references']))
    for start in range(0,len(texts),5): lines.append('  '+', '.join(texts[start:start+5]))
    lines.append('')
save_text('控件配置键目录.txt', lines)

review = {}
for address in d['functions']:
    review[address] = {'address':address, 'status':'导出待审阅', 'conclusion':'保留完整反编译和逐指令证据；尚无独立语义结论。',
                       'evidence_path':f'ida_ui_batch2_raw.json#/functions/{address}',
                       'unknowns':['完整调用契约、异常路径及运行时验证'],
                       'version_check':'ui_batch2_verification.json#/checks'}
for slot in v['slots']:
    if not slot['factory']: continue
    for kind in ['create','destroy']:
        x = slot['factory'][kind]; address = x['target']; text='\n'.join(d['functions'][address]['pseudocode'])
        if kind == 'create':
            passed = 'operator new' in text and 'else\n    return 0;' in text and bool(x.get('constructor'))
            conclusion=f"窗口槽{slot['slot']}工厂分配0x{x['allocation_size']:X}，空指针返回0，成功转构造器{x.get('constructor')}。"
        else:
            passed = '*(_DWORD *)(a1 + 4) = 0;' in text and 'a1: 1' in text
            conclusion=f"窗口槽{slot['slot']}释放包装器：检查记录+4，调用删除包装器后将记录+4清零。"
        review[address].update(status='同型模式核对' if passed else '导出待审阅', conclusion=conclusion,
                               unknowns=['派生对象业务/全部虚方法未逐项恢复；此状态不计深度完成'])
for c, name in zip(d['controls'], names):
    review[c['constructor']].update(status='静态局部审阅',conclusion=f'{name}构造链、虚表及本类默认字段已核对；分配大小由0x8E24D0提供。',unknowns=['所有默认字段消费者及析构'])
    review[c['parser']].update(status='静态局部审阅',conclusion=f'{name}属性读取路径与继承解析链已核对；专属键见控件配置键目录。',unknowns=['超长文本、非法数字、全部setter内部及实机表现'])
judgments = {
 '0x6e6080':'两张160项工厂表；写入124对，配置联读确认117条当前资源。',
 '0x8e24d0':'13种控件分配大小与构造器配对。',
 '0x8e06f0':'13控件类型和通用枚举共用转换；回调存在时优先扩展分支。',
 '0x6fc390':'窗口91包装对象构造，虚表A27940；内部成员+116构造。',
 '0x6fc4c0':'窗口94包装对象构造，虚表A27BB0；内部成员+208构造。',
 '0x7495d0':'91首次初始化绑定控件ID回调，初始化每页6项和图片资源。',
 '0x749a20':'91每次打开复位分页，填充500..550六项，隐藏其余至590。',
 '0x749d60':'91数据通知：参数首DWORD掩码1刷新个人属性，2刷新道具列表分页；此指针非原始网络包的已证类型。',
 '0x74af30':'91通知参数的前两字节控制60000/60001侧栏显示及位置。',
 '0x74d4d0':'94初始化绑定ID1/2/25事件5/10及ID10事件19。',
 '0x74d5e0':'94数据通知复制2个DWORD到+72/+76，调用虚表+164并清+748；汇编证实thiscall/retn4。',
 '0x6e2770':'94虚表+164经跳板调用此函数；请求打开槽21。'
}
for address, conclusion in judgments.items():
    review[address].update(status='静态局部审阅',conclusion=conclusion,unknowns=['业务下游完整契约与实机响应仍需网络/状态专题联合审阅'])
(p / '函数审阅清单.json').write_text(json.dumps({'scope':'本批地址；状态不等于全函数无未知项',
 'idb_input_sha256':d['idb_input_sha256'],'disk_sha256':v['disk_sha256'],'functions':list(review.values())},ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print('generated',len(review),'function records')
