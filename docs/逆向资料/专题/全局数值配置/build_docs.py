"""从已保存原证生成配置索引表和逐函数审阅清单；不访问IDA、不覆盖原证。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
resource = json.loads((HERE / '证据/resource.json').read_text(encoding='utf-8'))
refs = json.loads((HERE / '证据/references.json').read_text(encoding='utf-8'))
functions = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
comments = {item['index']: (item.get('leading_comments') or ['未提供资源注释'])[0]
            for item in resource['items']}
uses = {}
for ref in refs['references']:
    uses.setdefault(ref['index'], []).append(ref)

known = {
    0: '读取低字节装入角色/动态效果载荷；40B8定时炸弹附身步数。',
    1: '初始化玩家状态中的窄字节字段；完整业务含义未闭环。',
    2: '读入效果/住院相关参数；本批仅确认DWORD读取。',
    3: '与计数比较并在不足时覆盖；有下限/补齐语义。',
    4: '读入事件或住院参数；完整消费者需结合上层事件。',
    5: '633B90将其写入伤害/住院记录，值为3。',
    6: '多个事件记录使用；当前资源值3，未统一命名为某一事件。',
    7: '传入角色动作/新闻原地停留参数；40BA复用。',
    8: '乌龟步计数，多个效果路径加1后传给角色。',
    9: '梦游计数写入局部载荷低字节；40B8专题维护完整入口。',
    10: '陷害/嫁祸流程及40C2动画载荷使用；值3。',
    11: '694E10写入关系计数低字节；40BB本次仅确认解除关系分支。',
    12: '读入影响天数并传给角色/地图效果；精确事件需上层判定。',
    13: '读入冰冻相关天数；本批未恢复完整事件入口。',
    14: '文本/载荷中作为点券金额读取；未证明服务器扣款规则。',
    15: '作为PK天使/恶魔伤害值读取；未证明统一扣血路径。',
    16: '新闻/股市暂停天数传入字符串或状态结构。',
    17: '本次A87080窗口未检出直接xref；不能据此断言无人使用。',
    18: '一步卡/六步卡天数，多个角色效果路径加1后传入。',
    19: '地雷爆炸回合数写入地雷/角色消息载荷低字节。',
    20: '6327B0和7CC490的循环计数与其作signed比较；当前值2。',
    21: '633B90及其他爆炸范围路径调整地图坐标边界。',
    22: '核子飞弹范围路径调整坐标边界；未混同普通飞弹。',
    23: '安全核弹范围路径调整坐标边界。',
    24: '天使恶魔影响范围路径调整坐标边界。',
    25: '毒气影响长度参与循环上界；未证明所有毒气效果入口。',
    26: '火焰影响范围路径调整地图坐标。',
    27: '火焰影响回合数写入消息/动画载荷低字节。',
    28: '超级地雷住院天数参与下限补齐；资源值7。',
    29: '本次A87080窗口未检出直接xref；不能据此断言无人使用。',
    30: '冬眠天数在角色效果分支作为参数传入。',
    31: '碉堡扣血值写入伤害/状态记录；完整扣血消费者未展开。',
    32: '复活所需点券门槛/比较值；63ACC0按余额小于当前值400分支，不是余额上限。',
    33: '医院每点券换血量参与乘法并受最大数量限制。',
    34: '医院买血最大数量参与裁剪，不能只改换算比例。',
    35: '监狱扣血值写入状态/消息记录。',
    36: 'PK玩法监狱天数读取到消息/状态结构。',
    37: '7F7E30将角色附身天数与上限作signed比较，超出时窄写上限。',
}

lines = ['// ============================================================================',
         '// GValue索引、资源值与当前直接消费者',
         '// ============================================================================',
         '// 以下值来自Data/GValue.kpd严格GBK解码；地址是A87080+4*indx的运行时DWORD槽。',
         '// 引用数量是IDA当前直接xref计数，不是调用次数，也不代表全部间接消费者。',
         '// “未检出直接xref”只说明本次扫描窗口没有直接地址引用，不能证明无人使用。',
         '//']
for item in resource['items']:
    index = item['index']
    label = item['leading_comments'][-1] if item['leading_comments'] else '未提供资源注释'
    lines.extend([f"// [{index:02d}] {item['va'].upper()} / 当前值 {item['value']} / {label}",
                  '//   局部用途：' + known[index]])
    for ref in uses.get(index, []):
        lines.append(f"//   {ref['function']} @ {ref['site']} | {ref['text']}")
    if index in (17, 29):
        lines.append('//   本次没有直接引用；完整间接使用与服务器语义仍未知。')
    lines.append('//')
lines += ['//', '// 类型与符号观察：装载统一写DWORD；消费者可能mov/movzx取低字节，也可能作signed比较或idiv。',
          '// 因此不能把资源中的“天数”“长度”“金额”“半边长”互换，也不能统一加减一。',
          '// 具体静态统计：索引17、29无本次A87080..A8747F直接xref。',
          '// 其他索引至少有一处直接xref，但大型函数中若只导出汇编，业务语义仍处于局部状态。']
(HERE / '02_索引值与消费者概览.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')

review = []
for function in functions['functions']:
    va = function['va']
    indices = sorted(set(ref['index'] for ref in refs['references'] if ref['function'] == va))
    if va == '0x7b9ad0':
        status = '已分析'
        conclusion = ('读取GValue.kpd的ITEM indx/value，经atoi写A87080+4*indx；本函数不预清表，'
                      '文件打不开仅清临时对象、不写表；正常重复有效索引按遍历顺序覆盖。'
                      '未见索引界限检查，亦未检查字段查找及展开返回值；读取字段的长度检查发生于复制之后。')
        unknown = '表合法容量、索引的外围保证、坏字段实际后果及初始化/再次调用的运行入口；不据此认定存在热重载。'
    elif indices:
        status = '局部已分析'
        points = [ref['site'] + ': ' + ref['text'] for ref in refs['references'] if ref['function'] == va]
        conclusion = '已核对直接配置使用点；' + '；'.join(points)
        unknown = '上层入口、完整业务名称、间接读者和运行时边界需结合调用链。'
    else:
        status = '仅导出'
        conclusion = '作为装载依赖或消费者函数保存完整主块/尾块原证。'
        unknown = '本函数与GValue的间接关系及业务用途未在本批闭环。'
    review.append({'va': va, 'status': status, 'conclusion': conclusion, 'unknown': unknown,
                   'evidence': '证据/functions.json/functions/' + va})
(HERE / '函数审阅清单.json').write_text(json.dumps({
    'scope': 'GValue专题函数；机器字节和完整函数块已验证，语义按直接引用局部标注。',
    'functions': review}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    print(json.dumps({'functions': len(review), 'indices': len(resource['items'])}))
