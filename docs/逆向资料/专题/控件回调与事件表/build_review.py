"""由人工逐函数结论生成覆盖记录，不按目录自动升级语义状态。"""
from pathlib import Path
from collections import Counter
import json

BASE = Path(__file__).resolve().parent
RAW = ['注册与生命周期.json', '基础消费者.json', '输入复用.json', '清理与复制依赖.json', '游戏界面桥接.json']
notes = {}
def note(va, status, conclusion, unknown='完整动态路径、派生覆盖与实机行为未验证'):
    notes[hex(va)] = (status, conclusion, unknown)
note(0x8e9c30, '局部语义已审阅', '单参数回调17分支；event4..9/15..25映射；无效号弹窗，不写字段。')
note(0x8e9e00, '局部语义已审阅', '双参数回调10分支；event0..3/10..14/26映射；返回临时值非成功布尔。')
note(0x8e0af0, '部分分析', '基础虚表与27回调清零、时序默认值；清零后调用event17。', '其它文本/样式构造依赖未逐项闭合')
note(0x8e0ed0, '部分分析', '解除子链/引擎引用并释放多类资源，最后event18；限制对象非空即清零。', '全部资源所有权和回调重入未闭合')
note(0x8e2d80, '部分分析', '逐项复制26个回调，遗漏+516滚轮；扩展槽原值浅拷贝。', '完整克隆调用方与扩展资源所有权未闭合')
note(0x8e3eb0, '部分分析', '显示/隐藏前事件16/15，最后写visible并重算命中，隐藏清输入引用。', '子控件名字查找与特殊模式全部行为未闭合')
note(0x8e3a70, '复用已审阅', 'enabled变化清相关输入引用并刷新样式/命中；不以本函数替代visible设置。')
note(0x8e48f0, '局部语义已审阅', '后继先绘制；可见门后event19、自身draw、悬停及按住重复、event20，转首子。')
note(0x8eb410, '部分分析', '限+1132值、更新内样式，父+128(value,61,this)，最后自身+32值通知。', '完整派生对象构造与全部调用方尚未闭合')
note(0x902b50, '部分分析', '限+772值到764/768边界，条件调用U+48(index,this)，最后自身+32。', '派生对象完整配置/类型与后续资源动作尚未闭合')
note(0x7045a0, '部分分析', '只审控件2、7/8、13/14等事件注册；601E5E自动库名不可信。', '大函数其它初始化和业务回调出口未闭合')
note(0x8e3830, '局部语义已审阅', '基础虚表+8为空函数。')
note(0x8ea240, '局部语义已审阅', '基础+12清C+28/+32/+36/+40并返回0。')
note(0x8e46e0, '部分分析', '自身绘制按visible和样式调用引擎矩形/图片/文字回调。', '渲染参数与图像资源所有权未展开')
note(0x8ea680, '局部语义已审阅', '递归首子与后继链，然后虚表+120销毁当前对象。')
note(0x8e3850, '局部语义已审阅', '非空this先调用基础析构8E0ED0，再operator delete。')
note(0x8e2d10, '局部语义已审阅', '找到前兄弟则连其+408，否则改父+404或U顶层链。')
note(0x8e15b0, '局部语义已审阅', '扩展索引小于引擎计数且槽数组非空时写DWORD；未检查负索引。')
note(0x64f060, '局部语义已审阅', 'UI管理器槽数组this+68，每项132字节，返回slot+4界面实例。')
for va, offset, count in [(0x6eeb30,144,1),(0x6ee900,100,1),(0x6ee9a0,112,1),
                          (0x6ee9f0,116,2),(0x6eea40,124,2),(0x6ee950,104,1)]:
    note(va, '局部语义已审阅', f'cdecl桥取UI0实例，用该实例为ECX调用虚表+{offset}，转交{count}个原参数；没有对象空值门。')
for va, text in {
 0x8e8a10:'键鼠消息分派和重复计时，复用输入与快捷键专题，当前chunks重新导出。',
 0x8e8800:'鼠标命中切换、进入离开与拖动，复用输入与快捷键专题。',
 0x8e7e40:'按层掩码/可见性/矩形/图像测试寻找命中，复用输入专题。',
 0x8ea080:'焦点遍历同序快速分支不查visible/enabled；其余分支检查，通知新旧焦点。',
 0x8ea570:'显式聚焦检查order非零并发送新旧通知；与鼠标聚焦门控不同。'
}.items():
    note(va, '复用已审阅', text)
events = json.loads((BASE/'证据/事件映射与数据.json').read_text(encoding='utf-8'))['events']
details = {
 0:'左键时处理激活、焦点、相对坐标与层序；enabled/visible或模式1后回调。',
 1:'enabled/visible或模式1；左键清相对坐标，再调用释放回调。',
 2:'enabled且visible才调用按住重复回调；上游8E48F0负责时序。',
 3:'enabled且visible才调用双击回调。',
 4:'仅visible门，无enabled门。', 5:'enabled且visible门。',
 6:'先清U+20712，无本地enabled/visible门；空回调走默认。',
 7:'disabled/hidden或C+388=0才走自定义钩子；否则内置拖动，保留0x1F40掩码。',
 8:'无enabled/visible门，空回调返回1。', 9:'enabled/visible门；由绘制命中检查调用。',
 10:'enabled/visible门；同控件按下释放条件由消息层决定。',
 11:'enabled/visible门；Tab先切焦点，之后仍以原this调用注册钩子。',
 12:'enabled/visible门，转交VK。',13:'enabled/visible门，转交重复VK。',
 14:'enabled/visible门，转交字符值。',
 15:'只读+460非空则cdecl(C)；状态转换语义来自8E3EB0。',
 16:'只读+464非空则cdecl(C)；显示前语义来自8E3EB0。',
 17:'只读+468非空则cdecl(C)；基础构造已清0，正常此调用为空。',
 18:'只读+472非空则cdecl(C)；8E0ED0资源清理后直调。',
 21:'只读+484非空则cdecl(C)；值变化含义由两个派生调用证明。',
 22:'只读+496非空则cdecl(C)，焦点切入来自上游调用。',
 23:'只读+500非空则cdecl(C)，焦点切出来自上游调用。',
 24:'只读+488非空则cdecl(C)，鼠标激活来自上游调用。',
 25:'只读+492非空则cdecl(C)，鼠标失活来自上游调用。',
 26:'enabled/visible门；转交滚轮方向10/11。'
}
for row in events:
    if row['event'] in (19, 20):
        continue
    note(int(row['consumer'], 16), '局部语义已审阅',
         f"event{row['event']} / C+{row['field']} / {row['callback_arguments']}参数cdecl；" + details[row['event']])
functions, sources = {}, {}
for name in RAW:
    raw = json.loads((BASE/'证据'/name).read_text(encoding='utf-8'))
    for f in raw['functions']:
        functions[f['va']] = f
        sources.setdefault(f['va'], []).append('证据/'+name)
assert set(functions) == set(notes), sorted(set(functions) ^ set(notes))
rows=[]
for va, f in sorted(functions.items(), key=lambda x: int(x[0], 16)):
    status, conclusion, unknown = notes[va]
    rows.append(dict(va=va,name_from_idb=f['name'],review_status=status,conclusion=conclusion,
                     unknown=unknown,note=conclusion,evidence=sources[va],full_dependency_closure=False))
(BASE/'function_review.json').write_text(json.dumps(dict(scope='控件回调局部静态审阅；非全部派生与动态闭环',functions=rows),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
counts=Counter(r['review_status'] for r in rows)
lines=['// ============================================================================','// 逐函数覆盖 / 全部保留外部依赖边界','// '+str(dict(counts)),'// ============================================================================']
lines += ['// '+r['va'][2:].upper()+' / '+r['review_status']+' / '+r['conclusion'] for r in rows]
(BASE/'04_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps(dict(unique_functions=len(rows),statuses=dict(counts)),ensure_ascii=False))
