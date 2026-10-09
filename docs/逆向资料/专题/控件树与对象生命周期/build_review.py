"""人工逐函数结论；不以导出或复用来源自动提高语义等级。"""
from pathlib import Path
from collections import Counter
import json

BASE = Path(__file__).resolve().parent
RAW = ['创建与链表.json', '几何传播.json', '状态与销毁.json', '名称调用复用.json']
notes = {}
def note(va, status, conclusion, unknown='派生覆盖、动态重入和全部调用方契约未闭合'):
    notes[hex(va)] = (status, conclusion, unknown)

note(0x8e22c0, '局部语义已审阅', 'U+80七参cdecl自定义工厂失败回退；新根插顶层头；ECX=新C刷新坐标。', '自定义工厂初始化契约和外部调用方未全部闭合')
note(0x8e23f0, '局部语义已审阅', '第七工厂参数父C；写父字段并插首子；ECX=新C刷新坐标。', '全部派生构造/父子关系重入未闭合')
note(0x8e24d0, '部分分析', 'type0..12的分配大小和构造跳板；越界/分配失败0。', '13类派生构造器与完整资源所有权不在本专题展开')
note(0x8e2ac0, '局部语义已审阅', '名称忽略大小写，当前/子/兄弟深度优先首命中；不筛状态。', '循环/重复名称与无效名称指针动态行为未验证')
note(0x8e2b50, '局部语义已审阅', '空字符串调试并返回0；a3匹配却返this；失败只查首子；15处已知调用a3均0。', '非零a3实际外部触发未找到；重名归属判断未动态验证')
note(0x8e2c10, '局部语义已审阅', 'ID查找当前/子/兄弟，首个命中；失败0，无可见启用门。', 'ID唯一性和异常链动态行为未验证')
note(0x8e2ca0, '局部语义已审阅', '从父首子/根头找前驱；this不在非空链仍返尾。', '链成员前置条件是否在全部调用方保证未闭合')
note(0x8e2d10, '局部语义已审阅', '按前驱结果修兄弟或头；不清当前三链字段，不释放。', '非法成员调用的实际可达性未闭合')
note(0x8e3750, '局部语义已审阅', '负层归0；摘下同链再按降序插入，同层放旧节点前。', '所有调用方和重入导致的链状态未验证')
note(0x8e30d0, '局部语义已审阅', '自身绝对=相对+父绝对；再回写相对；清四布局字段，无递归。', '四缓存完整用途和溢出动态行为未验证')
note(0x8e31b0, '局部语义已审阅', '水平夹边，虚表+8通知；按关联数组移动同层对象；刷新子坐标。', '关联数组构造和任意关联环缺少独立闭合')
note(0x8e3340, '局部语义已审阅', '垂直与水平对称；使用+348/+356/客户高；按关联差值递归。', '关联数组构造和任意关联环缺少独立闭合')
note(0x8e34d0, '局部语义已审阅', '宽请求门、父边界截短、子越界先移再缩；最后虚表+12。', '负最终尺寸、派生通知和样式门动态效果未验证')
note(0x8e3610, '局部语义已审阅', '高度对称；<=0与样式5/1拒绝，截短后不二次限正。', '负最终尺寸、派生通知和样式门动态效果未验证')
note(0x8e38a0, '局部语义已审阅', '保存入口ECX；自身刷新后先兄弟递归，再首子循环。', '循环链和入口ECX上下文所有调用方未闭合')
note(0x8e39d0, '局部语义已审阅', '通过节点虚表+0先兄弟后首子；visible且样式5按自身enabled刷0/3。', '派生+0覆盖及完整样式枚举未展开')
note(0x8e3a70, '局部语义已审阅', '仅enabled改变时动作；先写自身，启用刷子样式和层序，禁用按名称清输入归属。', '特殊模式、重名和全部派生通知的动态效果未验证')
note(0x8e3eb0, '局部语义已审阅', 'visible通知在写状态前；显示刷子样式/层序；隐藏按名称清引用；最后重算悬停。', '特殊模式、重名、回调重入与派生通知动态效果未验证')
note(0x8e0af0, '部分分析', '父/首子/兄弟零、局部状态1、几何/层序/关联数组初值；27回调清零复用。', '文本、样式及全部扩展资源初始化依赖未闭合')
note(0x8e0ed0, '部分分析', '递归清首子；清引擎引用并摘链；释放多资源后析构通知；非空U+20724直接清。', '完整资源所有权、派生析构和直接删根头保存兄弟契约未闭合')
note(0x8e3850, '复用已审阅', '非空this基础析构后operator delete；基础虚表+120。')
note(0x8ea680, '局部语义已审阅', '先递归首子，再重读兄弟递归，最后虚表+120；销毁包含后继链。', '全部派生销毁覆盖和重入未闭合')
note(0x8e3830, '复用已审阅', '基础位置通知+8为空函数。')
note(0x8ea240, '复用已审阅', '基础尺寸通知+12清四布局字段并返0。')
note(0x8e48f0, '复用已审阅', '兄弟先绘制；本节点visible门控制自身及首子，层序后插同层显示靠前。', '全部绘制回调与派生渲染行为复用控件回调专题')
note(0x8e7e40, '复用已审阅', '兄弟先命中；hidden常规模式跳本树；enabled/层掩码控制首子访问。', '图像透明、缩放和全部输入分派复用输入专题')
note(0x8e8800, '复用已审阅', '名称查找610D96调用传a3=0；鼠标引用归属复用输入专题。', '其它鼠标流程本专题未重复闭合')

functions, sources = {}, {}
for name in RAW:
    raw = json.loads((BASE / '证据' / name).read_text(encoding='utf-8'))
    for f in raw['functions']:
        functions[f['va']] = f
        sources.setdefault(f['va'], []).append('证据/' + name)
assert set(functions) == set(notes), set(functions) ^ set(notes)
rows = []
for va in sorted(functions, key=lambda x: int(x, 16)):
    status, conclusion, unknown = notes[va]
    rows.append(dict(va=va, status=status, review_status=status, conclusion=conclusion,
                     unknown=unknown, evidence=sources[va], full_dependency_closure=False))
(BASE / 'function_review.json').write_text(json.dumps(dict(scope='控件树局部静态语义审阅', functions=rows), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
counts = dict(Counter(r['status'] for r in rows))
lines = ['// ============================================================================', '// 逐函数语义状态 / ' + str(counts), '// ============================================================================']
for r in rows:
    lines += ['// ' + r['va'][2:].upper() + ' / ' + r['status'], '//   结论：' + r['conclusion'], '//   未闭合：' + r['unknown'], '//   证据：' + ', '.join(r['evidence'])]
(BASE / '05_逐函数审阅清单.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(dict(functions=len(rows), statuses=counts), ensure_ascii=False))
