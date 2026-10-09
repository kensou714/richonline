"""逐窗口人工结论；明确区分未声明窗口和复用声明函数。"""
from pathlib import Path
import json

BASE=Path(__file__).resolve().parent
windows=[
    dict(va='0x8e14f0',end_va='0x8e1542',status='局部语义已审阅',kind='未声明代码窗口',
         conclusion='thiscall一参数；数量变化先删旧数组，再按正count分配4*count；不清槽；同数量保留；count原值保存。',
         unknown='两入口跳板无入xref，业务可达性未确认；分配失败和溢出未动态验证。',
         evidence=['证据/未声明窗口与全段候选.json']),
    dict(va='0x8e15f0',end_va='0x8e160f',status='局部语义已审阅',kind='未声明代码窗口',
         conclusion='thiscall(value,index)，retn8；仅signed index>count拒绝；写links[index-1]，一基无下界/空指针门。',
         unknown='实际注册调用未发现，异常index路径未动态验证；不能定性为已复现漏洞。',
         evidence=['证据/未声明窗口与全段候选.json'])]
facts={
    '0x8e0af0':('关联数组和数量初始化0。','其它构造资源与分配失败路径未全部闭合'),
    '0x8e0ed0':('释放关联数组本体并置指针0，不遍历销毁所指对象，不扫描其它控件反向数组。','完整派生所有权和外部解绑动作未闭合'),
    '0x8e2d80':('本体未直接复制+424/+428，不调用两绑定接口；扩展槽+420与关联数组不同。','其它文本/样式依赖及上层克隆是否补绑定未闭合'),
    '0x8e31b0':('同层遍历中按关联数组指针相等首命中移动；传当前对象为直接返向排除项。','长环、地址复用和分配异常运行行为未验证'),
    '0x8e3340':('垂直消费与水平对称；不直接解引用数组所存目标指针，只与同层节点比较。','长环、地址复用和全部调用方前置条件未闭合')}
functions=[dict(va=va,status='复用已审阅',review_status='复用已审阅',conclusion=c,unknown=u,evidence=['证据/构造释放复制与移动复用.json'],full_dependency_closure=False) for va,(c,u) in facts.items()]
for row in windows:
    row['review_status']=row['status']
    row['full_dependency_closure']=False
review=dict(scope='2未声明窗口单列，不计入声明函数覆盖；5依赖函数复用',code_windows=windows,functions=functions)
(BASE/'function_review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines=['// ============================================================================','// 审阅清单 / 2未声明窗口局部审阅 / 5声明依赖复用','// ============================================================================']
for row in windows+functions:
    lines+=['// '+row['va'][2:].upper()+' / '+row.get('kind','声明函数')+' / '+row['status'],'//   结论：'+row['conclusion'],'//   未闭合：'+row['unknown'],'//   证据：'+','.join(row['evidence'])]
(BASE/'04_逐窗口与函数审阅清单.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('已生成：2个未声明窗口，5个复用声明函数。')
