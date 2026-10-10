"""生成逐函数状态；复用与部分分析分别保留。"""
from pathlib import Path
from collections import Counter
import json
BASE=Path(__file__).resolve().parent
CONCLUSIONS={
0x8E1C40:'写P+40*i+32颜色槽，无边界保护',
0x8E1C70:'更新图像ID前通知旧资源；随后按控件门刷新',
0x8E1D10:'仅type5更新第二参数，通知与刷新门同类',
0x8E1DB0:'不区分大小写相等沿用旧串；不等先通知释放，再复制新串',
0x8E1EF0:'x87写P+40*i+40 float槽',0x8E1F20:'x87写P+40*i+44 float槽',
0x8E1F50:'x87写P+40*i+48 float槽',0x8E1F80:'x87写P+40*i+52 float槽',
0x8E1FB0:'type5和参数1时取得/沿用尺寸；内嵌P镜像活动宽高；所有出口保存参数',
0x8E21D0:'写P+8，type非5时强制0',
0x8E2200:'写当前索引P+12并保留ECX owner委托尺寸刷新',
0x8E2230:'写P.type并保留ECX owner按旧P+4刷新',
0x8E1930:'逐字段按0/2/1/3复制四状态，路径通过setter，期间可能触发刷新',
0x6E2E60:'复用15项注册器，核对尺寸/替换通知三回调来源',
0x8E86A0:'非零参数写U+16',0x8E86C0:'非零参数写U+20',0x8E8620:'非零参数写U+44',
0x6E4D00:'按ID查询宽高写出；无条件AL1，不检验宽高是否-1',
0x6E4D40:'路径映射ID再查宽高；无条件AL1',
0x6E51D0:'条件调用owner虚表+132，按返回路径或输出ID清单图像槽',
}
PARTIAL={0x8E1DB0:'异常分配、字符串别名与最终析构契约未闭合',
0x8E1930:'字段复制顺序已核；中途回调重入、源目标别名与全部副作用未闭合',
0x6E4D00:'复用宽高管理器契约，未重审完整按需加载路径',
0x6E4D40:'路径到索引及完整按需加载依赖未重审',
0x6E51D0:'关联对象门及owner虚表动态目标未闭合'}
REUSED={0x8E1C40:'界面数值与颜色解析契约',0x6E2E60:'提示文本生命周期',
0x8E86A0:'提示文本生命周期',0x8E86C0:'提示文本生命周期',0x8E8620:'提示文本生命周期'}
rows=[]
for name in ['functions_raw.json','callbacks_raw.json']:
    for f in json.loads((BASE/name).read_text('utf-8'))['functions']:
        va=int(f['va'],16)
        status='部分分析' if va in PARTIAL else '局部语义已审阅'
        rows.append(dict(va=f['va'],name=f['name'],status=status,review_status=status,
                         conclusion=CONCLUSIONS[va],unknown=PARTIAL.get(va,'合法输入、全局生命周期与外部回调行为未完全闭合'),
                         full_dependency_closure=False,reviewed_chunks=f['declared_chunks'] if status!='部分分析' else [],
                         evidence=[name],reused_from=REUSED.get(va),
                         scope='逐声明块汇编核对；未把自动函数名和导出数量当完整业务恢复'))
assert len(rows)==len(CONCLUSIONS)==20
result=dict(counts=dict(Counter(r['status'] for r in rows)),reused_count=len(REUSED),functions=rows)
(BASE/'function_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
print(result['counts'])
