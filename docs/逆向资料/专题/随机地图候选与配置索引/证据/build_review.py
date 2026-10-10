"""从逐函数审阅结论生成索引；不把自动导出状态升格成语义完成。"""
from pathlib import Path
from collections import Counter
import json

BASE=Path(__file__).resolve().parent
CONCLUSIONS={
    0x629DD0:'等于0谓词',0x629DF0:'等于1谓词',0x629E10:'等于4谓词',
    0x6A9D50:'连续map键加载九个目标容器；未清空目标，出口不构成bool成功',
    0x6AA450:'从合法起点顺序环筛选，返回借用条目或0',
    0x6AA530:'每次计时重种子，按模式尺寸选组，以rand余数选择初始位置',
    0x6AAA80:'依据对象+64门槛与276字节表查找值返回AL布尔',
    0x6B8C50:'begin非0时算术右移7取条目数',0x6B8E00:'begin非0时算术右移7取容量',
    0x6B8CB0:'begin迭代器加索引并取条目指针，无边界保护',
    0x6B8D20:'有空间复制一条推进end，满容量委托插入包装器',
    0x6B8EA0:'输出end迭代器',0x6B8E60:'输出begin迭代器',
    0x6B9100:'委托复制count条并返回dest+128*count',
    0x628C60:'全局8字节对象懒构造与缓存；构造依赖未闭合',
    0x64F200:'返回this+0x64地址；复用已有字段访问契约',
    0x6B8EE0:'取得相对begin索引，委托插入1条后重建输出迭代器',
    0x6B91B0:'委托迭代器首DWORD解引用',
    0x6B91E0:'thiscall源迭代器加索引后写输出迭代器；纠正伪码丢ECX',
    0x6B9920:'包装首DWORD赋值构造迭代器',
    0x6BA210:'调试AL标签与四个参数转发给复制循环',
    0x7E9610:'strcmp首匹配返回276字节记录+264；未匹配-1',
    0x6B92E0:'已读插入分支、容量增长及字段提交；移动/清理依赖未全审',
    0x6B9960:'迭代器首DWORD加index<<7',0x6B9990:'包装迭代器差值计算',
    0x6B99E0:'返回迭代器首DWORD',0x6B9A60:'写迭代器首DWORD并返回this',
    0x6B9A90:'迭代器指针差算术右移7',0x6BA5C0:'返回调试初始化字节0xCC',
    0x6BA620:'正常路径以同一source复制count份，异常销毁委托依赖未闭合',
    0x6BA800:'包装placement复制',0x6BA970:'placement new后rep movsd复制128字节；未验证内存范围',
}
PARTIAL={0x628C60:'外部构造、全局释放及并发访问未闭合',
         0x6B92E0:'搬移、分配、释放及异常依赖未全审',
         0x6BA620:'异常销毁目标及SEH表未闭合'}
rows=[]
for name in ['functions_raw.json','dependencies_raw.json','supplement_raw.json']:
    for f in json.loads((BASE/name).read_text('utf-8'))['functions']:
        va=int(f['va'],16)
        assert va in CONCLUSIONS
        status='部分分析' if va in PARTIAL else '局部语义已审阅'
        rows.append(dict(va=f['va'],name=f['name'],status=status,review_status=status,
            conclusion=CONCLUSIONS[va],unknown=PARTIAL.get(va,'完整对象生命周期、外部输入有效性及真实业务触发未全部闭合'),
            full_dependency_closure=False,reviewed_chunks=f['declared_chunks'] if status!='部分分析' else [],
            evidence=[name],scope='逐条读取声明块汇编；结论限于局部契约，库自动名不作为依据'))
assert len(rows)==len(CONCLUSIONS)==32
result=dict(counts=dict(Counter(r['status'] for r in rows)),functions=rows,
            reused_contracts=['6AA530计时与随机数专题','64F200商店字段访问','6A9530文本与容器MapList消费原证'],
            scope='本专题32函数；不把未声明跳表、导航点、复用MapList入口计成新完整函数')
(BASE/'function_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
print(result['counts'])
