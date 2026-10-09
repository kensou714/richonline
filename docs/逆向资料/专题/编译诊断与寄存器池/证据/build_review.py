"""生成逐函数人工审阅状态与中文清单；不修改原始导出。"""
from pathlib import Path
from collections import Counter
import json

BASE = Path(__file__).resolve().parent
SOURCES = ['functions_raw.json', 'identity_callers.json']
NOTES = {
    0x995011: ('部分分析', '已读控制流并恢复操作码分解、输入引用计数、结果条目与诊断邻域。', '操作记录与类型描述表依赖未闭合，未恢复源码签名和所有操作码名。'),
    0x993EC8: ('局部语义已审阅', '非零uint32计数时rep stosd写FFFFFFFF；返回0/retn8。', '调用者缓冲容量与误传负计数路径未全审。'),
    0x9CAD79: ('局部语义已审阅', '入口ECX池；分配96字节、初始化、登记，失败删除条目并返回-1。', '池完整类型和外部输入来源未恢复。'),
    0x9CB6FC: ('局部语义已审阅', '仅mov EAX,ECX后返回；无初始化操作。', '不能因此声称完整记录已初始化。'),
    0x9CB700: ('局部语义已审阅', '填写类型/两个参数/double，固定哨兵及零字段，恒返回0。', '条目+5C未写，多个字段精确业务语义未恢复。'),
    0x9CA930: ('局部语义已审阅', '空析构跳板后按删除标志bit0调用operator delete；返回this。', '原C++类型名与外部生命周期未恢复。'),
    0x9CAA68: ('局部语义已审阅', 'count==capacity扩容，有限数值属性分类，登记条目并返回索引。', 'x87非有限数值/__ftol边界及完整类型表未闭合。'),
    0x9CAF88: ('局部语义已审阅', '无符号索引>=count返回0，否则加载指针数组槽。', '合法空槽与越界都返回0；池全生命周期未闭合。'),
    0x9D0A78: ('局部语义已审阅', '256字节格式化并强制末NUL，tag2/12选来源，写对象+38错误标记。', '忽略消息存储失败；源节点完整枚举未恢复。'),
    0x994DE3: ('局部语义已审阅', '256字节格式化并强制末NUL，tag5/12选来源，写上下文+34错误标记。', '与9D0A78布局不同；源节点枚举/上层恢复未闭合。'),
    0x98E8C1: ('局部语义已审阅', '4096字节行缓冲、文件/行号/错误号前缀、LF/NUL、先加条数再追加节点。', '原CRT/输入来源未全闭合；异常Format实机行为未测试。'),
    0x98E170: ('局部语义已审阅', 'len+5节点头插，+0旧头/+4含NUL文本；计字节不计NUL。', '链表导出/销毁/最终显示顺序未闭合。'),
    0xA0B1AA: ('部分分析', '核对D3DX9 Shader Compiler字符串指针和调用9D0A78的同函数出处。', '其余着色器目标及编译输出组织未全审。'),
    0x9916F1: ('部分分析', '核对D3DX9 Shader Assembler字符串指针和调用98E8C1的同函数出处。', '其余汇编目标及输出组织未全审。'),
}
functions = []
for source in SOURCES:
    for f in json.loads((BASE/source).read_text('utf-8'))['functions']:
        status, conclusion, unknown = NOTES[int(f['va'], 16)]
        functions.append(dict(va=f['va'], sources=[source], evidence=[source, 'navigation_data.json'],
            status=status, review_status=status, conclusion=conclusion, unknown=unknown,
            full_dependency_closure=False,
            reviewed_chunks=f['declared_chunks'] if status == '局部语义已审阅' else []))
functions.sort(key=lambda f: int(f['va'], 16))
assert len(functions) == len({f['va'] for f in functions}) == 14
counts = dict(Counter(f['review_status'] for f in functions))
(BASE/'function_review.json').write_text(json.dumps(dict(sources=SOURCES, counts=counts,
    functions=functions), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
lines = ['// ============================================================================',
    '// 编译诊断与寄存器池 / 逐函数审阅清单',
    '// ============================================================================',
    '// 14个唯一函数；11个局部语义已审阅，3个部分分析。',
    '// 局部函数的声明块已读；不宣称CRT、类型表或全部调用者依赖已闭合。',
    '// 995011及2个出处大函数保留部分状态，后续可按未知项继续分析。', '//']
for f in functions:
    lines.extend(['// '+f['va'].upper()+' / '+f['review_status'], '// '+f['conclusion'],
                  '// 边界：'+f['unknown'], '//'])
(BASE.parent/'04_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
print(json.dumps(counts, ensure_ascii=True))
