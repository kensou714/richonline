"""从已有只读导出建立人工审阅状态；不把导出自动当成完整语义。"""
from pathlib import Path
from collections import Counter
import json

BASE = Path(__file__).resolve().parent
SOURCES = ['functions_raw.json', 'caller_functions.json']
NOTES = {
    0x628EF0: ('懒分配16字节过滤对象，构造后存A76738；全局无同步。', '分配失败处理与调用线程来源未闭合。'),
    0x64C460: ('只清对象+4、+C两指针，不清+0、+8计数。', '未成功加载前的上层使用顺序未闭合。'),
    0x64C490: ('两非空词条数组delete[]后清指针，计数保持。', '销毁后是否再次过滤未闭合。'),
    0x64C510: ('第一套词条：数ITEM，按count<<6分配，初始化首字节，再顺序读str。', '解析及解包依赖只审相关调用；异常资源实机行为未验证。'),
    0x64C770: ('第二套词条：字段+8/+C，按64字节槽加载；与第一套同型。', '解析及解包依赖只审相关调用；异常资源实机行为未验证。'),
    0x64F220: ('每个64字节词条槽仅首字节写0。', '其余槽字节取决于分配器，非完整清零。'),
    0x64C9E0: ('第一套词条首命中优先，原地memset星号；高位首字节步进2。', '所有调用者长度和编码未闭合；不宣称真实输入已触发边界。'),
    0x64CAE0: ('第二套词条同型过滤，使用+8/+C，返回AL命中标记。', '所有调用者长度和编码未闭合。'),
    0x647610: ('转交三参数到strncmp真实实现9228E0。', 'CRT实现细节仅覆盖本专题实际调用语义。'),
    0x64CDC0: ('按mode逐字节25与01互换，不识别双字节或Unicode。', '上层是否存在嵌入01及容量契约未闭合。'),
    0x627160: ('ABABB8懒分配0x18968字节，无构造初始化。', '分配失败与加载失败后使用路径未闭合。'),
    0x818D70: ('打开解包资源，固定复制0x7FC8/0x1099C，再存系统语言标签。', '解包器异常路径只部分审阅；没有证明所有资源失败恢复。'),
    0x818EA0: ('合成16位值，判断A1A1..A9FE或B0A1..F7FE，不独立验尾字节。', '全局ABAA40使函数非重入；实机并发未证明。'),
    0x818F10: ('合成16位值，判断三个反向整数区间，不独立验尾字节。', '格网含编码孔洞；实机输入来源未闭合。'),
    0x818FA0: ('前向原地双字节查表，376行步长，目标为记录+2/+3。', '无容量与孤立高位字节保护；输入可达性未验证。'),
    0x8190B0: ('反向原地双字节查表，后表起点7FC8、764行步长。', '无容量与孤立高位字节保护；输入可达性未验证。'),
    0x64ED90: ('读取对象+18964系统语言标签。', '标签不等于字符串编码或CP_ACP。'),
    0x64F000: ('比较语言标签是否1，以AL返回。', '调用者的语言约束未全闭合。'),
    0x64F030: ('比较语言标签是否2，以AL返回。', '调用者的语言约束未全闭合。'),
    0x81C450: ('GetSystemDefaultLangID：804/1004为1，404/C04/1404为2，其余0。', '未推断实际ACP或输入编码。'),
    0x8198E0: ('从解析游标读至LF，转换反引号n、高位复制两字节，先写后断言容量。', '解析器完整对象与资源异常路径见资源专题，不在此全审。'),
    0x9228E0: ('最多N字节扫描Str1至NUL，再比较对应字节，N=0直接相等。', '仅该比较实现已读汇编；未全审所有CRT与运行时依赖。'),
    0x623AD0: ('核对ChsTb启动调用，忽略加载返回值；其余初始化保留原汇编。', 'IME、随机数、输出器等后续语义不在此全审。'),
    0x623EE0: ('核对Filter先于FilterN加载，任一返回0即启动返回0。', '大量其他资源加载与后续启动语义未全审。'),
    0x6AAB50: ('核对过滤、百分号转义、语言单字节和参数四字节组包、本地消息13。', '全局发送缓冲容量及消息13到网络的路径未闭合。'),
    0x6C14E0: ('核对RACE的name/desc局部缓冲128/1024与语言1时前向转换。', '其余RACE字段加载、尾块与失败处理未全审。'),
    0x81B4C0: ('核对资源读取、首字节差分还原和解包调用邻域。', '完整资源对象生命周期及所有错误分支未全审。'),
    0x81B7F0: ('核对LZO解包参数与声明尺寸使用。', '解压核心、异常输出长度与所有依赖未全审。'),
    0x81AD80: ('核对818D70结尾ECX指向栈资源对象后调用析构。', '完整资源析构及调用环境未全审；非映射对象析构。'),
    0x648C20: ('核对聊天载荷语言比较、前反向转换、过滤、显示邻域顺序。', '其余UI、命令及聊天分支未全审。'),
    0x64A9F0: ('核对另一聊天载荷的语言比较、转换、过滤和格式化邻域。', '其余UI、命令及聊天分支未全审。'),
}
PARTIAL = {0x623AD0, 0x623EE0, 0x6AAB50, 0x6C14E0, 0x81B4C0,
           0x81B7F0, 0x81AD80, 0x648C20, 0x64A9F0}
functions = []
for source in SOURCES:
    for f in json.loads((BASE/source).read_text('utf-8'))['functions']:
        va = int(f['va'], 16)
        conclusion, unknown = NOTES[va]
        functions.append(dict(va=f['va'], sources=[source], evidence=[source, 'navigation_data.json'],
            status='部分分析' if va in PARTIAL else '局部语义已审阅', full_dependency_closure=False,
            review_status='部分分析' if va in PARTIAL else '局部语义已审阅',
            conclusion=conclusion, unknown=unknown,
            reviewed_chunks=[] if va in PARTIAL else f['declared_chunks']))
functions.sort(key=lambda f: int(f['va'], 16))
assert len(functions) == len({f['va'] for f in functions}) == 31
counts = dict(Counter(f['review_status'] for f in functions))
(BASE/'function_review.json').write_text(json.dumps(dict(sources=SOURCES, counts=counts,
    functions=functions), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
lines = ['// ============================================================================',
    '// 文本过滤与字码转换 / 逐函数审阅清单',
    '// ============================================================================',
    '// 31个唯一函数；22个局部语义已审阅，9个部分分析。',
    '// 局部语义覆盖保存声明块；不表示调用者、CRT/EH依赖全部闭合。',
    '// 部分分析只核对正文指定邻域，不以完整导出冒充完整审阅。',
    '// 状态、结论、未知项、来源与审阅块见证据/function_review.json。', '//']
for f in functions:
    lines.extend(['// '+f['va'].upper()+' / '+f['review_status'], '// '+f['conclusion'],
                  '// 边界：'+f['unknown'], '//'])
(BASE.parent/'05_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
print(json.dumps(counts, ensure_ascii=True))
