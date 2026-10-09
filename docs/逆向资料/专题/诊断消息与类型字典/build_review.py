"""由已核验原证生成诊断类型字典与显式审阅清单；不把导出自动升为已分析。"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / '证据' / name).read_text(encoding='utf-8'))


def main():
    handlers = read('diagnostic_handlers.json')
    helpers = read('diagnostic_helpers.json')
    queue = read('diagnostic_queue_helpers.json')
    data = read('diagnostic_data.json')
    strings = {(x['function'], x['site']): x for x in data['strings']}
    text = '''// 4053..4057：诊断载荷与类型名称
//
// 4053 → 662E30；读取下界12字节
//   +4 signed BYTE：0现金、1存款、2点券、3卡槽显示。
//   0/1/2：+5 signed BYTE选P，P+112提供名称；+8 signed DWORD用于%d。
//   3：+6 signed BYTE为显示槽号；+8为-1显示空值，否则作表索引。
//   表地址由627C20取得，693370返回DWORD[table]+1128*index+660字符串。
//   本处理器只格式化文字，没有按+8修改现金、存款、点券或库存。
//   默认分支仍调用文字记录函数，但没有写Buffer。入口rep stosd填0xCC，
//   因此未知+4不是安全忽略分支；实际可达性取决于上游消息规则，未动态验证。
//
// 4054 → 663010；读取下界16字节
//   +4/+8/+12三个DWORD按有符号%d显示为MaxNum、MaxIndx、FactNum。
//   仅凭显示标签不能把它们命名成某个确定容器的真实容量字段。
//
// 4055 → 6630F0；读取下界8字节
//   +4按IEEE754 float读取，fld后以double传给sprintf的%f，显示<Ver ...>。
//   不读主EXE文件版本，也未见基于该数值进行兼容性分支。
//
// 4056 → 6631C0；读取下界10字节
//   +4 signed WORD为地产索引；M=G+0x65C，D=DWORD[M+56]+68*index。
//   +6 BYTE：11显示“小”，12显示“大”，其它显示“错”。
//   +7 signed BYTE为下面的建筑类别；+8 signed BYTE为显示等级。
//   +9 signed BYTE为owner；-1显示“无”，否则直接取P[owner]+112的名称。
//   地产名称来自D+32。其余类别/等级/归属来自本消息，不从D重新读取。
//   本函数没有更新D，不可把它当成建筑状态同步协议。
//
// 建筑类别原文（4056的+7；仅字面映射，不自动推导可建性/价格/技能）
'''.splitlines()
    mapping = []
    for f in handlers['functions']:
        if f['va'] not in ('0x6631c0', '0x663500'):
            continue
        if f['va'] == '0x663500':
            text.extend('''//
// 4057 → 663500；读取下界8字节
//   +4 signed WORD为显示索引；+6 signed BYTE经下表选名称。
//   +7 signed BYTE为owner；-1显示“无”，否则直接取P[owner]+112。
//   本处理器不解析地图坐标，不写动态格，不触发对应NPC效果。
//
// NPC与动态物件原文（4057的+6）'''.splitlines())
        for ins in f['assembly']:
            item = strings.get((f['va'], ins['va']))
            match = re.search(r'case (-?\d+)(?:$|\s)', ins['text'])
            default = 'default case' in ins['text']
            if item and (match or default):
                value = int(match.group(1)) if match else '其它'
                text.append(f"//   {str(value):>3}  {item['gbk']}  字符串{item['va']}；分支{ins['va']}")
                mapping.append(dict(handler=f['va'], value=value, label=item['gbk'],
                                    literal_va=item['va'], branch_va=ins['va'],
                                    raw_hex=item['raw_hex']))
    text.extend('''//
// 文字记录与容量
//   五个处理器均调用62A100取得记录器，再以颜色0xFF00FF00和Source=null调用649A30。
//   649A30将文字按300像素宽度拆行；不是按300字节安全截断。
//   行记录步长340：+0文字，+272来源字符串，+336颜色。行索引位于对象+16，
//   记录基址在+20。本专题只局部审阅布局及入口，字体宽度/滚动/绘制另见文本专题。
//   0x80以上字节按双字节路径拷贝；不是UTF-8多字节解码器。
//   RTC描述明确Buffer容量：4053/4055/4057为128，4054/4056为256字节。
//   伪码显示132/260是把保护空隙并进数组，不能据此放宽缓冲区。
//   sprintf没有显式输出上限；名字长度、表索引与上游验证仍需单独取证。
//
// 编码与适用范围
//   上述名称是EXE中原始GBK字节的静态转录，保留原词“恐怖份子”“研究所BS”。
//   CP950对照解码产生乱码，证据JSON同时保留；运行ACP未测。
//   此表与动态格12=地雷、27=超级地雷的已证路径吻合。
//   它没有直接证明角色P+1488的状态号与NPC编号具有一一对应关系。
//   状态槽、静态格类型、动态格类型、卡片编号必须分别核对写入源。
'''.splitlines())
    (ROOT / '01_诊断载荷与类型名称.txt').write_text('\n'.join(text) + '\n', encoding='utf-8')
    (ROOT / '类型名称映射.json').write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding='utf-8')
    conclusions = {
        0x662920: '4041以{2,signed+4,signed+5}通知UI槽0；24字节栈对象仅前三DWORD业务赋值；具体消费者待追。',
        0x6629d0: '4042检查G槽标志和P+144>0后，将packet+5字符串复制到DWORD[P+576]+8。',
        0x662a70: '4043将两个signed BYTE扩展为DWORD，向G+0x20的8字节环形队列入队。',
        0x662e30: '4053显示现金/存款/点券/卡槽；不修改对应数值；非法分支未初始化Buffer仍输出。',
        0x663010: '4054显示三个signed DWORD诊断值；不据标签推断具体容器。',
        0x6630f0: '4055将+4 float提升为double供%f显示；不验证版本兼容性。',
        0x6631c0: '4056格式化地产名称、消息中的建筑类别/等级/owner；恢复-1..20共22个显式值及额外默认分支的字面映射。',
        0x663500: '4057格式化动态对象索引、31类字面名称和owner；无地图状态修改。',
        0x64f710: '比较WORD[G+0x14784]与传入GmsvID；不符弹MessageBoxA后返回0。',
        0x6279c0: 'UI管理器单例getter，首次分配0x6C0并调用构造；构造内部未在本组审阅。',
        0x6e4640: '锁管理器+0x6A8，查132字节槽的+4对象，调用vtbl+0x10再解锁。',
        0x63e7d0: '返回BYTE[this+3632+slot]；4042调用时this为G。',
        0x63f810: 'SETNLE实现signed DWORD[this+144]>0；4042调用时this为P。',
        0x63f7b0: '返回DWORD[this+576]；4042随后将其用作Q对象，不是MFC字体类型。',
        0x640d60: 'strcpy(this+8,Source)，未提供长度参数；目的对象容量未追完。',
        0x697ea0: '满队列返回0，否则写8字节二元记录，推进写索引并增加count。',
        0x63e1c0: '返回this+112字符串地址；本组调用点ECX均明确为角色对象。',
        0x627c20: '表单例getter，首次分配0x14C；表装载和容量不在本组范围。',
        0x693370: '返回DWORD[this]+1128*index+660，没有局部索引检查。',
        0x62a100: '文字记录器单例getter，首次分配0x1688；构造/析构不在本组范围。',
        0x649a30: '局部确认300像素拆行、340字节记录、+272来源和+336颜色；不是300字节截断。',
        0x694360: '返回DWORD[this+56]+68*index；4056调用时this=G+0x65C。',
        0x6985d0: '比较read与(write+1)%modulus判满，模数及索引有效性依赖外部。',
        0x698610: '返回(index+1)%modulus，汇编为32位有符号余数。',
        0x6bfa00: '将ECX作为CRITICAL_SECTION指针调用EnterCriticalSection。',
        0x6bfa40: '将ECX作为CRITICAL_SECTION指针调用LeaveCriticalSection。',
    }
    records = []
    for name, group in [('diagnostic_handlers.json', handlers), ('diagnostic_helpers.json', helpers),
                        ('diagnostic_queue_helpers.json', queue)]:
        for f in group['functions']:
            assert f['bytes_match_disk'], f['va']
            records.append(dict(va=f['va'], status='局部语义已审阅', conclusion=conclusions[int(f['va'], 16)],
                                evidence='证据/' + name,
                                unknown='未实机验证；范围之外的上游校验、构造、间接消费者及外部依赖不计为本函数群已闭环。'))
        assert all(t['matching'] for t in group['thunks'])
    assert len(records) == len(conclusions) == 26
    assert all(s['bytes']['matching'] for s in data['strings'])
    assert all(r['header_bytes']['matching'] and r['descriptor_bytes']['matching'] for r in data['rtc'])
    (ROOT / '函数审阅清单.json').write_text(json.dumps(dict(scope='诊断及相邻通知局部语义审阅', functions=records), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(functions=len(records), dictionary_entries=len(mapping), all_exported_bytes_match=True), ensure_ascii=False))


if __name__ == '__main__':
    main()
