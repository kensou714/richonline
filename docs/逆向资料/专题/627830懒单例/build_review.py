"""生成显式函数状态，原证导出不等于整组完成。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ('seeds.json', 'lifetime_and_facade.json', 'gate_and_delete.json')
PARTIAL = {0x627830: 'SEH作用域表和分配器异常未闭合。',
           0x627520: '借用对象构造依赖及SEH作用域未闭合。',
           0x698C70: '69A230目标含义、+5写入者及完整对象未闭合。'}
REUSED = {0x6DD3D0, 0x6DD600, 0x6DD710, 0x6DD810, 0x6DD880, 0x6DDCF0}
CONCLUSIONS = {
    0x627830: 'A766BC为空时分配20字节并构造；空分配保持0；无局部锁。',
    0x6298E0: '调用四槽析构；flag低位为1才delete管理器，返回原this。',
    0x6DD250: '先借用A766B8对象+5地址至+16，再清四字库槽。',
    0x627520: 'A766B8的20字节依赖对象懒创建外层。',
    0x6DD2B0: '按偏移0/4/8/12删除非空字库并清槽，不动借用地址。',
    0x6DF790: '返回this+5字节地址，不复制或拥有它。',
    0x698C70: '写依赖对象+0、+4=1、+6=0；未写+5。',
    0x6DFBA0: '字库析构后按flag低位删除，返回原this。',
    0x6DFC10: '无保护地读取管理器+16所指byte作为门控。',
    0x6DD3D0: '依次发布并初始化12/14/16/24；失败不回滚，重复调用覆盖旧槽。',
    0x6DD600: '借用byte门控，窄转宽并按字号选槽绘制；非法字号仍使用局部值。',
    0x6DD710: '借用byte门控，宽字符串单行绘制；非法字号非安全拒绝。',
    0x6DD810: '窄转宽后进入矩形门面，存在二次门控。',
    0x6DD880: '矩形分行与全局缓冲，绘行重取懒单例；既有风险沿用字体专题。',
    0x6DDCF0: '12/14/16/24返回四槽，其余字号返回0。',
}


def build():
    rows = []
    for filename in FILES:
        data = json.loads((HERE / '证据' / filename).read_text(encoding='utf-8'))
        for index, function in enumerate(data['functions']):
            address = int(function['va'], 16)
            reused = address in REUSED
            status = '既有专题完整复核' if reused else ('局部静态契约部分完成' if address in PARTIAL else '局部静态契约已完成')
            rows.append(dict(va=function['va'], status=status, newly_analyzed=not reused,
                             conclusion=CONCLUSIONS[address],
                             unknown=PARTIAL.get(address, '外部依赖、运行态与上层参数安全未由本局部证明。'),
                             evidence=f'证据/{filename}#/functions/{index}',
                             declared_chunks=function['declared_chunks'],
                             declared_bytes=sum(int(c['end_va'],16)-int(c['start_va'],16) for c in function['declared_chunks']),
                             reused_topic='../字体与文本渲染/函数审阅清单.json' if reused else None))
    payload = dict(disk_sha256=data['disk_sha256'], functions=rows,
                   limitation='局部静态契约不代表全部外部依赖闭合；既有字体复核不重复新增完成量。')
    (HERE / 'function_review.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    lines = ['// ============================================================================', '// 逐函数结论 / 本表由build_review.py生成', '// ============================================================================']
    for row in rows:
        lines.extend(['//', f"// {row['va']} / {row['status']} / {row['declared_bytes']}声明字节",
                      '// ' + row['conclusion'], '// 未决：' + row['unknown'], '// 原证：' + row['evidence']])
    (HERE / '03_逐函数结论.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
    return payload


if __name__ == '__main__':
    print(len(build()['functions']))
