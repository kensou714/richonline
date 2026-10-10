"""生成分级清单与逐函数正文，外部复用函数保留来源而不复制全专题。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CONTRACTS = {
    '0x91f950': ('静态契约已审阅', '17字节包装，参数原样转91F800并返回32位EAX。', '不扩大为所有CRT版本的atoi契约。'),
    '0x91f800': ('静态契约已审阅', '按locale跳开头空白，一个ASCII符号、连续ASCII数字，低32位累积和最终neg；无数字0。', '线程/locale内部依赖未全部闭环；没有安全输入或全文合法保证。'),
    '0x9305c0': ('静态契约已审阅', '范围调试检查后读取locale+72分类表WORD并与mask相与；非法值可能继续访问。', '调试报告内部及终止策略未展开；表对象必须有效。'),
    '0x930660': ('局部消费契约已审阅', 'c=-1或0..255查表；其他值按高BYTE标记经外部API做1/2BYTE分类。', '外部字符串分类/码页API未闭环；atoi仅使用0..255直接表路径。'),
    '0x92de70': ('局部消费契约已审阅', 'lock(12)、内部locale更新、正常路径unlock(12)，返回保存的更新结果。', 'SEH作用域表、内部更新及锁算法未展开，不保证所有异常路径。'),
}
REUSE = {
    '0x930960': ('../随机数状态与取样边界/证据/functions_raw.json', '返回/创建8Ch线程对象，正常路径保存恢复LastError；复用线程对象原证。'),
    '0x6daa10': ('../图像运行时接口/证据/draw_mapping_dependencies.json', '名称字段交atoi解析，复用已审字符串消费；不新增完整业务函数完成量。'),
}


def main():
    rows = {}
    fingerprint = None
    for filename in ('classification_helpers.json', 'locale_update.json', 'seeds.json'):
        path = HERE / '证据' / filename
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or 'functions' not in data:
            continue
        fingerprint = data['disk_sha256']
        for index, function in enumerate(data['functions']):
            address = function['va']
            status, conclusion, unknown = CONTRACTS[address]
            row = rows.setdefault(address, dict(va=address, status=status, conclusion=conclusion, unknown=unknown, evidence=[]))
            row['evidence'].append(f'证据/{path.name}#/functions/{index}')
    for address, (source, conclusion) in REUSE.items():
        data = json.loads((HERE / source).read_text(encoding='utf-8'))
        index = next(i for i, function in enumerate(data['functions']) if function['va'] == address)
        assert data['disk_sha256'] == fingerprint
        rows[address] = dict(va=address, status='既有专题审阅复核', conclusion=conclusion,
                             unknown='仅复用已审原证及当前调用边界；不新增主审完成量。',
                             evidence=[f'{source}#/functions/{index}'], reused_review=source)
    functions = sorted(rows.values(), key=lambda row: int(row['va'], 16))
    payload = dict(disk_sha256=fingerprint, functions=functions,
                   scope='数字转换、分类及locale外层；代表消费者为既有专题复用')
    (HERE / '函数审阅清单.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    lines = ['// ============================================================================', '// CRT数字转换 / 逐函数分级',
             '// ============================================================================', '// 原证指针见函数审阅清单.json；复用项不新增完成量。', '//']
    for row in functions:
        lines.extend(['// ' + row['va'].upper() + ' / ' + row['status'], '//   ' + row['conclusion'],
                      '//   未知：' + row['unknown'], '//'])
    (HERE / '04_逐函数结论.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
    print(len(functions))


if __name__ == '__main__':
    main()
