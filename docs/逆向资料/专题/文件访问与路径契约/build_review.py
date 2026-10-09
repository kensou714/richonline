"""登记本专题人工结论；既有日志专题保持来源，不重复累计新增审阅。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACTS = {
    '81b980': '固定ABAB9C临界区内调用文件摘要，正常返回后释放锁；不传播摘要错误状态。',
    '827b30': 'rb打开，按4096字节循环读取并更新摘要，写16字节结果后关闭；打开失败不改输出。',
    '8283c0': '初始化四个MD5链值及64位比特计数；不初始化剩余64字节块存储。',
    '828dd0': '更新64位比特计数，补齐已有块、处理完整64字节块并保存余数。',
    '828e90': '补至56或120字节，追加8字节原长度，写16字节小端摘要并清88字节状态。',
    '8284e0': '按小端解码16 DWORD，执行MD5四轮64步并累加原四链值；不更新长度、不清工作栈。',
    '6bfa00': 'EnterCriticalSection(this)薄包装，未在本函数初始化或拥有临界区。',
    '6bfa40': 'LeaveCriticalSection(this)薄包装，无摘要/FILE错误返回语义。',
    'a0e76a': 'CreateDirectoryA成功将错误值置0，否则取LastError；最终错误值0则返回0，非0映射后返回-1；不递归。',
    '923d90': '空FILE只调试报告后继续；普通路径锁定并转内部关闭，特殊40h标记清零后返回-1。',
    '924000': '未锁定的元素读取实现；EOF/错误返回已完成元素数，分别设置10h/20h标记。',
    '9243c0': 'fopen转_fsopen并固定共享参数64；内部打开流程不在此条展开。',
    '924480': '未锁定的元素写入实现；短写/失败返回已完成元素数并设置20h，乘积无溢出检查。',
    '923f60': '锁FILE，调用924000，保存元素读取数量，解锁并返回保存结果。',
    '9243e0': '锁FILE，调用924480，保存元素写入数量，解锁并返回保存结果。',
    '819c20': '选择at/wt，直接覆盖对象首FILE槽，返回非空判断，不先关闭旧槽。',
    '819c90': '直接关闭对象首FILE槽，不校验空值，也不把已关闭槽清零。',
    '81c350': 'FindFirst失败返回-1；首条起回调，AL非0停止；正常结束或停止后FindClose并返回BOOL。',
}
PARTIAL = {'623b60': '启动函数中创建ScreenShot并忽略结果，后续传相对Config/Data路径；其余系统初始化未在此条审阅。'}
REUSED = {
    '81be00': '先写两路缓冲，关闭非空FILE，再释放缓存；复用事件文字记录器主审阅。',
    '81bea0': '建立Log/Game和Log/Sys日期目录，at打开两FILE；复用事件文字记录器主审阅。',
    '81c190': 'strlen追加，阈值/force满足时尝试写出后无条件清used；复用事件文字记录器主审阅。',
    '81c2b0': '尝试写两路剩余缓存，不清used；复用事件文字记录器主审阅。',
}


def main():
    entries = {}
    fingerprint = None
    for path in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('functions'), list):
            continue
        fingerprint = data['disk_sha256']
        for index, function in enumerate(data['functions']):
            key = function['va'][2:]
            entry = entries.setdefault(function['va'], dict(va=function['va'], evidence=[]))
            entry['evidence'].append(f'证据/{path.name}#/functions/{index}')
            if key in CONTRACTS:
                entry.update(status='静态契约已审阅', conclusion=CONTRACTS[key],
                             unknown='未实机执行；外部调用者、正式源码类型及非正常退出约束不由本条证明。')
            elif key in PARTIAL:
                entry.update(status='局部消费契约已审阅', conclusion=PARTIAL[key],
                             unknown='仅文件/路径消费片段已核，不宣称整个函数业务闭合。')
            elif key in REUSED:
                entry.update(status='既有专题审阅复核', conclusion=REUSED[key],
                             unknown='主证据和独审见专题/事件文字记录器；本专题不新增此函数审阅数量。',
                             reused_review='../事件文字记录器/05_逐函数审阅.txt')
            else:
                entry.update(status='邻近候选仅导出', conclusion='完整块字节已导出；尚未登记逐路径语义结论。',
                             unknown='导出不等于人工完成。')
    rows = sorted(entries.values(), key=lambda r: int(r['va'], 16))
    code = dict(start_va='0x81b8b0', end_va='0x81b973', status='未声明代码区间已审阅',
                conclusion='精确模式8000h/4000h选择wb/wt；以对象+00/+08单元素写出并关闭；无结果检查。',
                unknown='IDA未声明函数，未证实真实业务调用者；不能计入完整函数数。',
                evidence=['证据/undeclared_write.json#/code_range'])
    manifest = dict(disk_sha256=fingerprint, scope='文件静态契约；局部与复用项独立计数',
                    functions=rows, code_ranges=[code])
    (HERE / '函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// ============================================================================', '// 文件访问 / 逐函数结论',
             '// ============================================================================', '// 机器证据指针见函数审阅清单.json；复用项不新增完成量。', '//']
    for row in rows:
        lines.extend(['// ' + row['va'].upper() + ' / ' + row['status'],
                      '//   ' + row['conclusion'], '//   未知：' + row['unknown'], '//'])
    lines.extend(['// ' + code['start_va'].upper() + '..' + code['end_va'].upper() + ' / ' + code['status'],
                  '//   ' + code['conclusion'], '//   未知：' + code['unknown']])
    (HERE / '05_逐函数结论.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return len(rows)


if __name__ == '__main__':
    print(main())
