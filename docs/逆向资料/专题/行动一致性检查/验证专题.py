"""重新核对专题证据与当前磁盘 EXE，生成函数审阅清单和验证结果。"""
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASELINE = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'

# 每项只覆盖这里写明的语义；大函数和外部调用另留边界。
REVIEWS = {
    0x662B20: ('4044 入口：GmsvID、目标格比较，原 6 字节记录向 head 重插',
               ['网络帧校验和服务端完整调度未展开', '运行现场停滞未复现']),
    0x63E410: ('返回参与者 R+0x5B8 的 DWORD 当前格位', []),
    0x63E5B0: ('this+0x640 转为游戏队列，读取 head', []),
    0x64F710: ('比较 WORD GmsvID；不一致显示 Error GmsvID，返回相等谓词',
               ['G+0x14784 的完整更新来源未在本专题审阅']),
    0x64FA50: ('复制 Size 到 RTC 确认的 288 字节槽，调用指定位置插入，returnMode=1',
               ['未见本函数对 Size<=288 的预先检查；不能外推其他调用者输入安全']),
    0x6942C0: ('记录构造器仅写 +0 WORD 0x4044', []),
    0x63F940: ('返回 Q+0x0C 的 head', []),
    0x6980F0: ('固定 288 字节环形槽按 position 之前插入，搬移较短侧；返回游标按模式变化',
               ['调用者 position 合法性需各自检查；不修复反编译参数类型']),
    0x64F870: ('接收分类函数；4044 走默认游戏队列复制路径',
               ['即时分支其他事件只保留原证，未宣称全部业务已审阅']),
    0x698640: ('head==next(tail) 的插入容量边界谓词', []),
    0x698680: ('环形 next(i)=(i+1)%capacity', ['容量初始化及无效输入范围不在本专题']),
    0x6986B0: ('环形 prev(i)，0 回绕到 capacity-1', ['容量初始化及无效输入范围不在本专题']),
    0x7BB290: ('门控允许时先 pop 288 字节，再经类型表调用处理入口',
               ['三个门控的完整来源复用队列专题；不能称每帧必消费']),
    0x7D8010: ('pop：推进 head、count--、复制旧 head 的 288 字节',
               ['非空保证来自调用者，未见本函数局部空队列检查']),
    0x7EFF30: ('4044 桥接：传递 G 和未变换的 record 指针', []),
    0x694DB0: ('复制 R+0x5B8 当前格位到 R+0x5BC', ['快照字段消费用途未闭合']),
    0x7F72A0: ('写 R+0x5B8 并同步 R+0x21C/0x220 显示坐标',
               ['地图坐标查询辅助函数输入边界未重新展开']),
    0x6802A0: ('606C 记录：+2 signed BYTE 参与槽、+4 signed WORD 格位，setter 后刷新',
               ['后续刷新辅助函数仅解析地址，业务副作用复用移动专题']),
}


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def collect_ranges(value):
    """遍历统一证据格式；每条字节断言都按实际磁盘重新验证。"""
    if isinstance(value, dict):
        if {'va', 'size', 'idb_hex', 'disk_hex'} <= value.keys():
            yield value
        for child in value.values():
            yield from collect_ranges(child)
    elif isinstance(value, list):
        for child in value:
            yield from collect_ranges(child)


def main():
    disk = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(disk).hexdigest()
    if digest != BASELINE:
        raise ValueError('当前 EXE 基线改变，应重新导出并审阅，不能沿用旧结论')
    if disk[:2] != b'MZ':
        raise ValueError('不是 PE 文件')
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    if disk[pe:pe + 4] != b'PE\0\0':
        raise ValueError('PE 签名错误')
    if struct.unpack_from('<H', disk, pe + 24)[0] != 0x10B:
        raise ValueError('本脚本只验证 PE32 基线')
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    section_count = struct.unpack_from('<H', disk, pe + 6)[0]
    optional_size = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + optional_size + 40 * i + 8)
                for i in range(section_count)]

    def disk_bytes(va, size):
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return disk[offset + relative:offset + relative + size]
        raise ValueError('范围未映射到磁盘节：' + hex(va))

    paths = sorted((HERE / '证据').glob('*.json'))
    documents = [(path, read_json(path)) for path in paths]
    assertions = 0
    unmapped = []
    unique_bytes = set()
    functions = {}
    for path, document in documents:
        if document.get('disk_sha256', BASELINE) != BASELINE:
            raise ValueError('证据基线不一致：' + path.name)
        for row in collect_ranges(document):
            va, size = int(row['va'], 16), row['size']
            original = bytes.fromhex(row['idb_hex'])
            if row['disk_hex'] is None:
                # 分派槽不在磁盘原始节内：保留 IDA 观察，禁止伪造磁盘比较通过。
                if not (va == 0xA9E1F0 and size == 4 and row['matching'] is None
                        and row['file_backed'] is False and len(original) == size):
                    raise ValueError('出现未声明的未映射范围：' + row['va'])
                if any(0 <= va - base - rva and va - base - rva + size <= raw_size
                       for _, rva, raw_size, _ in sections):
                    raise ValueError('未映射声明与 PE 原始节不一致')
                unmapped.append({'地址': row['va'], '长度': size,
                                 '说明': '仅 IDA 读值；没有磁盘原始节映射，不计入字节匹配'})
                continue
            captured_disk = bytes.fromhex(row['disk_hex'])
            current = disk_bytes(va, size)
            if not (len(original) == size and original == captured_disk == current
                    and row['matching'] is True):
                raise ValueError('字节断言不一致：' + path.name + ':' + row['va'])
            assertions += 1
            unique_bytes.update(range(va, va + size))
        for row in document.get('functions', []):
            va = int(row['va'], 16)
            if va in functions:
                raise ValueError('函数重复导出：' + row['va'])
            if row['bytes_match_disk'] is not True:
                raise ValueError('函数范围字节核验失败：' + row['va'])
            functions[va] = (path, row)
    if functions.keys() != REVIEWS.keys():
        raise ValueError('函数审阅清单与原证范围不一致')

    extra = read_json(HERE / '证据/check_layout_and_registration.json')
    rtc = {int(r['descriptor']['va'], 16): r for r in extra['rtc']}
    for va, offset, size in [(0x662BD6, -20, 6), (0x64FAE8, -300, 288)]:
        row = rtc[va]
        if row['count'] != 1 or len(row['variables']) != 1:
            raise ValueError('RTC 数量不一致')
        variable = row['variables'][0]
        descriptor_bytes = bytes.fromhex(row['descriptor']['idb_hex'])
        count, pointer = struct.unpack('<II', descriptor_bytes)
        layout = variable['layout']
        actual_offset, actual_size, name_pointer = struct.unpack('<iII', bytes.fromhex(layout['idb_hex']))
        if not (count == 1 and pointer == int(layout['va'], 16)
                and actual_offset == variable['stack_offset'] == offset
                and actual_size == variable['buffer_size'] == size
                and name_pointer == int(variable['name_bytes']['va'], 16)):
            raise ValueError('RTC 语义与原始描述不一致')
    registration = extra['registration']
    if int(registration['dispatch_base'], 16) + 4 * int(registration['code'], 16) != int(registration['slot'], 16):
        raise ValueError('4044 表槽公式错误')
    write = bytes.fromhex(registration['registration_write']['idb_hex'])
    if not (write[:2] == b'\xC7\x05'
            and struct.unpack('<II', write[2:]) == (0xA9E1F0, 0x60B1C5)):
        raise ValueError('4044 注册写入格式不一致')
    for key, target in [('bridge_thunk', 0x7EFF30), ('handler_thunk', 0x662B20)]:
        row = registration[key]
        raw = bytes.fromhex(row['idb_hex'])
        if raw[0] != 0xE9 or int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True) != target:
            raise ValueError('4044 跳板解析错误')

    scan = read_json(HERE / '证据/position_displacement_scan.json')
    verified = read_json(HERE / '证据/position_displacement_verified.json')
    if len(scan['hits']) != 56 or len(verified['hits']) != 56 or verified['all_matching'] is not True:
        raise ValueError('候选总数或核验结果不一致')
    categories = {'直接写': 0, '读': 0, 'push立即数': 0, 'add立即数': 0}
    for candidate, row in zip(scan['hits'], verified['hits']):
        if any(candidate[key] != row[key] for key in ['function', 'va', 'text', 'raw_hex']):
            raise ValueError('原始候选发生变更：' + row['va'])
        if not (row['same_function'] and row['same_raw_hex']
                and row['declared_function'] == candidate['function']
                and row['raw_hex'] == row['byte_range']['idb_hex']
                and row['instruction_size'] == row['byte_range']['size']):
            raise ValueError('候选身份核验失败：' + row['va'])
        text = row['text']
        if re.match(r'^mov\s+\[', text):
            categories['直接写'] += 1
        elif text.startswith('mov '):
            categories['读'] += 1
        elif text.startswith('push '):
            categories['push立即数'] += 1
        elif text.startswith('add '):
            categories['add立即数'] += 1
        else:
            raise ValueError('候选分类未覆盖：' + text)
    if categories != {'直接写': 5, '读': 44, 'push立即数': 3, 'add立即数': 4}:
        raise ValueError('候选分类数量不一致')

    # 外部复用不重复导出大函数，但重新核对其全部已保存指令与当前 EXE。
    movement_path = HERE.parent / '移动与动画协议/证据/movement_protocol_core.json'
    movement = read_json(movement_path)
    if movement['磁盘SHA256'].lower() != BASELINE:
        raise ValueError('复用移动原证的磁盘基线不一致')
    movement_rows = [r for r in movement['函数'] if int(r['地址'], 16) == 0x7F5D90]
    if len(movement_rows) != 1 or movement_rows[0]['字节一致'] is not True:
        raise ValueError('复用移动函数缺失或旧核验失败')
    movement_function = movement_rows[0]
    movement_assertions = 0
    movement_bytes = set()
    movement_instructions = {}
    for row in movement_function['完整汇编']:
        va = int(row['地址'], 16)
        audit = row['字节核验']
        original = bytes.fromhex(audit['IDB字节'])
        captured_disk = bytes.fromhex(audit['磁盘字节'])
        if not (audit['匹配'] is True and original == captured_disk == disk_bytes(va, len(original))):
            raise ValueError('移动复用原证字节不一致：' + row['地址'])
        movement_assertions += 1
        movement_bytes.update(range(va, va + len(original)))
        movement_instructions[va] = row['汇编']
    for va in [0x7F5EE5, 0x7F5F7B, 0x7F5FF3, 0x7F6089]:
        if not re.match(r'^mov\s+\[.*5B8h\], eax$', movement_instructions[va]):
            raise ValueError('运动直接写入锚点不一致：' + hex(va))
    if movement_instructions[0x7F60D2] != 'call    sub_60A086':
        raise ValueError('路线格 setter 调用锚点不一致')

    text_files = sorted(HERE.glob('0*.txt'))
    text_lines = 0
    for path in text_files:
        lines = path.read_text(encoding='utf-8').splitlines()
        if any(line.strip() and not line.startswith('//') for line in lines):
            raise ValueError('正文存在非注释式段落：' + path.name)
        text_lines += len(lines)
    review = {'对象': '当前 Richonline/RnClient.exe', '磁盘SHA256': digest,
              '方法': '逐函数汇编及调用审阅；RTC/注册表数据补证；按 PE 映射重新核验磁盘字节',
              '结论边界': '仅列明语义达到审阅范围；没有现场复现或二进制修改',
              '函数': [{'地址': hex(va), '结束地址': row['end_va'],
                        '证据': '证据/' + path.name, '状态': '已审阅所列语义',
                        '结论': REVIEWS[va][0], '未闭合项': REVIEWS[va][1],
                        '指令范围字节数': sum(r['size'] for r in row['byte_ranges'])}
                       for va, (path, row) in sorted(functions.items())],
              '外部复用': [{'地址': '0x7f5d90', '状态': '局部已审阅',
                            '证据': '../移动与动画协议/证据/movement_protocol_core.json',
                            '结论': '四方向跨格写入与路线格 setter 调用，不宣称大函数完整业务已解析'}]}
    (HERE / '函数审阅清单.json').write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding='utf-8')
    result = {'对象': '当前 Richonline/RnClient.exe', '磁盘SHA256': digest,
              '核验方式': '只读磁盘重验；IDA 当前指令和归属信息来自已保存补证',
              '证据文件数': len(documents), '函数数': len(functions),
              '字节断言数': assertions, '去重覆盖字节数': len(unique_bytes),
              '未映射观察': unmapped,
              'RTC容量': {'4044临时记录': 6, '插入包装内部槽': 288},
              '候选数': 56, '候选分类': categories,
              '外部复用核验': {'函数': '0x7f5d90', '指令断言数': movement_assertions,
                                '覆盖字节数': len(movement_bytes),
                                '方法': '重新核对原专题全部已保存指令；语义仍限定相关运动分支'},
              '正文文件数': len(text_files), '正文行数': text_lines,
              '全部通过': True, '限制': '离线脚本不重新连接 IDA、不证明运行时状态或穷尽间接写入'}
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
