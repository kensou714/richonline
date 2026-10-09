"""只读核验卡片函数证据、联读Big5资源并生成有明确边界的函数清单。"""
import hashlib
import json
import struct
from pathlib import Path
import lzokay

folder = Path(__file__).resolve().parent
root = folder.parents[3]
raw = json.loads((folder / 'ida_cards_raw.json').read_text(encoding='utf8'))
# 人工结论源同时维护发送门槛边界；动作返回0不能改写为网络发送成功。
notes = json.loads((folder / 'card_review_conclusions.json').read_text(encoding='utf8'))
binary = (root / 'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', binary, 0x3c)[0]
count = struct.unpack_from('<H', binary, pe + 6)[0]
optional_size = struct.unpack_from('<H', binary, pe + 20)[0]
base = struct.unpack_from('<I', binary, pe + 52)[0]
sections = []
for i in range(count):
    p = pe + 24 + optional_size + i * 40
    _, rva, size, pointer = struct.unpack_from('<IIII', binary, p + 8)
    sections.append((rva, size, pointer))


def read_va(va, size):
    relative = va - base
    for start, length, offset in sections:
        if start <= relative and relative + size <= start + length:
            return binary[offset + relative - start:offset + relative - start + size]
    return None


checks = []
for function in raw['functions'].values():
    chunks = []
    for region in function['ranges']:
        original = bytes.fromhex(region['idb_bytes_hex'])
        current = read_va(int(region['start'], 16), len(original))
        chunks.append({'start': region['start'], 'end': region['end'],
                       'match': original == current,
                       'idb_sha256': hashlib.sha256(original).hexdigest(),
                       'disk_sha256': hashlib.sha256(current).hexdigest() if current else None})
    checks.append({'ea': function['ea'], 'chunks': chunks,
                   'match': all(item['match'] for item in chunks)})
regions = []
for region in raw['data_regions']:
    original = bytes.fromhex(region['bytes_hex'])
    regions.append({'start': region['start'], 'kind': region['kind'],
                    'match': read_va(int(region['start'], 16), len(original)) == original})
verification = {'idb_input_sha256': raw['idb_input_sha256'],
                'disk_sha256': hashlib.sha256(binary).hexdigest().upper(),
                'functions': checks, 'data_regions': regions,
                'matched_functions': sum(item['match'] for item in checks)}
(folder / 'cards_verification.json').write_text(
    json.dumps(verification, ensure_ascii=False, indent=2) + '\n', encoding='utf8')

# 资源保留原始繁体；不用系统默认编码，也不改动游戏原文件。
prop_bytes = (root / 'Data' / 'Prop.kpd').read_bytes()
decoded = bytes((value - prop_bytes[0]) & 255 for value in prop_bytes[1:])
uncompressed_size, compressed_size = struct.unpack_from('<II', decoded)
plain = lzokay.decompress(decoded[8:8 + compressed_size], uncompressed_size)
source = plain.decode('big5')
resources = {}
duplicates = []
for block in source.split('[PROP]')[1:]:
    values = {}
    for line in block.splitlines():
        if '=' in line and not line.lstrip().startswith('//'):
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    if 'indx' in values:
        index = int(values['indx'])
        if index in resources:
            duplicates.append(index)
        resources[index] = values
bindings = [{'id': item['id'], 'resource': resources.get(item['id'])}
            for item in raw['operation_table']]
resource_report = {'source': 'Data/Prop.kpd', 'encoding': 'Big5严格解码',
                   'file_sha256': hashlib.sha256(prop_bytes).hexdigest(),
                   'plain_sha256': hashlib.sha256(plain).hexdigest(),
                   'record_count': len(resources), 'duplicate_ids': duplicates,
                   'uncompressed_size': len(plain), 'bindings': bindings}
(folder / 'resource_binding.json').write_text(
    json.dumps(resource_report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')

operations = {item['target']: item for item in raw['operation_table']}
replies = {item[2]: item for item in raw['reply_map']}
reviews = []
for ea, function in raw['functions'].items():
    if ea in notes:
        status = '静态局部语义已审阅'
        detail = notes[ea]
        conclusion, unknown, document = detail['conclusion'], detail['unknown'], detail['document']
    elif ea in raw['thunk_targets']:
        status = '跳板目标已核对'
        target = raw['thunk_targets'][ea]
        conclusion = f'{ea}直接跳转{target}，仅核对地址连接，不计作独立业务实现。'
        unknown = f'目标{target}完整业务以其审阅状态为准；跳板不证明目标副作用。'
        document = 'ida_cards_raw.json/functions/' + ea
    elif ea in operations:
        status = '动作桥接已核对'
        item = operations[ea]
        name = resources.get(item['id'], {}).get('name', '无匹配资源')
        conclusion = f"道具{item['id']}「{name}」由{item['thunk']}进入此桥接，以ECX传游戏对象并调用{item['business_thunk']}到{item['business_target']}。"
        unknown = f"道具{item['id']}业务目标{item['business_target']}未因桥接核对而完成语义审阅；500..503另见人工记录。"
        document = '04_动作入口与资源导航.txt'
    elif ea in replies:
        status = '回复桥接已核对'
        item = replies[ea]
        conclusion = f'{item[0]}登记入口{item[1]}经本桥接转thiscall目标{item[4]}（中间跳板{item[3]}）。'
        unknown = f'{item[0]}的入队前包长验证与网络或本地产生来源不由桥接本身证明。'
        document = '02_超级地雷请求到清理.txt' if item[0] in ['0x40ee','0x6006','0x601a','0x6061'] else '03_直接卡片与扩展边界.txt'
    else:
        raise ValueError('缺少明确审阅状态：' + ea)
    reviews.append({'ea': ea, 'name': function['name'], 'status': status,
                    'conclusion': conclusion, 'unknown': unknown, 'document': document,
                    'evidence': 'ida_cards_raw.json/functions/' + ea})
(folder / '函数审阅清单.json').write_text(
    json.dumps(reviews, ensure_ascii=False, indent=2) + '\n', encoding='utf8')

lines = ['// 道具动作入口与资源导航 / 92项代码写表映射', '//',
         '// 802E00写AB5368+id*4；使用注册指令恢复，未读取运行期函数指针。',
         '// 各项业务语义除500..503外仍待逐函数审阅，不能将本导航计为92种效果完成。', '//']
for item in raw['operation_table']:
    resource = resources.get(item['id'], {})
    lines.extend([f"// ID {item['id']}  {resource.get('name', '无匹配资源')}  icon={resource.get('icon', '未配置')}",
                  f"//   写入 {item['write_ea']} -> 槽 {item['slot_address']}",
                  f"//   {item['thunk']} -> {item['target']} -> {item['business_thunk']} -> {item['business_target']}",
                  f"//   类型 {resource.get('type')}/{resource.get('chType')}；enable={resource.get('enable')}；cm/pk/hb={resource.get('cm')}/{resource.get('pk')}/{resource.get('hb')}", '//'])
(folder / '04_动作入口与资源导航.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
summary = {'functions': len(checks), 'matched': verification['matched_functions'],
           'regions': len(regions), 'matched_regions': sum(item['match'] for item in regions),
           'operations': len(operations), 'resource_missing': [item['id'] for item in bindings if not item['resource']],
           'states': {state: sum(item['status'] == state for item in reviews)
                      for state in sorted({item['status'] for item in reviews})}}
print(json.dumps(summary, ensure_ascii=True))
assert all(item['match'] for item in checks + regions), '字节核验失败'
assert len(notes) == sum(item['status'] == '静态局部语义已审阅' for item in reviews)
