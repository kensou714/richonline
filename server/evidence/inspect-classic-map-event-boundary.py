"""只读枚举经典 EMP 尾部原始数组，不赋予未验证的新闻池语义。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay
import pefile

ROOT = Path(__file__).resolve().parents[2]


def inspect_map(path):
    raw = path.read_bytes()
    version = struct.unpack_from('<I', raw, 16)[0]
    if version not in (1, 2, 3):
        raise ValueError(f'{path.name}: unsupported EMP version')
    metadata = 3 + 2 * (version >= 2) + (version >= 3)
    width, height = struct.unpack_from('<II', raw, 23288 + (metadata - 2) * 4)
    packed = raw[23288 + metadata * 4 + 120:]
    decoded = bytes((value - packed[0]) & 255 for value in packed[1:])
    size, compressed_size = struct.unpack_from('<II', decoded)
    if len(decoded) != compressed_size + 8:
        raise ValueError(f'{path.name}: invalid packed length')
    data = lzokay.decompress(decoded[8:], size)
    background_width, background_height = struct.unpack_from('<ii', data, 8)
    decorations_offset = 16 + background_width * background_height * 4 + width * height * 64
    decorations = struct.unpack_from('<I', data, decorations_offset)[0]
    tail = decorations_offset + 4 + decorations * 36 + width * height * 92
    cursor = tail + 120

    def word():
        nonlocal cursor
        value = struct.unpack_from('<i', data, cursor)[0]
        cursor += 4
        return value

    def array(stride=1):
        offset = cursor - tail
        count = word()
        if count < 0 or count * stride > (len(data) - cursor) // 4:
            raise ValueError(f'{path.name}: invalid array at {offset}')
        values = [[word() for _ in range(stride)] for _ in range(count)]
        return {'count_offset': offset, 'count': count,
                'values': [row[0] for row in values] if stride == 1 else values}

    source = array()
    cards = array(2)
    pools = [array(), array()] if cards['count'] else []
    extra = [array(), array()]
    postlude_offset = cursor - tail
    postlude = [word() for _ in range(11)]
    card_ids = {row[0] for row in cards['values']}
    return {'map': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
            'version': version, 'width': width, 'height': height, 'tail_offset': tail,
            'source_dword_array': source, 'card_count': cards['count'],
            'pool_counts': [pool['count'] for pool in pools], 'source_extra_arrays': extra,
            'extra0_all_in_card_table': all(value in card_ids for value in extra[0]['values']),
            'postlude_offset': postlude_offset, 'source_postlude': postlude}


def main():
    loader = json.loads(Path(__file__).with_name('classic-map-event-loader.json').read_text(encoding='utf-8'))
    client = (ROOT / 'RnClient.exe').read_bytes()
    pe = pefile.PE(data=client)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    function = loader['function_bytes']
    start, end = int(function['start'], 16), int(function['end'], 16)
    function_hash = hashlib.sha256(pe.get_data(start - image_base, end - start)).hexdigest()
    if function_hash != function['sha256']:
        raise ValueError('On-disk map loader differs from IDA evidence')
    for address, _, encoded in loader['assembly_excerpt']:
        expected = bytes.fromhex(encoded)
        if pe.get_data(int(address, 16) - image_base, len(expected)) != expected:
            raise ValueError(f'On-disk instruction differs at {address}')
    pe.close()
    maps = [inspect_map(path) for path in sorted((ROOT / 'Map').glob('CM*.emp'))]
    if not maps:
        raise ValueError('No classic EMP files found')
    result = {'scope': 'Static on-disk resource inventory; array gameplay consumers unproven',
              'client_sha256': hashlib.sha256(client).hexdigest(),
              'loader_function_sha256': function_hash, 'loader_matches_ida': True,
              'loader': 'NEW 0x7DF010', 'map_count': len(maps), 'maps': maps}
    output = Path(__file__).with_name('classic-map-event-boundary.json')
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'maps': len(maps), 'output': str(output)}, ensure_ascii=True))


if __name__ == '__main__':
    main()
