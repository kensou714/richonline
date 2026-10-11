"""只读核对原客户端字节及 EMP 医院／监狱坐标，不启动游戏或执行玩法测试。"""
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
        raise ValueError(f'{path.name}: unsupported version')
    metadata = 3 + 2 * (version >= 2) + (version >= 3)
    width, height = struct.unpack_from('<II', raw, 23288 + (metadata - 2) * 4)
    packed = raw[23288 + metadata * 4 + 120:]
    decoded = bytes((value - packed[0]) & 255 for value in packed[1:])
    size, compressed_size = struct.unpack_from('<II', decoded)
    if len(decoded) != compressed_size + 8:
        raise ValueError(f'{path.name}: invalid packed length')
    data = lzokay.decompress(decoded[8:], size)
    background_width, background_height = struct.unpack_from('<II', data, 8)
    terrain = 16 + background_width * background_height * 4
    decorations_offset = terrain + width * height * 64
    decorations = struct.unpack_from('<I', data, decorations_offset)[0]
    tail = decorations_offset + 4 + decorations * 36 + width * height * 92
    record = {'map': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
              'width': width, 'height': height, 'tail_offset': tail}
    for name, offset in [('hospital', 0), ('jail', 32)]:
        points = [struct.unpack_from('<ii', data, tail + offset + i * 8) for i in range(2)]
        terrain_types = [struct.unpack_from('<b', data, terrain + (y * width + x) * 64)[0]
                         if 0 <= x < width and 0 <= y < height else None for x, y in points]
        delta = (points[1][0] - points[0][0], points[1][1] - points[0][1])
        directions = {(0, 2): 0, (0, -1): 2, (-1, 0): 1, (2, 0): 3}
        valid = all(value is not None for value in terrain_types)
        record[name] = {'points': points, 'terrain': terrain_types,
                        'exit_direction': directions.get(delta) if valid else None,
                        'available': valid and terrain_types[1] != -1 and delta in directions}
    return record


def main():
    evidence = json.loads(Path(__file__).with_name('facility-exit-client.json').read_text(encoding='utf-8'))
    client = (ROOT / 'RnClient.exe').read_bytes()
    pe = pefile.PE(data=client)
    base = pe.OPTIONAL_HEADER.ImageBase
    instructions = 0
    for function in evidence['functions']:
        start, end = int(function['start'], 16), int(function['end'], 16)
        if hashlib.sha256(pe.get_data(start - base, end - start)).hexdigest() != function['sha256']:
            raise ValueError(f'Client function differs at {start:x}')
        for instruction in function['instructions']:
            expected = bytes.fromhex(instruction['bytes'])
            if pe.get_data(int(instruction['address'], 16) - base, len(expected)) != expected:
                raise ValueError(f'Client instruction differs at {instruction["address"]}')
            instructions += 1
    pe.close()
    maps = [inspect_map(path) for path in sorted((ROOT / 'Map').glob('*.emp'))]
    if not maps:
        raise ValueError('No EMP resources found')
    result = {'scope': 'Static original resource and executable inspection only',
              'client_sha256': hashlib.sha256(client).hexdigest(),
              'functions_matched': len(evidence['functions']), 'instructions_matched': instructions,
              'map_count': len(maps), 'maps': maps}
    output = Path(__file__).with_name('facility-map-geometry.json')
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'maps': len(maps), 'functions': len(evidence['functions']),
                      'instructions': instructions,
                      'available': {name: sum(row[name]['available'] for row in maps)
                                    for name in ['hospital', 'jail']}}))


if __name__ == '__main__':
    main()
