"""只读统计当前经典地图的布局和开局输入，不运行服务端或测试场景。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

ROOT = Path(__file__).resolve().parents[2]


def word(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def unpack(data):
    decoded = bytes((value - data[0]) & 255 for value in data[1:])
    size, packed = struct.unpack_from('<II', decoded)
    return lzokay.decompress(decoded[8:8 + packed], size)


def main():
    maps = []
    for file in sorted((ROOT / 'Map').glob('*.emp')):
        raw = file.read_bytes()
        if word(raw, 23288) != 0:
            continue
        version = word(raw, 16)
        metadata = 3 + (2 if version >= 2 else 0) + (1 if version >= 3 else 0)
        width = word(raw, 23288 + (metadata - 2) * 4)
        height = word(raw, 23288 + (metadata - 1) * 4)
        data = unpack(raw[23288 + metadata * 4 + 120:])
        terrain = 16 + word(data, 8) * word(data, 12) * 4
        decoration = terrain + width * height * 64
        tile_types = decoration + 4 + word(data, decoration) * 36
        properties = tile_types + width * height * 4
        tail = properties + width * height * 88
        sprites = {}
        for tile in range(width * height):
            sprite = data[properties + tile * 88]
            if sprite in (11, 12):
                sprites[str(sprite)] = sprites.get(str(sprite), 0) + 1
        stock_count = word(data, tail + 120)
        maps.append(dict(name=file.name, sha256=hashlib.sha256(raw).hexdigest(), version=version,
                         width=width, height=height, property_sprites=sprites,
                         base_funds=list(struct.unpack_from('<3I', data, tail + 104)),
                         monetary_scale=word(data, tail + 116),
                         stock_configurations=list(struct.unpack_from('<' + str(stock_count) + 'I', data, tail + 124))))
    resources = {name: hashlib.sha256((ROOT / 'Data' / name).read_bytes()).hexdigest()
                 for name in ('Option.kpd', 'Pawn.kpd', 'Stock.kpd', 'Prop.kpd')}
    result = dict(scope='Read-only resource inventory; no C++ execution or gameplay validation',
                  resources=resources, maps=maps)
    output = Path(__file__).with_name('classic-startup-resources.json')
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(maps=len(maps), versions=sorted({m['version'] for m in maps}),
                          output=str(output)), ensure_ascii=False))


if __name__ == '__main__':
    main()
