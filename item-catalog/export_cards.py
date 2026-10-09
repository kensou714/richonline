"""Read-only extraction of the game's card catalog and original NP artwork."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import re
import struct
from pathlib import Path
from PIL import Image


class Decoder:
    def __init__(self, root: Path):
        library = root / 'resource-manager/native/ResourceCodec.dll'
        if not library.exists():
            library = root / 'ResourceCodec.dll'
        self.lib = ctypes.CDLL(str(library))
        self.lib.resource_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]

    def unpack(self, path: Path) -> bytes:
        return self.unpack_bytes(path.read_bytes())

    def unpack_bytes(self, data: bytes) -> bytes:
        if not 9 <= len(data) <= 128 * 1024 * 1024:
            raise ValueError('Invalid packed file')
        shifted = bytes((b - data[0]) % 256 for b in data[1:])
        size, count = struct.unpack_from('<II', shifted)
        if not 0 < size <= 64 * 1024 * 1024 or count != len(shifted) - 8:
            raise ValueError('Invalid packed lengths')
        out = ctypes.create_string_buffer(size)
        if self.lib.resource_decompress(shifted[8:], count, out, size) != 0:
            raise ValueError('Decompression failed')
        return out.raw

    def picture(self, path: Path) -> Image.Image:
        data = self.unpack(path)
        mode, width, height = struct.unpack_from('<BII', data)
        if not 0 < width * height <= 1024 * 1024:
            raise ValueError(f'Invalid picture dimensions: {path}')
        size = width * height
        if mode == 2:
            return Image.frombytes('RGBA', (width, height), data[9:9 + size * 4], 'raw', 'BGRA')
        if mode != 1:
            raise ValueError(f'Unsupported picture mode: {path}')
        frames, alpha = struct.unpack_from('<IB', data, 9)
        if frames < 1 or (frames > 1 and alpha):
            raise ValueError(f'Unsupported transparent animation: {path}')
        required = 14 + 768 + size * (2 if alpha else 1)
        if len(data) < required:
            raise ValueError(f'Truncated picture: {path}')
        palette, indices = data[14:782], data[782:782 + size]
        pixels = bytearray(size * 4)
        for i, index in enumerate(indices):
            rgb = palette[index * 3:index * 3 + 3]
            opacity = 0 if rgb == b'\x00\xff\x00' else data[782 + size + i] if alpha else 255
            pixels[i * 4:i * 4 + 4] = rgb + bytes([opacity])
        return Image.frombytes('RGBA', (width, height), pixels)


def records(text: str):
    current = None
    for line in text.splitlines():
        section = re.fullmatch(r'\s*\[([^]]+)\]\s*', line)
        if section:
            if current is not None:
                yield current
            current = {'section': section[1]}
        elif current is not None and '=' in line and not line.lstrip().startswith(('//', '#', ';')):
            key, value = line.split('=', 1)
            current[key.strip()] = value.strip()
    if current is not None:
        yield current


def simplified(text: str) -> str:
    if not text:
        return text
    result = ctypes.create_unicode_buffer(len(text) * 2 + 1)
    count = ctypes.windll.kernel32.LCMapStringEx('zh-CN', 0x02000000, text, len(text), result, len(result), None, None, 0)
    if not count:
        raise ctypes.WinError()
    return result[:count].translate(str.maketrans({'後': '后', '麽': '么', '麼': '么', '裡': '里'}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent / 'public')
    args = parser.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'images').mkdir(exist_ok=True)
    decoder = Decoder(root)
    mapping = {r['section']: int(r['npid']) for r in records(decoder.unpack(root / 'Tex/card.dat').decode('gbk'))}
    cards, image_ids = [], set()
    for item in records(decoder.unpack(root / 'Data/Prop.kpd').decode('cp950')):
        if item.get('type') != 'CARD':
            continue
        icon = int(item['icon']) if item.get('icon') else None
        npid = mapping.get(f'CARD_{icon}') if icon is not None else None
        path = root / f'Tex/{npid // 500:02}/{npid:05}.np' if npid is not None else None
        image = decoder.picture(path) if path is not None and path.exists() else None
        if image is not None and npid not in image_ids:
            image.save(out / f'images/{npid}.png', optimize=True)
            image_ids.add(npid)
        cards.append({
            'id': int(item['indx']), 'name': item['name'], 'description': item.get('desc', ''),
            'nameSimplified': simplified(item['name']), 'descriptionSimplified': simplified(item.get('desc', '')),
            'sourceType': item.get('chType'),
            'enabled': item.get('enable', '').split(',')[0].lower() == 'true',
            'shopSale': item.get('saleG') == 'true',
            'shopPrice': int(item['priceG']) if item.get('priceG') else None,
            'image': f'images/{npid}.png' if image is not None else None,
            'imageStatus': 'available' if image is not None else 'missing',
            'width': image.width if image is not None else None, 'height': image.height if image is not None else None,
            'source': {'icon': icon, 'npid': npid, 'file': path.relative_to(root).as_posix() if path else None},
        })
    cards.sort(key=lambda c: c['id'])
    if not cards or len({c['id'] for c in cards}) != len(cards):
        raise ValueError('Empty catalog or duplicate card IDs')
    dataset = {'cards': cards, 'sourceFiles': {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in ['Data/Prop.kpd', 'Tex/card.dat']}}
    serialized = json.dumps(dataset, ensure_ascii=False, separators=(',', ':'))
    (out / 'cards.json').write_text(serialized, encoding='utf-8')
    (out / 'cards.js').write_text('window.CARD_CATALOG=' + serialized.replace('<', '\\u003c') + ';\n', encoding='utf-8')
    print(json.dumps({'cards': len(cards), 'images': len(image_ids), 'missingImages': sum(c['image'] is None for c in cards), 'output': str(out)}, ensure_ascii=True))


if __name__ == '__main__':
    main()
