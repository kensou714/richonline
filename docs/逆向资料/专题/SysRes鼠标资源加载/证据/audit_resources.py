"""只读核当前光标目录结构与PE导入表；不调用Windows加载接口或更改资源。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def inspect_resources():
    rows = []
    for path in sorted((ROOT / 'SysRes').glob('04_*.ms')):
        data = path.read_bytes()
        reserved, kind, count = struct.unpack_from('<3H', data)
        assert reserved == 0 and kind == 2 and count > 0
        assert 6 + 16 * count <= len(data)
        entries = []
        for i in range(count):
            width, height, colors, pad, hot_x, hot_y, size, offset = struct.unpack_from('<4B2H2I', data, 6 + 16 * i)
            width, height = width or 256, height or 256
            assert pad == 0 and hot_x < width and hot_y < height
            assert offset >= 6 + 16 * count and size > 0 and offset + size <= len(data)
            dib_size, dib_w, dib_h, planes, bits, compression, image_size, xppm, yppm, used, important = struct.unpack_from('<IiiHHIIiiII', data, offset)
            assert dib_size == 40 and dib_w == width and dib_h == height * 2 and planes == 1
            assert compression == 0 and bits in (1, 4, 8, 24, 32)
            palette = (used or (1 << bits)) if bits <= 8 else 0
            xor_bytes = ((width * bits + 31) // 32) * 4 * height
            and_bytes = ((width + 31) // 32) * 4 * height
            assert dib_size + palette * 4 + xor_bytes + and_bytes == size
            entries.append(dict(width=width, height=height, hotspot=[hot_x, hot_y], resource_size=size, resource_offset=offset,
                                dib_header_size=dib_size, dib_height=dib_h, bits_per_pixel=bits, compression=compression,
                                palette_entries=palette, xor_bytes=xor_bytes, and_bytes=and_bytes))
        assert max(e['resource_offset'] + e['resource_size'] for e in entries) == len(data)
        rows.append(dict(path=path.relative_to(ROOT).as_posix(), filename_index=int(path.stem[3:]), size=len(data),
                         sha256=hashlib.sha256(data).hexdigest(), header_hex=data[:22].hex(), cursor_type=kind, entries=entries))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sec = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, sec + 40 * i + 8) for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    def disk(rva, size):
        matches = [(r, o) for _, r, n, o in sections if r <= rva and rva + size <= r + n]
        assert len(matches) == 1
        r, o = matches[0]
        return blob[o + rva - r:o + rva - r + size]
    def cstr(rva):
        result = bytearray()
        for i in range(4096):
            char = disk(rva + i, 1)
            if char == b'\0':
                return result.decode('ascii')
            result.extend(char)
        raise AssertionError('PE导入字符串缺少终止')
    wanted = {0xAD3F38:'LoadImageA', 0xAD3F3C:'LoadCursorA', 0xAD3F88:'SetCursor', 0xAD3F8C:'MessageBoxA', 0xAD3ACC:'DeleteObject'}
    rva = struct.unpack_from('<I', blob, pe + 128)[0]
    imports = []
    for i in range(1024):
        original, stamp, forward, name, first = struct.unpack('<5I', disk(rva + 20 * i, 20))
        if not any((original, stamp, forward, name, first)):
            break
        for index in range(65536):
            lookup = struct.unpack('<I', disk((original or first) + index * 4, 4))[0]
            if lookup == 0:
                break
            va = base + first + index * 4
            if va not in wanted:
                continue
            assert not lookup & 0x80000000
            symbol = cstr(lookup + 2)
            assert symbol == wanted[va]
            imports.append(dict(iat_va=hex(va), dll=cstr(name), symbol=symbol, disk_iat_hex=disk(first+index*4,4).hex(),
                                descriptor_rva=hex(rva+20*i), lookup_rva=hex((original or first)+index*4), name_rva=hex(lookup+2)))
    assert len(imports) == len(wanted)
    return dict(status='PASS', disk_sha256=SHA, resource_count=len(rows), resources=rows, imports=imports,
                boundary='当前磁盘CUR结构与编号；未调用LoadImage/LoadCursor、未验证系统接受或图像外观；IAT磁盘值不等同运行目标。')


if __name__ == '__main__':
    result = inspect_resources()
    (HERE / 'resource_audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(status=result['status'], resources=result['resource_count'], imports=len(result['imports']))))
