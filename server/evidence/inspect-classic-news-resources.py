"""只读提取NEW新闻UI初始化表与本机纹理映射；不运行服务端或游戏场景。"""
from pathlib import Path
import hashlib
import json
import re
import struct
import lzokay

ROOT = Path(__file__).resolve().parents[2]


def main():
    evidence_path = Path(__file__).with_name('classic-news-initialization.json')
    evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
    assert hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest() == evidence['client_sha256']
    loader = '\n'.join(evidence['functions']['0x718de0']['pseudocode'])
    pairs = [(int(slot) - 18, int(texture)) for slot, texture in re.findall(
        r'\*\(this \+ (\d+)\) = sub_60F3B5\(a1: 10, a2: 10, a3: (\d+), a4: -1\);', loader)
        if 18 <= int(slot) < 118]
    assert len(pairs) == 29 and len({slot for slot, _ in pairs}) == 29
    raw = (ROOT / 'Tex/other.dat').read_bytes()
    decoded = bytes((value - raw[0]) & 255 for value in raw[1:])
    size, packed = struct.unpack_from('<II', decoded)
    assert len(decoded) == 8 + packed
    text_bytes = lzokay.decompress(decoded[8:], size)
    content = text_bytes.decode('cp950')
    assert content.encode('cp950') == text_bytes
    sections = {}
    current = None
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            assert current not in sections
            sections[current] = {}
        elif current and '=' in line:
            key, value = line.split('=', 1)
            sections[current][key.strip()] = value.strip()
    # 原加载器遇到缺节即停止，故不仅核对目标节，也核对到目标的连续前缀。
    assert all(f'OTHER_{group}' in sections for group in range(11))
    assert all(f'O_10_S_{index}' in sections for index in range(1 + max(t for _, t in pairs)))
    pictures = []
    for slot, texture in pairs:
        section = f'O_10_S_{texture}'
        npid = int(sections[section]['npid'])
        relative = f'Tex/{npid // 500:02d}/{npid:05d}.np'
        image = (ROOT / relative).read_bytes()
        pictures.append(dict(picture=slot, texture=texture, section=section, npid=npid,
                             path=relative, bytes=len(image), sha256=hashlib.sha256(image).hexdigest()))
    evidence['resources'] = dict(path='Tex/other.dat', sha256=hashlib.sha256(raw).hexdigest(),
                                 decoded_sha256=hashlib.sha256(text_bytes).hexdigest(),
                                 groups_0_through_10_contiguous=True,
                                 group10_items_0_through_63_contiguous=True, pictures=pictures,
                                 scope='On-disk mapping and NP file presence; no runtime rendering assertion')
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(pictures=len(pictures), output=str(evidence_path)), ensure_ascii=False))


if __name__ == '__main__':
    main()
