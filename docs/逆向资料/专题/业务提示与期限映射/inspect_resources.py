"""只读提取提示1120..1129及UI71；保存原文、严格编码往返和资源身份。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sections = runpy.run_path(str(ROOT / 'docs/逆向资料/专题/提示文本生命周期/inspect_resources.py'))['sections']


def decode(relative):
    source = (ROOT / relative).read_bytes()
    if relative.endswith('.kpd'):
        key = source[0]
        expanded, packed = struct.unpack('<II', bytes((b-key) & 255 for b in source[1:9]))
        assert 0 < expanded <= 64 * 1024 * 1024 and packed == len(source)-9
        plain = lzokay.decompress(bytes((b-key) & 255 for b in source[9:]), expanded)
        assert len(plain) == expanded
    else:
        key = b'RichNet'
        plain = bytes((b-key[i % len(key)]) & 255 for i, b in enumerate(source))
    codec = 'gbk' if relative == 'Interface/Intf.kpd' else 'cp950'
    text = plain.decode(codec, errors='strict')
    assert text.encode(codec) == plain
    return dict(source=relative, source_sha256=hashlib.sha256(source).hexdigest(),
                source_size=len(source), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                codec=codec, strict_roundtrip=True, sections=sections(text))


def collect():
    text = decode('Data/RichStr.kpd')
    text['sections'] = [s for s in text['sections'] if s['fields'].get('indx') in {str(i) for i in range(1120, 1130)}]
    requested = {str(i) for i in range(1120, 1130)}
    present = {s['fields']['indx'] for s in text['sections']}
    text['requested_indices'] = sorted(requested, key=int)
    text['missing_indices'] = sorted(requested-present, key=int)
    intf = decode('Interface/Intf.kpd')
    intf['sections'] = [s for s in intf['sections'] if s['fields'].get('indx') == '71']
    assert len(intf['sections']) == 1
    filename = intf['sections'][0]['fields']['file']
    ui = decode('Interface/' + filename)
    prop = decode('Data/Prop.kpd')
    prop['sections'] = [s for s in prop['sections'] if s['fields'].get('indx') in {'1', '9', '13', '501', '503'}]
    result = dict(scope='当前资源只读解码；不模拟运行期窗口或网络响应', records=[text, intf, ui, prop])
    path = HERE / '证据/resources.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    collect()
