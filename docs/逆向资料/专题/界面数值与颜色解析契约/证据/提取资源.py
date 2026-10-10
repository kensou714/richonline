"""只读变换实际UI样本，保存颜色值、所在节、行号与原始字节指纹。"""
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SELECTED = ['Interface/G_Bank.ui', 'Interface/L_MyInfo.ui', 'Interface/L_PlayerInfo.ui']


def decode(blob):
    # 沿用界面系统专题已核对的9105D0规则；.ui不是KPD压缩容器。
    key = b'RichNet'
    plain = bytes((value-key[index % len(key)]) & 255 for index, value in enumerate(blob))
    return plain


def show(raw):
    try:
        return raw.decode('ascii', errors='strict')
    except UnicodeDecodeError:
        return 'hex:'+raw.hex()


def colors(plain):
    section, headers, records = None, {}, []
    for number, line in enumerate(plain.split(b'\n'), 1):
        stripped = line.strip()
        if stripped.startswith(b'[') and stripped.endswith(b']'):
            section, headers = show(stripped[1:-1]), {}
        elif b'=' in line and not stripped.startswith((b'//', b';')):
            key, value = (show(part.strip()) for part in line.split(b'=', 1))
            headers[key] = value
            if key.lower().endswith('color'):
                records.append(dict(section=section, line=number, key=key, value=value,
                                    raw_line=show(line), raw_line_hex=line.hex(), prior_fields=dict(headers)))
    return records


def main():
    records = []
    for source in SELECTED:
        blob = (ROOT / source).read_bytes()
        plain = decode(blob)
        records.append(dict(source=source, source_sha256=hashlib.sha256(blob).hexdigest(),
                            source_bytes=len(blob), key_ascii='RichNet',
                            transform='(cipher[i]-key[i%7])&255', decoded_bytes=len(plain),
                            field_view='ASCII；非ASCII字段显示hex，不猜全文编码',
                            decoded_sha256=hashlib.sha256(plain).hexdigest(), colors=colors(plain)))
    (HERE / 'resource_samples.json').write_text(json.dumps(dict(records=records), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({r['source']: len(r['colors']) for r in records}, ensure_ascii=False))


if __name__ == '__main__':
    main()
