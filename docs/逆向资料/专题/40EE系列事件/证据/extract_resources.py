"""只读提取本专题引用的 KPD 文本块及来源指纹。"""
from pathlib import Path
import hashlib
import json
import re
import struct
import lzokay

OUT = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[5]
SELECTED = {'Prop': set(range(500, 515)) | {1130, 1131},
            'RichStr': {40, 41, 330, 331, 332, 342, 346, 347, 348, 349, 350, 351, 352,
                        805, 806, 807, 808, 809, 810, 1056, 1057, 1058, 1069, 1070, 1071, 1072}
                       | set(range(311, 319))}

def main():
    sources, selected = [], {}
    for name, ids in SELECTED.items():
        relative = f'Data/{name}.kpd'
        raw = (ROOT/relative).read_bytes()
        decoded = bytes((x-raw[0]) & 255 for x in raw[1:])
        size, compressed_size = struct.unpack_from('<II', decoded)
        assert compressed_size == len(decoded)-8
        plain = lzokay.decompress(decoded[8:], size)
        assert len(plain) == size
        text = plain.decode('cp950', errors='strict')
        marker = 'PROP' if name == 'Prop' else 'ITEM'
        blocks = {}
        for block in text.split(f'[{marker}]')[1:]:
            match = re.search(r'^\s*indx\s*=\s*(\d+)', block, re.M)
            if match and int(match[1]) in ids:
                blocks[match[1]] = f'[{marker}]\n'+block.strip()
        selected[name] = blocks
        assert set(map(int,blocks)) == ids, (name, sorted(ids-set(map(int,blocks))))
        sources.append(dict(source=relative, source_bytes=len(raw), key=raw[0],
                            source_sha256=hashlib.sha256(raw).hexdigest(),
                            decoded_bytes=size, decoded_sha256=hashlib.sha256(plain).hexdigest(),
                            encoding='CP950严格解码', selected_ids=sorted(ids)))
    result = dict(provenance=sources, selected_blocks=selected,
                  limit='资源原文支持显示内容；描述中的规则效果须与函数/消费者/实机另行核对')
    (OUT/'resource_semantics.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'resources={len(sources)} blocks={sum(len(x) for x in selected.values())}')

if __name__ == '__main__':
    main()
