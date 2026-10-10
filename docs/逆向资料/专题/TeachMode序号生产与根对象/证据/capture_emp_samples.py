"""只读抽取三个代表EMP的已证头字段，不实现完整地图解析或修改资源。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FILES = ('Map/BS_1_1.emp', 'Map/CM_CS_2.emp', 'Map/TC_CM_1.emp')


def main():
    cursor = 0 + 16
    version_offset = cursor
    cursor += 4 + 23268
    mode_offset = cursor
    cursor += 4
    offsets = (cursor, cursor + 4, cursor + 8)
    assert (version_offset, mode_offset, *offsets) == (16, 23288, 23292, 23296, 23300)
    samples = []
    for name in FILES:
        data = (ROOT / name).read_bytes()
        assert len(data) >= offsets[-1] + 4, name
        version = struct.unpack_from('<i', data, version_offset)[0]
        fields = []
        for offset, member, minimum in ((mode_offset, 24, None),
                                        (offsets[0], 104, 2),
                                        (offsets[1], 108, 2),
                                        (offsets[2], 112, 3)):
            raw = data[offset:offset + 4]
            enabled = minimum is None or version >= minimum
            fields.append(dict(file_offset=offset, map_offset_if_gate_passes=member, width=4,
                               hex=raw.hex(), uint32=struct.unpack('<I', raw)[0],
                               read_by_proven_header_path=enabled,
                               interpretation='已证正常头路径目标' if enabled else '仅观察同一文件位置；不能赋给该Map成员',
                               signed_version_minimum=minimum))
        samples.append(dict(path=name, sha256=hashlib.sha256(data).hexdigest(),
                            length=len(data), version_offset=version_offset,
                            version_hex=data[version_offset:version_offset + 4].hex(),
                            version_int32=version, fields=fields))
    result = dict(scope='仅三文件已证头字段，不作全资源或官方业务语义判定',
                  offset_assumption='fopen起始0，两次SEEK_CUR成功且前序4×1读取完整',
                  source='load_source_raw.json/functions/0x7df010/0x7df0c4..0x7df17e',
                  samples=samples)
    (HERE / 'emp_header_samples.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(samples, ensure_ascii=True))


if __name__ == '__main__':
    main()
