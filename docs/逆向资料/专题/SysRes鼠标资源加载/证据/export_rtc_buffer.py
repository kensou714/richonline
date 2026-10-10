"""鼠标资源路径缓冲的RTC声明补证；指针驱动有限读取，禁止覆盖。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def export():
    import ida_bytes
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    output = HERE / 'rtc_buffer_raw.json'
    assert not output.exists(), '禁止覆盖既有RTC补证'
    pe = struct.unpack_from('<I', image, 0x3c)[0]
    base = struct.unpack_from('<I', image, pe+52)[0]
    table = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, table+40*i+8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]

    def read(ea, size):
        offsets = [off+ea-base-rva for _, rva, length, off in sections
                   if 0 <= ea-base-rva and ea-base-rva+size <= length]
        assert len(offsets) == 1
        raw = ida_bytes.get_bytes(ea, size)
        disk = image[offsets[0]:offsets[0]+size]
        assert raw is not None and len(raw) == size and raw == disk
        return dict(start_va=hex(ea), size=size, idb_hex=raw.hex(), disk_hex=disk.hex(),
                    matching=True, sha256=hashlib.sha256(raw).hexdigest())

    header = read(0x6BAD03, 8)
    count, pointer = struct.unpack('<II', bytes.fromhex(header['idb_hex']))
    assert count == 1 and pointer == 0x6BAD0B, '已观察RTC描述符变化，停止扩读'
    descriptor = read(pointer, 12)
    offset, size, name_pointer = struct.unpack('<iII', bytes.fromhex(descriptor['idb_hex']))
    assert offset == -148 and size == 128 and name_pointer == 0x6BAD17
    name = bytearray()
    for index in range(256):
        unit = bytes.fromhex(read(name_pointer+index, 1)['idb_hex'])
        name.extend(unit)
        if unit == b'\0':
            break
    else:
        raise AssertionError('变量名在有限长度内无NUL')
    result = dict(schema='richonline-rtc-buffer-evidence-26-1', disk_sha256=SHA,
                  exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  frame_descriptor=header, variable_descriptor=descriptor,
                  variable_name=read(name_pointer, len(name)),
                  declared_variable_count=count, ebp_relative_offset=offset,
                  declared_buffer_size=size,
                  pending_status='RTC静态帧描述符；不等于动态栈安全或所有格式化输入均受限')
    payload = (json.dumps(result, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
    with output.open('xb') as stream:
        stream.write(payload)
    return dict(path=str(output), sha256=hashlib.sha256(payload).hexdigest(),
                buffer_size=size, offset=offset, variable_name_hex=name.hex())
