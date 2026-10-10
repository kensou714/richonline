"""有限域参考模型；重现颜色入口循环，不冒充完整CRT或客户端实机执行。"""
import math
import re


def parse_hex(raw):
    """只接收首部0x和最多32个后续ASCII字节；返回低32位位型。"""
    if raw is None:
        return 0
    if isinstance(raw, str):
        raw = raw.split('\0', 1)[0].encode('ascii', errors='strict')
    raw = raw.split(b'\0', 1)[0]
    if not raw.isascii():
        raise ValueError('非ASCII输入超出有限模型域')
    if not raw:
        return 0
    if not raw.startswith(b'0x'):
        raise ValueError('非小写0x首部由atof路径处理，不在十六进制模型域内')
    if len(raw)-2 > 32:
        raise ValueError('超出有限模型域；不模拟极长输入的CRT浮点状态和内存边界')
    index, total = len(raw)-1, 0
    exponent = 9-index
    while index > 1:
        character = raw[index]
        if 48 <= character <= 57:
            digit = character-48
        elif 65 <= character <= 70:
            digit = character-55
        elif 97 <= character <= 102:
            digit = character-87
        else:
            digit = None
        if digit is not None:
            # 先对16^e截断，再乘当前位；负指数在本域内为有限小数，转成0。
            weight = int(math.pow(16.0, exponent))
            total = (total+digit*weight) & 0xFFFFFFFF
        index -= 1
        exponent += 1
    return total


def parse_decimal_subset(raw):
    """只模拟严格普通十进制、至多6位小数和有符号32位范围内的有限数。"""
    if not re.fullmatch(r'[+-]?[0-9]{1,10}(?:\.[0-9]{1,6})?', raw):
        raise ValueError('不模拟atof的空白、指数、locale、尾随文本或非有限输入')
    number = float(raw)
    if not -(2**31) <= number <= 2**31-1:
        raise ValueError('不模拟超出所选十进制域的转换')
    return math.trunc(number) & 0xFFFFFFFF


def expected_hex_by_positions(raw):
    """独立位置模型：前8个位置各占4位，非法位按0，短串右补0。"""
    digits = raw[2:10].ljust(8, '_')
    return int(''.join(c if c in '0123456789abcdefABCDEF' else '0' for c in digits), 16)


def verify_model():
    cases = {
        '0x': 0, '0x1': 0x10000000, '0x12': 0x12000000,
        '0x1234567': 0x12345670, '0x12345678': 0x12345678,
        '0x123456789': 0x12345678, '0x000000001': 0,
        '0xffffffff': 0xFFFFFFFF, '0xAbCdEf01': 0xABCDEF01,
        '0x1g3': 0x10300000, '0x 1': 0x01000000,
        '0x-1': 0x01000000, '0x1 ': 0x10000000,
    }
    for raw, expected in cases.items():
        assert parse_hex(raw) == expected
    assert parse_hex(None) == 0 and parse_hex('') == 0
    assert parse_hex(b'0x1\0ffff') == 0x10000000
    assert parse_hex(b'0x1\0\xff') == 0x10000000
    assert parse_hex('0x1\0\u00ff') == 0x10000000
    for raw in [b'0x\xff', '0x\u00ff']:
        try:
            parse_hex(raw)
        except ValueError:
            pass
        else:
            raise AssertionError('非ASCII输入必须拒绝')
    # 枚举每个位置与所有ASCII字节，保持长度信息并检查非法位仍消耗位置。
    checked = 0
    for width in range(1, 33):
        for position in range(width):
            for character in range(1, 128):
                raw = '0x'+'0'*position+chr(character)+'0'*(width-position-1)
                assert parse_hex(raw) == expected_hex_by_positions(raw)
                checked += 1
    decimals = {'0': 0, '1.9': 1, '-1.9': 0xFFFFFFFF, '2147483647': 0x7FFFFFFF,
                '-2147483648': 0x80000000, '+12.25': 12}
    for raw, expected in decimals.items():
        assert parse_decimal_subset(raw) == expected
    for raw in ['0X1', ' 0x1', '-0x1']:
        try:
            parse_hex(raw)
        except ValueError:
            pass
        else:
            raise AssertionError(raw)
    return {'hex_examples': cases, 'decimal_examples': decimals, 'position_cases': checked,
            'scope': '参考模型与静态公式互证；没有调用原EXE的CRT，非客户端实机验证'}


if __name__ == '__main__':
    import json
    print(json.dumps(verify_model(), ensure_ascii=False))
