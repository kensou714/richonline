"""按当前32位指令契约核对有限可读输入；不执行原函数、不仿真线程依赖。"""


def convert(data, classification):
    if len(classification) != 256:
        raise ValueError('分类表必须有256项')
    position = 0

    def byte_at(index):
        if index >= len(data):
            raise ValueError('模型拒绝超出可读输入，不代表原函数会拒绝')
        return data[index]

    while classification[byte_at(position)] & 8:
        position += 1
    character = byte_at(position)
    sign = character
    position += 1
    if character in (43, 45):
        character = byte_at(position)
        position += 1
    result = 0
    while 48 <= character <= 57:
        result = (result * 10 + character - 48) & 0xFFFFFFFF
        character = byte_at(position)
        position += 1
    if sign == 45:
        result = (-result) & 0xFFFFFFFF
    return result if result < 0x80000000 else result - 0x100000000


def ascii_classification():
    table = [0] * 256
    for value in (9, 10, 11, 12, 13, 32):
        table[value] = 8
    return table


def verify_samples():
    table = ascii_classification()
    cases = {
        b'': 0, b'0': 0, b'123': 123, b'  \t-42x': -42,
        b'+ 7': 0, b'--7': 0, b'-': 0, b'abc': 0, b'12abc': 12,
        b'0x10': 0, b'1.5': 1, b'2147483647': 2147483647,
        b'2147483648': -2147483648, b'4294967295': -1, b'4294967296': 0,
        b'-2147483648': -2147483648, b'-2147483649': 2147483647,
        b'\x80' + b'12': 0, b'\xef\xbc\x91': 0,
    }
    for data, expected in cases.items():
        assert convert(data + b'\0', table) == expected
    # 以任意精度整数独立核对低32位，覆盖长度、符号及停止字符。
    checked = 0
    for length in range(1, 101):
        digits = bytes(48 + ((index * 7 + length) % 10) for index in range(length))
        number = int(digits)
        for sign in (b'', b'+', b'-'):
            signed = -number if sign == b'-' else number
            expected = signed % (1 << 32)
            if expected >= 1 << 31:
                expected -= 1 << 32
            for tail in (b'\0', b'x\0', b' \0'):
                assert convert(b' \t' + sign + digits + tail, table) == expected
                checked += 1
    alternate = table.copy()
    alternate[0xA0] = 8
    assert convert(b'\xA012\0', table) == 0
    assert convert(b'\xA012\0', alternate) == 12
    failures = 0
    for data in (b'', b'+', b'123'):
        try:
            convert(data, table)
        except ValueError:
            failures += 1
    assert failures == 3
    return dict(named_cases=len(cases), arbitrary_precision_cases=checked,
                locale_model_cases=2, bounded_input_rejections=failures,
                limitation='表驱动32位边界模型；不是机器码仿真或真实locale测试。')


if __name__ == '__main__':
    print(verify_samples())
