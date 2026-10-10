# -*- coding: utf-8 -*-
"""根据DIV/反转/右对齐写入的有限模型；不是原程序执行器。"""

MASK = 0xFFFFFFFF


def xtoa(value, radix, negative):
    if not 2 <= radix <= 36:
        raise ValueError("模型只覆盖合法基数2..36")
    current = value & MASK
    prefix = b""
    if negative:
        prefix = b"-"
        current = (-current) & MASK
    digits = bytearray()
    while True:
        remainder = current % radix
        current //= radix
        digits.append(remainder + (48 if remainder <= 9 else 87))
        if current == 0:
            break
    left, right = 0, len(digits)-1
    while True:
        digits[left], digits[right] = digits[right], digits[left]
        left += 1
        right -= 1
        if left >= right:
            break
    return prefix + digits + b"\0"


def ltoa(value, radix):
    signed = value & MASK
    if signed & 0x80000000:
        signed -= 1 << 32
    return xtoa(signed, radix, radix == 10 and signed < 0)


def format_value(value):
    temporary = bytearray(10)
    converted = ltoa(value, 16)
    temporary[:len(converted)] = converted
    length = temporary.index(0)
    output = bytearray(b"0x00000000\0")
    output[10-length:10] = temporary[:length]
    return bytes(output)


def parse_fixed(text):
    # 仅复用8E0450对规范8位ASCII的有限权重，不模拟其十进制或非法字符串路径。
    if len(text) != 11 or text[:2] != b"0x" or text[-1] != 0:
        raise ValueError("仅允许规范0x八位加NUL")
    result = 0
    for i, c in enumerate(text[2:10]):
        if 48 <= c <= 57:
            digit = c-48
        elif 97 <= c <= 102:
            digit = c-87
        else:
            raise ValueError("非法hex数位")
        result += digit * (16 ** (7-i))
    return result & MASK


def run_models(require):
    values = set(range(65536)) | {n << 16 for n in range(65536)}
    values |= {(n << 24) | (255-n) for n in range(256)}
    values |= {0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x12345678, 0xABCDEF01}
    for value in sorted(values):
        out = format_value(value)
        expected = ("0x%08x" % value).encode("ascii") + b"\0"
        require(out == expected, "DIV模型与独立固定宽度公式")
        require(len(out) == 11 and parse_fixed(out) == value, "八位颜色往返")
    crt_cases = [(-1,16,b"ffffffff\0"), (-2147483648,16,b"80000000\0"),
                 (-1,10,b"-1\0"), (-2147483648,10,b"-2147483648\0"),
                 (0,16,b"0\0"), (35,36,b"z\0"), (255,2,b"11111111\0")]
    for value, radix, expected in crt_cases:
        require(ltoa(value, radix) == expected, "CRT符号及基数边界")
    for length in range(1,9):
        require(2 <= 10-length <= 9 and (10-length)+length == 10, "串行右对齐区间")
    # 模拟两次长度观测不一致时的指令地址算术，不声称系统真实允许此交错。
    for count in range(1,9):
        for placement in range(1,9):
            end_exclusive = 10-placement+count
            require((end_exclusive > 10) == (count > placement), "交错长度覆盖NUL条件")
    shared = bytearray(format_value(1))
    pointer_a = shared
    copied_a = bytes(shared)
    shared[:] = format_value(2)
    pointer_b = shared
    require(pointer_a is pointer_b and pointer_a == b"0x00000002\0", "共享指针别名")
    require(copied_a == b"0x00000001\0", "跨调用副本独立")
    return {"value_samples": len(values), "crt_cases": len(crt_cases),
            "serial_lengths": 8, "interleaving_arithmetic": 64, "lifetime_checks": 2}
