"""只读独审核验：受限解释原证压缩表达式，与独立MD5模型比较；不执行EXE。"""
import ast
import hashlib
import json
import math
import random
import struct
from pathlib import Path

MASK = 0xFFFFFFFF
HERE = Path(__file__).resolve().parent
INITIAL = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]


def load_statements():
    evidence = json.loads((HERE / '证据/digest_transform.json').read_text(encoding='utf-8'))
    function = next(f for f in evidence['functions'] if f['va'] == '0x8284e0')
    source = '\n'.join(function['pseudocode'])
    source = source[source.index('  v7 = a1[1];'):source.index('  return result;')]
    source = source.replace('(unsigned int)', '').replace('*a1', 'a1[0]')
    return [ast.parse(' '.join(statement.split()), mode='exec').body[0]
            for statement in source.split(';') if statement.strip()]


def expression(node, values):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return values[node.id]
    if isinstance(node, ast.Subscript):
        assert isinstance(node.value, ast.Name) and node.value.id == 'a1'
        return values['a1'][expression(node.slice, values)]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        return ~expression(node.operand, values) & MASK
    if isinstance(node, ast.Call):
        assert isinstance(node.func, ast.Name) and node.func.id == 'HIWORD' and len(node.args) == 1
        return expression(node.args[0], values) >> 16
    if isinstance(node, ast.BinOp):
        left, right = expression(node.left, values), expression(node.right, values)
        operations = {ast.Add: lambda: left + right, ast.Sub: lambda: left - right,
                      ast.Mult: lambda: left * right, ast.BitAnd: lambda: left & right,
                      ast.BitOr: lambda: left | right, ast.BitXor: lambda: left ^ right,
                      ast.LShift: lambda: left << right, ast.RShift: lambda: left >> right}
        assert type(node.op) in operations
        return operations[type(node.op)]() & MASK
    raise AssertionError(ast.dump(node))


def from_evidence(statements, state, block):
    values = {'a1': list(state)}
    values.update({f'v{135 + index}': value for index, value in enumerate(struct.unpack('<16I', block))})
    for statement in statements:
        assert isinstance(statement, (ast.Assign, ast.AugAssign))
        target = statement.targets[0] if isinstance(statement, ast.Assign) else statement.target
        value = expression(statement.value, values)
        if isinstance(statement, ast.AugAssign):
            assert isinstance(statement.op, ast.Add)
            value = (expression(target, values) + value) & MASK
        if isinstance(target, ast.Name):
            values[target.id] = value
        else:
            assert isinstance(target, ast.Subscript) and target.value.id == 'a1'
            values['a1'][expression(target.slice, values)] = value
    return values['a1']


def reference(state, block):
    words = struct.unpack('<16I', block)
    a, b, c, d = state
    rotations = ((7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21))
    for i in range(64):
        if i < 16:
            boolean, index = (b & c) | (~b & d), i
        elif i < 32:
            boolean, index = (b & d) | (c & ~d), (5 * i + 1) % 16
        elif i < 48:
            boolean, index = b ^ c ^ d, (3 * i + 5) % 16
        else:
            boolean, index = c ^ (b | ~d), 7 * i % 16
        total = (a + boolean + words[index] + int(abs(math.sin(i + 1)) * 2**32)) & MASK
        shift = rotations[i // 16][i % 4]
        rotated = ((total << shift) | (total >> (32 - shift))) & MASK
        a, b, c, d = d, (b + rotated) & MASK, b, c
    return [(old + new) & MASK for old, new in zip(state, (a, b, c, d))]


def main():
    statements = load_statements()
    generator = random.Random(0x8284E0)
    for _ in range(128):
        block = generator.randbytes(64)
        state = [generator.getrandbits(32) for _ in range(4)]
        assert from_evidence(statements, state, block) == reference(state, block)
    sizes = (0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 4095, 4096, 4097, 8193)
    for size in sizes:
        data = generator.randbytes(size)
        padded = data + b'\x80' + b'\0' * ((55 - size) % 64) + struct.pack('<Q', size * 8)
        state = list(INITIAL)
        for offset in range(0, len(padded), 64):
            state = from_evidence(statements, state, padded[offset:offset + 64])
        assert struct.pack('<4I', *state) == hashlib.md5(data).digest()
    print(json.dumps({'random_compression_cases': 128, 'hashlib_digest_sizes': list(sizes),
                      'expression_statements': len(statements), 'mismatches': 0,
                      'boundary': '解释已导出压缩表达式；初始化和补齐由模型提供，不是客户端执行测试。'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
