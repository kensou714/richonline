"""稳定、合法输入的静态契约模型；不执行原机器码或字体回调。"""
from dataclasses import dataclass
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Node:
    length: int
    width: int
    atomic: int = 0


def locate(widths, target, flag, nodes=None, *, text_length=None, depth=0):
    """90CE80：返回(码元位置, 外层a4差值, 使用的最大递归深度)。"""
    if depth > 32:
        raise ValueError('模型递归界限；不声明畸形输入终止')
    n = len(widths) if text_length is None else text_length
    if n == 0:
        return 0, 0, depth
    assert all(0 <= w <= 255 for w in widths)
    total = 0

    def overflow(position):
        delta = total - target
        if total == target:
            return position, delta, depth
        inner, _, deepest = locate(widths, total, flag, nodes, text_length=n, depth=depth + 1)
        return inner, delta, deepest

    if nodes is None:
        for i in range(n):
            next_width = total + widths[i]
            if next_width > target:
                return overflow(i)
            if next_width == target and not (flag & 255):
                return i + 1, 0, depth
            total = next_width
    else:
        offset = 0
        for node in nodes:
            if node.atomic & 255:
                next_width = total + node.width
                if next_width > target:
                    return overflow(offset)
                if next_width == target and not (flag & 255):
                    return offset, 0, depth
                total = next_width
            else:
                for j in range(max(node.length, 0)):
                    next_width = total + widths[offset + j]
                    if next_width > target:
                        return overflow(offset + j)
                    if next_width == target and not (flag & 255):
                        return offset + j + 1, 0, depth
                    total = next_width
            offset += node.length
    # 机器出口取最初wcslen，不取分段长度和；可观察空链与长度不一致的区别。
    return n, total - target, depth


def prefix_width(widths, position, nodes=None, *, text_length=None):
    """90D120；调用者负责position范围，模型不允许用Python负下标伪造非法访问。"""
    n = len(widths) if text_length is None else text_length
    if n == 0:
        return 0
    if nodes is None:
        if position > len(widths):
            raise ValueError('原函数会超出模型宽度数组；不替它钳制')
        return sum(widths[:max(0, position)])
    total, offset = 0, 0
    for node in nodes:
        end = offset + node.length
        if end > position:
            if node.atomic & 255:
                return total
            assert 0 <= offset <= len(widths)
            return total + sum(widths[offset:max(offset, position)])
        total += node.width
        offset = end
    return total


def next_position(widths, position, flag, nodes=None):
    """90D310普通域，按汇编节点分支复现；需要非空有效文本地址。"""
    low = flag & 255
    if nodes is None:
        # 稳定flag+40时两条普通循环最终等价；非零分支额外反复调用wcslen。
        i = position + 1
        if i < 0:
            raise ValueError('原函数存在负下标读取；模型拒绝非法指针访问')
        while i < len(widths):
            if widths[i] != 0:
                return i
            i += 1
        return len(widths)
    offset = 0
    for node in nodes:
        end, result = offset + node.length, position + 1
        if offset <= result and end > position:
            if node.width == 0 and low:
                position += node.length
            elif node.atomic & 255:
                return end
            elif result == end and not low:
                return result
            elif result < end:
                assert result >= 0
                while widths[result] == 0 and low:
                    result += 1
                    if result >= end:
                        break
                if result < end:
                    return result
        offset = end
    return offset


def breakpoint_before_limit(text, widths, target, mode):
    """8E0A00只返回AL的布尔含义；text为非0 UTF-16码元序列。"""
    if mode == 0:
        return True
    total = 0
    for i, unit in enumerate(text):
        if widths[i] and (unit in (44, 46, 32, 10, 13)
                          or unit == 92 and i + 1 < len(text) and text[i + 1] == 110):
            return True
        total += widths[i]
        if total >= target:
            return False
    return True


def tokens(widths, nodes):
    """独立参考把节点展开成可消费单元，不使用locate的循环变量与分支。"""
    if nodes is None:
        return [(i, i + 1, w, False) for i, w in enumerate(widths)]
    out, position = [], 0
    for node in nodes:
        if node.atomic & 255:
            out.append((position, position + node.length, node.width, True))
        else:
            out.extend((i, i + 1, widths[i], False) for i in range(position, position + node.length))
        position += node.length
    return out


def reference_locate(widths, target, flag, nodes=None):
    if not widths:
        return 0, 0
    units = tokens(widths, nodes)
    boundaries = list(itertools.accumulate([u[2] for u in units]))
    overflow = next((i for i, boundary in enumerate(boundaries) if boundary > target), None)
    exact = next((i for i, boundary in enumerate(boundaries) if boundary == target), None)
    if not (flag % 256) and exact is not None and (overflow is None or exact < overflow):
        unit = units[exact]
        return (unit[0] if unit[3] else unit[1]), 0
    if overflow is None:
        return len(widths), (boundaries[-1] if boundaries else 0) - target
    before = boundaries[overflow - 1] if overflow else 0
    if before == target:
        return units[overflow][0], 0
    position, _ = reference_locate(widths, before, flag, nodes)
    return position, before - target


def run():
    counts = dict(plain=0, segmented=0, prefix=0, next_plain=0, flag_period=0,
                  breakpoint=0, explicit_edges=0)
    largest_depth = 0
    for n in range(5):
        for widths in itertools.product((0, 1, 2, 255), repeat=n):
            for target in range(-2, min(sum(widths), 12) + 3):
                for flag in (0, 1):
                    got, delta, depth = locate(widths, target, flag)
                    assert (got, delta) == reference_locate(widths, target, flag)
                    assert 0 <= got <= n
                    largest_depth = max(largest_depth, depth)
                    counts['plain'] += 1
            for position in range(-2, n + 1):
                assert prefix_width(widths, position) == sum(widths[:max(position, 0)])
                counts['prefix'] += 1
            for position in range(-1, n + 2):
                for flag in (0, 1, 256, 257):
                    expected = next((i for i in range(position + 1, n) if widths[i]), n)
                    assert next_position(widths, position, flag) == expected
                    counts['next_plain'] += 1
    # 节点宽度与普通字节缓存相容，含原子跨度、零宽和链尾。
    for a, b, c, atomic_width in itertools.product((0, 1, 7), repeat=4):
        widths = (a, atomic_width, 0, b, c)
        nodes = [Node(1, a), Node(2, atomic_width, 1), Node(2, b + c)]
        for target, flag in itertools.product(range(-2, a + atomic_width + b + c + 3), (0, 1)):
            got, delta, depth = locate(widths, target, flag, nodes)
            assert (got, delta) == reference_locate(widths, target, flag, nodes)
            largest_depth = max(largest_depth, depth)
            assert 0 <= got <= 5
            counts['segmented'] += 1
        expected_prefix = [0, a, a, a + atomic_width, a + atomic_width + b, a + atomic_width + b + c]
        for position, expected in enumerate(expected_prefix):
            assert prefix_width(widths, position, nodes) == expected
            counts['prefix'] += 1
    for value in range(-256, 512):
        for target in (0, 1, 2, 8):
            assert locate((1, 0, 0, 7), target, value)[:2] == locate((1, 0, 0, 7), target, value % 256)[:2]
            counts['flag_period'] += 1
    cases = [
        ((1, 0, 0, 7), 1, 0, None, (1, 0)),
        ((1, 0, 0, 7), 1, 1, None, (3, 0)),
        ((1, 0, 0, 7), 4, 0, None, (1, -3)),
        ((1, 0, 0, 7), 4, 1, None, (3, -3)),
        ((4, 0, 1), 4, 0, [Node(2, 4, 1), Node(1, 1)], (0, 0)),
        ((4, 0, 1), 4, 1, [Node(2, 4, 1), Node(1, 1)], (2, 0)),
        ((4, 0, 7), 5, 0, [Node(2, 4, 1), Node(1, 7)], (0, -1)),
        ((1, 2), -2, 1, None, (0, 2)),
        ((0, 0), -2, 1, None, (2, 2)),
        ((1, 2), 0, 1, [], (2, 0)),
    ]
    for widths, target, flag, nodes, expected in cases:
        assert locate(widths, target, flag, nodes)[:2] == expected
        counts['explicit_edges'] += 1
    # 分段链耗尽返回字符串长度，不强行把损坏/不同步的数据描述成正常输入。
    assert locate((1, 1, 1), 9, 1, [Node(1, 1)])[:2] == (3, -8)
    assert locate((0, 0), 0, 0, [Node(2, 0, 1)])[:2] == (0, 0)
    assert next_position((2, 0, 0, 3), 0, 0) == next_position((2, 0, 0, 3), 0, 1) == 3
    assert next_position((2, 0, 0, 3), 0, 0, [Node(4, 5)]) == 1
    assert next_position((2, 0, 0, 3), 0, 1, [Node(4, 5)]) == 3
    assert next_position((4, 0, 3), 0, 0, [Node(2, 4, 1), Node(1, 3)]) == 2
    counts['explicit_edges'] += 6
    # 独立参考比较“首可见断点事件”和“首累计阈值事件”的位置，相同位置断点优先。
    for n in range(4):
        for text in itertools.product((65, 32, 92, 110), repeat=n):
            for widths in itertools.product((0, 2), repeat=n):
                for target in range(-1, 8):
                    stop = next((i for i, unit in enumerate(text) if widths[i]
                                 and (unit in (44, 46, 32, 10, 13)
                                      or unit == 92 and text[i + 1:i + 2] == (110,))), n)
                    threshold = next((i for i, width in enumerate(itertools.accumulate(widths))
                                      if width >= target), n)
                    expected = stop <= threshold
                    assert breakpoint_before_limit(text, widths, target, 1) == expected
                    assert breakpoint_before_limit(text, widths, target, 0) is True
                    counts['breakpoint'] += 2
    result = dict(scope='静态普通域契约模型；非机器码执行或真实客户端验收', cases=counts,
                  largest_recursion_depth=largest_depth, failures=0,
                  boundary='有效终止字符串与足量缓存、稳定字段、有限无环分段、非负宽度、无32位溢出；显式边例另记不一致链')
    (HERE / 'model_result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False, indent=2))
