"""只复现已核局部规则；不调用客户端、不发送请求、不推断编码名称。"""
from dataclasses import dataclass


@dataclass
class Entry:
    first: int
    second: int = 1
    category: int = 0
    encoding: bytes = b'abcdefgh'
    gift: int = 0


def signed32(value):
    value &= 0xffffffff
    return value - 0x100000000 if value & 0x80000000 else value


def special_encoding(entry):
    if entry is None:
        return False
    if len(entry.encoding) < 8:
        raise ValueError('模型输入须提供实际读取的 8 字节')
    return entry.encoding[3] == ord('1') and entry.encoding[5] == ord('2')


def group(entries):
    ordinary, gifts, requested = [], [], []
    for category in (0, 1):
        for index in range(len(entries)-1, -1, -1):
            entry = entries[index]
            if signed32(entry.first) == -1 or entry.category != category or special_encoding(entry):
                continue
            if signed32(entry.gift) > 0:
                gifts.append(index)
            elif len(ordinary) < 70:
                ordinary.append(index)
            else:
                requested.append((index, entry.first, entry.second))
                entry.first = entry.second = -1
    return ordinary, gifts, requested


def category_zero_count(entries, argument):
    argument = argument & 0xff
    return sum(signed32(e.first) != -1 and e.category == 0
               and (not argument or not special_encoding(e)) for e in entries)


def category_zero_first(entries, argument):
    argument = argument & 0xff
    for index, entry in enumerate(entries):
        if signed32(entry.first) != -1 and entry.category == 0:
            if special_encoding(entry) == bool(argument):
                return index
    return None


def verify_boundaries():
    cases = []
    for count in (0, 69, 70, 71):
        entries = [Entry(i) for i in range(count)]
        ordinary, gifts, requested = group(entries)
        assert ordinary == list(range(count-1, max(-1, count-71), -1))
        assert not gifts
        assert requested == ([(0, 0, 1)] if count == 71 else [])
        if count == 71:
            assert entries[0].first == entries[0].second == -1
            assert group(entries) == (list(range(70, 0, -1)), [], [])
        cases.append(f'普通条数 {count}')

    entries = [Entry(i, category=1) for i in range(5)]
    entries += [Entry(i, category=0) for i in range(5, 73)]
    ordinary, gifts, requested = group(entries)
    assert ordinary == list(range(72, 4, -1)) + [4, 3]
    assert requested == [(2, 2, 1), (1, 1, 1), (0, 0, 1)] and not gifts
    cases.append('类别 0 优先，类别 1 共用剩余 2 个额度')

    assert group([Entry(i, gift=1) for i in range(100)]) == ([], list(range(99, -1, -1)), [])
    cases.append('礼物 100 条不套用普通 70 条上限')

    encodings = [b'aaa1a2aa', b'bbb1b2bb', b'aaa1a3aa', b'aaa0a2aa', b'\x00\x00\x001\x002\x00\x00']
    assert [special_encoding(Entry(i, encoding=code)) for i, code in enumerate(encodings)] == [True, True, False, False, True]
    assert not special_encoding(None)
    entries = [Entry(0, encoding=encodings[0]), Entry(1, encoding=encodings[2]),
               Entry(2, category=2), Entry(-1), Entry(4, gift=1),
               Entry(5, gift=0), Entry(6, gift=-1), Entry(7, gift=0xffffffff),
               Entry(8, gift=0x80000000), Entry(9, encoding=encodings[1], gift=1)]
    assert category_zero_count(entries, 0) == 8
    assert category_zero_count(entries, 1) == 6
    assert category_zero_first(entries, 1) == 0
    assert category_zero_first(entries, 0) == 1
    for argument in (256, -256):
        assert category_zero_count(entries, argument) == 8
        assert category_zero_first(entries, argument) == 1
    assert category_zero_count(entries, 257) == 6
    assert category_zero_first(entries, 257) == 0
    cases.append('查询参数仅读低8位：256/-256等效0，257等效1')
    assert group(entries) == ([8, 7, 6, 5, 1], [4], [])
    cases.append('两字符谓词、非 NUL 字节、无效槽、类别 2、signed 礼物边界')
    assert category_zero_first([Entry(-1), Entry(1, category=1)], 0) is None
    assert signed32(0xffffffff) == -1 and signed32(0x7fffffff) > 0
    cases.append('查询没有有效类别 0，32 位符号转换')
    return cases


if __name__ == '__main__':
    print('\n'.join(verify_boundaries()))
