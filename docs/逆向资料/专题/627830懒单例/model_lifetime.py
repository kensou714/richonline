"""只模拟局部顺序及所有权，不执行原函数、分配器或GDI。"""
from itertools import product

SIZES = (12, 14, 16, 24)


def lazy_get(current, allocate):
    return current if current else allocate()


def gate_read(manager):
    return manager[4][0]


def initialize(slots, successful, next_id=100):
    slots = list(slots)
    replaced = []
    for index, success in enumerate(successful):
        if slots[index]:
            replaced.append(slots[index])
        slots[index] = next_id + index
        if not success:
            return slots, False, replaced
    return slots, True, replaced


def destroy(slots, flag):
    freed = [value for value in slots if value]
    return [0] * 4, freed, bool(flag & 1)


def check_model():
    partial_cases = 0
    for first_failure in range(5):
        success = [index != first_failure for index in range(4)]
        slots, ok, replaced = initialize([0] * 4, success)
        count = min(first_failure + 1, 4)
        assert slots == [100 + i if i < count else 0 for i in range(4)]
        assert ok == (first_failure == 4) and not replaced
        cleared, freed, deleted = destroy(slots, 1)
        assert cleared == [0] * 4 and freed == slots[:count] and deleted
        partial_cases += 1
    repeat_cases = 0
    for first_failure in range(5):
        old = [10, 11, 12, 13]
        slots, ok, replaced = initialize(old, [i != first_failure for i in range(4)])
        count = min(first_failure + 1, 4)
        assert replaced == old[:count] and slots[count:] == old[count:]
        assert ok == (first_failure == 4)
        repeat_cases += 1
    release_cases = 0
    for mask in product((False, True), repeat=4):
        slots = [i + 1 if present else 0 for i, present in enumerate(mask)]
        for flag in range(256):
            cleared, freed, deleted = destroy(slots, flag)
            assert cleared == [0] * 4
            assert freed == [i + 1 for i, present in enumerate(mask) if present]
            assert deleted == (flag % 2 == 1)
            release_cases += 1
    routing_cases = 0
    mapping = dict(zip(SIZES, [10, 11, 12, 13]))
    for size in range(-64, 129):
        expected = next((10 + i for i, legal in enumerate(SIZES) if size == legal), 0)
        assert mapping.get(size, 0) == expected
        routing_cases += 1
    gate_cases = 0
    for mask in product((False, True), repeat=4):
        borrowed = bytearray(1)
        manager = [i + 1 if present else 0 for i, present in enumerate(mask)] + [borrowed]
        for value in range(256):
            borrowed[0] = value
            assert gate_read(manager) == value
            assert bool(gate_read(manager)) == (value > 0)
            gate_cases += 1
        assert manager[4] is borrowed
    allocations = []
    def allocate():
        allocations.append(1)
        return 99
    assert lazy_get(10, allocate) == 10 and allocations == []
    assert lazy_get(0, lambda: 0) == 0
    created = lazy_get(0, allocate)
    assert created == 99 and allocations == [1]
    assert lazy_get(created, allocate) == 99 and allocations == [1]
    # 分配返回空时原入口仍调用依赖，不能用模型伪造一个正常失败返回。
    return dict(partial_initializations=partial_cases, repeated_initializations=repeat_cases,
                release_masks_and_flags=release_cases, routing_sizes=routing_cases,
                borrowed_byte_and_slot_cases=gate_cases, lazy_creation_cases=4,
                limitation='串行局部契约；不模拟空this依赖、SEH、借用地址有效性或GDI。')


if __name__ == '__main__':
    import json
    print(json.dumps(check_model(), ensure_ascii=False))
