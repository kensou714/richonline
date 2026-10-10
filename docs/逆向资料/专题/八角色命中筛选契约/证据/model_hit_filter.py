"""依据已审静态分支建立契约模型；不执行客户端机器码。"""
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def eligible(available, states, special, current, inside, a5, a6):
    if not available:
        return False
    for state in states:
        if state != -1:
            return False
    if not (a6 & 255) and special:
        return False
    if not (a5 & 255) and current:
        return False
    return bool(inside)


def collect(hit_mask, old_last):
    output, count, last = [77] * 8, 0, old_last
    for i in range(8):
        output[i] = 0
        if hit_mask & (1 << i):
            output[i] = 1
            count += 1
            last = i
    return output, count, last


def run():
    branches = masks = geometry = 0
    flags = (0, 1, 255, 256, 257, -256)
    for available, state_bits, special, current, inside, a5, a6 in itertools.product(
            (False, True), range(16), (False, True), (False, True), (False, True), flags, flags):
        states = [0 if state_bits & (1 << i) else -1 for i in range(4)]
        expected = (available and state_bits == 0 and inside
                    and (bool(a6 % 256) or not special)
                    and (bool(a5 % 256) or not current))
        assert eligible(available, states, special, current, inside, a5, a6) == expected
        branches += 1
    for mask in range(256):
        output, count, last = collect(mask, -123)
        selected = [i for i in range(8) if mask >> i & 1]
        assert output == [int(i in selected) for i in range(8)]
        assert count == len(selected)
        assert last == (max(selected) if selected else -123)
        masks += 1
    # 无溢出的普通坐标域；坐标边界以独立range集合判断，检验四边严格排除。
    for world_x, world_y, camera_x, camera_y in itertools.product(
            (-1000, 0, 1000), (-1000, 0, 1000), (-32768, -1, 0, 32767), (-32768, -1, 0, 32767)):
        right, bottom = world_x - camera_x, world_y - camera_y
        valid_x, valid_y = range(right - 63, right), range(bottom - 95, bottom)
        for dx, dy in itertools.product((-65, -64, -63, -1, 0, 1), (-97, -96, -95, -1, 0, 1)):
            x, y = right + dx, bottom + dy
            actual = x > right - 64 and x < right and y > bottom - 96 and y < bottom
            assert actual == (x in valid_x and y in valid_y)
            geometry += 1
    result = dict(scope='静态契约模型，非机器码执行或实机', branch_cases=branches,
                  output_mask_cases=masks, geometry_cases=geometry, failures=0,
                  limitation='不覆盖指针别名、回调副作用、分配或32位坐标溢出')
    (HERE / 'model_result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                          encoding='utf-8', newline='\n')
    return result


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False, indent=2))
