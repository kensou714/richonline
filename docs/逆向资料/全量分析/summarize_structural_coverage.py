"""将纯跳板与其余声明入口分开统计，避免把入口数误当业务完成率。"""
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8'))


def main():
    inventory = read('functions.json')
    exported = {r['va'] for r in read('evidence_coverage.json')['functions']}
    reviewed = {r['va'] for r in read('review_coverage.json')['functions']}
    counts = collections.defaultdict(collections.Counter)
    for f in inventory:
        group = '五字节E9直接跳板' if f['classification'] == '直接跳板已识别' else '其余声明入口'
        c = counts[group]
        c['总数'] += 1
        c['原证导出'] += f['va'] in exported
        c['有显式分级记录'] += f['va'] in reviewed
        c['无显式分级记录'] += f['va'] not in reviewed
    assert sum(c['总数'] for c in counts.values()) == len(inventory) == 29019
    payload = dict(scope='结构分组，不推导语义完成率；跳板识别已在历史台账保存',
                   groups=dict(counts), total=len(inventory))
    (ROOT / '结构覆盖口径.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['// 声明入口的结构覆盖口径', '// ============================================================================',
             '// 总入口29019；一个函数的原证、导航、模板、局部语义和全业务闭环是不同维度。',
             '// 本表按既有函数清单中的五字节E9直接跳板分类，保留其余所有入口。',
             '// 其余入口仍含CRT、模板、对象方法和业务函数，不等同纯游戏逻辑。',
             '// 原证导出数不含仅在thunks.json有5字节识别记录而未导出函数正文的跳板。',
             '// 有分级记录包含仅导出与局部审阅，绝不据此计算完成百分比。', '//']
    for group, c in counts.items():
        lines += ['// ' + group,
                  '//   总数：' + str(c['总数']),
                  '//   原证导出：' + str(c['原证导出']),
                  '//   有显式分级记录：' + str(c['有显式分级记录']),
                  '//   无显式分级记录：' + str(c['无显式分级记录']), '//']
    lines += ['// 未声明范围与单条指令候选均单列在evidence_coverage.json，不加入上述分母。',
              '// 由summarize_structural_coverage.py重建；数字会随在写专题改变。']
    (ROOT / '结构覆盖口径.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(payload, ensure_ascii=False))


if __name__ == '__main__':
    main()
