"""按310个分派项生成短分册；只整理已有证据，不自动判定业务完成。"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOP = ROOT.parent
OUT = ROOT / '消息入口导航'


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    mapping_path = TOP / '专题/游戏分派桥接/证据/dispatch_bridges_raw.json'
    review_path = ROOT / 'review_coverage.json'
    evidence_path = ROOT / 'evidence_coverage.json'
    mapping = read(mapping_path)['entries']
    reviews = {r['va']: r['reviews'] for r in read(review_path)['functions']}
    evidence = {r['va']: r['evidence'] for r in read(evidence_path)['functions']}
    rows = []
    for entry in sorted(mapping, key=lambda x: int(x['code'], 16)):
        handler = entry['handler']
        rows.append(dict(code=entry['code'], registration_site=entry['write_va'],
                         bridge=entry['bridge'], handler=handler,
                         evidence=evidence.get(handler, []),
                         handler_reviews=reviews.get(handler, [])))
    assert len(rows) == 310 and len({r['code'] for r in rows}) == 310
    OUT.mkdir(exist_ok=True)
    source_hashes = {p.relative_to(TOP).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (mapping_path, review_path, evidence_path)}
    data = dict(scope='仅按分派注册与现有清单导航；同一handler多份局部结论不合成完成',
                source_sha256=source_hashes, entries=rows,
                no_explicit_handler_review=[r['code'] for r in rows if not r['handler_reviews']])
    (OUT / 'message_navigation.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    index = ['// 消息入口导航', '// ============================================================================',
             '// 310个注册项；逐条列出真实handler、桥接与显式清单来源。',
             '// 这里没有完成率。仅导出、桥接模板和异常尾块审阅均不等于消息语义闭环。',
             '// 路径相对docs/逆向资料；详细结论/未知/原证请回到JSON指针所列记录。',
             '// 静态来源指纹保存在message_navigation.json；由../build_message_navigation.py重建。',
             '// 40xx/42xx/50xx回复与60xx本地记录分开核查，不能把所有入口当网络包。', '//']
    for part, start in enumerate(range(0, len(rows), 24), 1):
        batch = rows[start:start + 24]
        filename = f'{part:02d}_{batch[0]["code"][2:].upper()}至{batch[-1]["code"][2:].upper()}.txt'
        index.append('// ' + filename)
        lines = ['// 消息入口导航 · ' + batch[0]['code'] + ' 至 ' + batch[-1]['code'],
                 '// ============================================================================',
                 '// 只索引现有证据；读完桥接或有一份局部清单不表示整个事件已完成。', '//']
        for row in batch:
            lines += [f'// {row["code"]} -> handler {row["handler"]}；桥接 {row["bridge"]}',
                      f'//   注册写点 {row["registration_site"]}；原证来源 {len(row["evidence"])} 份。']
            if not row['handler_reviews']:
                lines.append('//   无显式handler审阅；需按原证继续核对。')
            for review in row['handler_reviews']:
                lines.append('//   ' + review['status'])
                lines.append('//     ' + review['source'] + ' #' + review['json_pointer'])
            lines.append('//')
        (OUT / filename).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    index += ['//', '// 无显式handler清单的编号：' + '、'.join(data['no_explicit_handler_review']),
              '// 清单存在但仅导出的入口仍须深入，不能从以上名单消失推断分析完成。']
    (OUT / '00_阅读入口.txt').write_text('\n'.join(index) + '\n', encoding='utf-8')
    print(json.dumps(dict(entries=len(rows), no_explicit_handler_review=data['no_explicit_handler_review']), ensure_ascii=False))


if __name__ == '__main__':
    main()
