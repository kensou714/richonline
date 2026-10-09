"""离线汇总IDA分批结果、逐文件缺口和补证字节复验；不修改源资料。"""
import collections
import hashlib
import json
from pathlib import Path

from audit_tail_chunks import DOCS, OUT, disk_reader, write


def main():
    snap_bytes = (OUT / 'source_snapshot.json').read_bytes()
    snap = json.loads(snap_bytes)
    snapshot_hash = hashlib.sha256(snap_bytes).hexdigest()
    batches = [json.loads(p.read_text(encoding='utf-8')) for p in sorted((OUT / 'batches').glob('batch_*.json'))]
    expected = list(range(0, len(snap['unique_functions']), 100))
    assert [b['start'] for b in batches] == expected
    assert all(b['source_snapshot_sha256'] == snapshot_hash for b in batches)
    assert sum(b['requested'] for b in batches) == len(snap['unique_functions'])
    functions = {f['va']: f for b in batches for f in b['functions']}
    errors = [row for b in batches for row in b['errors']]
    gaps = [row for b in batches for row in b['gaps']]
    tails = [row for row in gaps if not row['is_main']]
    mains = [row for row in gaps if row['is_main']]
    supplements = [row for b in batches for row in b['tail_supplements']]
    digest, read = disk_reader()
    for row in supplements:
        assert row['matching'] and bytes.fromhex(row['idb_hex']) == bytes.fromhex(row['disk_hex']) == read(int(row['va'], 16), row['size'])
    by_source = collections.defaultdict(list)
    for row in gaps:
        by_source[row['source']].append(row)
    changed = []
    for source, meta in snap['files'].items():
        path = DOCS / source
        now = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        if now != meta['sha256']:
            changed.append(dict(source=source, snapshot_sha256=meta['sha256'], current_sha256=now))
    unknown = [dict(va=r['va'], source=r['source'], json_pointer=r['json_pointer'],
                    byte_evidence_available=bool(r['byte_ranges']),
                    addressed_assembly_available=bool(r['assembly_addresses']),
                    addressless_lines=r['addressless_lines']) for r in snap['records']
               if not r['byte_ranges'] or not r['assembly_addresses']]
    standard = {(r['source'], r['json_pointer']) for r in snap['records'] if r['standard_schema']}
    controls = {}
    for topic in ('40A0系列事件', '40C1状态事件'):
        records = [r for r in snap['records'] if '/' + topic + '/' in r['source']]
        seen = {r['va'] for r in records}
        controls[topic] = dict(records=len(records), declared_functions=len(seen & functions.keys()),
                              declared_tails=sum(not c['is_main'] for va in seen if va in functions for c in functions[va]['chunks']),
                              gap_records=sum('/' + topic + '/' in r['source'] for r in gaps))
    summary = dict(scope='按快照与当前IDA声明chunk审计；未补充或提升语义结论',
                   created_utc=snap['created_utc'], disk_sha256=digest, snapshot_sha256=snapshot_hash,
                   source_files=len(snap['files']), source_records=len(snap['records']), candidate_addresses=len(snap['unique_functions']),
                   declared_functions=len(functions), undeclared_or_nonfunction_addresses=len(errors),
                   batches=len(batches), source_files_with_gaps=len(by_source),
                   tail_gap_records=len(tails), tail_gap_functions=len({r['va'] for r in tails}),
                   tail_gap_sources=len({r['source'] for r in tails}),
                   main_gap_records=len(mains), standard_schema_gap_records=sum((r['source'], r['json_pointer']) in standard for r in gaps),
                   supplementary_tail_records=len(supplements), supplementary_bytes=sum(r['size'] for r in supplements),
                   supplementary_unique_ranges=len({(r['va'], r['size']) for r in supplements}),
                   supplementary_all_match_current_disk=True, incomplete_measurement_records=len(unknown),
                   source_files_changed_after_snapshot=changed, controls=controls)
    write('audit_summary.json', summary)
    write('gaps_by_source.json', dict(sources=dict(sorted(by_source.items()))))
    write('unassessable_dimensions.json', dict(scope='缺少原字节范围或带地址汇编，不等同于确认缺口', records=unknown))
    write('undeclared_or_nonfunction.json', dict(scope='显式未声明代码范围及数据表，不计作已声明函数尾块遗漏', records=errors))
    write('tail_supplements.json', dict(disk_sha256=digest, status='仅导出补证；未提升语义审阅等级', chunks=supplements))
    lines = ['// ============================================================================', '// 按原文件和函数列出的范围缺口', '// ============================================================================',
             '// 对象为source_snapshot.json对应旧原证快照；不改写原文件，也不合并其审阅等级。',
             '// 尾块补证见tail_supplements.json；主块汇编缺项仅单列，不冒充SEH尾块。',
             '// 字节数指标为缺少覆盖的指令条目数；完整逐指令地址见gaps_by_source.json。', '']
    for source, rows in sorted(by_source.items()):
        lines.append('// 文件：' + source)
        for r in rows:
            kind = '主块' if r['is_main'] else '尾块'
            lines.append(f"//   {r['va']} {kind} {r['chunk_start']}..{r['chunk_end']}（不含末端）")
            lines.append(f"//     {r['json_pointer']}；未覆盖指令字节={len(r['missing_byte_instruction_vas'])}条；缺地址汇编={len(r['missing_assembly_vas'])}条。")
        lines.append('')
    (OUT / '01_逐文件缺口.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
