"""按原文件哈希及JSON位置合并三轮审计，旧发现保留，现存缺口独立计算。"""
import collections
import hashlib
import json
from datetime import datetime, timezone

from audit_tail_chunks import DOCS, OUT, disk_reader, write


def load(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))


def main():
    final = load('source_snapshot_final.json')
    live_keys = {(r['source'], r['json_pointer']) for r in final['records']}
    phases = [('source_snapshot.json', 'batches'), ('delta_snapshot.json', 'incremental_batches'),
              ('delta_final_snapshot.json', 'final_incremental_batches')]
    by_record, funcs, supplements, issues, verified_records = {}, {}, {}, {}, {}
    batches_count = 0
    for snapshot_name, folder in phases:
        snap = load(snapshot_name)
        digest = hashlib.sha256((OUT / snapshot_name).read_bytes()).hexdigest()
        rows = {(r['source'], r['json_pointer']): r for r in snap['records']}
        for key in rows:
            by_record[key] = []
            verified_records[key] = snap['files'][key[0]]['sha256']
        batches = [json.loads(p.read_text(encoding='utf-8')) for p in sorted((OUT / folder).glob('*.json'))]
        assert [b['start'] for b in batches] == list(range(0, len(snap['unique_functions']), 100))
        assert all(b['source_snapshot_sha256'] == digest for b in batches)
        for batch in batches:
            batches_count += 1
            for f in batch['functions']:
                funcs[f['va']] = f
            for g in batch['gaps']:
                by_record[(g['source'], g['json_pointer'])].append(g)
            for s in batch['tail_supplements']:
                supplements[(s['function_va'], s['va'])] = s
            for e in batch['errors']:
                issues[e['va']] = e
    assert all(k in verified_records and verified_records[k] == final['files'][k[0]]['sha256'] for k in live_keys)
    gaps = [g for key in live_keys for g in by_record[key]]
    gaps.sort(key=lambda g: (g['source'], int(g['va'], 16), int(g['chunk_start'], 16)))
    tails = [g for g in gaps if not g['is_main']]
    tail_keys = {(g['va'], g['chunk_start']) for g in tails}
    current_supp = [supplements[k] for k in sorted(tail_keys)]
    digest, rd = disk_reader()
    for s in current_supp:
        assert s['matching'] and bytes.fromhex(s['idb_hex']) == bytes.fromhex(s['disk_hex']) == rd(int(s['va'], 16), s['size'])
    source_state = []
    checked_at = datetime.now(timezone.utc).isoformat()
    for source, meta in final['files'].items():
        path = DOCS / source
        now = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        source_state.append(dict(source=source, snapshot_sha256=meta['sha256'], snapshot_inspected_utc=meta['inspected_utc'],
                                 final_checked_utc=checked_at, current_sha256=now, unchanged=now == meta['sha256']))
    assert all(s['unchanged'] for s in source_state), '源文件再次变化，请重新增量核验，不发布为现存统计'
    declared = set(final['unique_functions']) & funcs.keys()
    unresolved = [issues[va] for va in final['unique_functions'] if va not in funcs]
    unknown = [dict(va=r['va'], source=r['source'], json_pointer=r['json_pointer'],
                    bytes_assessable=bool(r['byte_ranges']), assembly_assessable=bool(r['assembly_addresses']),
                    addressless_lines=r['addressless_lines']) for r in final['records']
               if not r['byte_ranges'] or not r['assembly_addresses']]
    standard = {(r['source'], r['json_pointer']) for r in final['records'] if r['standard_schema']}
    controls = {}
    for topic in ('40A0系列事件', '40C1状态事件', '4019系列事件', '406D系列事件', '40B0系列事件'):
        records = [r for r in final['records'] if '/' + topic + '/' in r['source']]
        vas = {r['va'] for r in records} & declared
        controls[topic] = dict(records=len(records), declared_functions=len(vas),
                              declared_tails=sum(not c['is_main'] for va in vas for c in funcs[va]['chunks']),
                              gap_records=sum('/' + topic + '/' in g['source'] for g in gaps))
    summary = dict(scope='最终快照当前仍缺口；历史快照与批次保留；补证不提升语义',
                   final_snapshot_utc=final['created_utc'], final_hash_check_utc=checked_at, disk_sha256=digest,
                   source_files=len(final['files']), source_records=len(final['records']), candidate_addresses=len(final['unique_functions']),
                   declared_functions=len(declared), excluded_undeclared_or_nonfunction=len(unresolved), batches=batches_count,
                   tail_gap_records=len(tails), tail_gap_functions=len({g['va'] for g in tails}),
                   tail_gap_sources=len({g['source'] for g in tails}), main_gap_records=sum(g['is_main'] for g in gaps),
                   standard_schema_gap_records=sum((g['source'], g['json_pointer']) in standard for g in gaps),
                   supplementary_tail_records=len(current_supp), supplementary_bytes=sum(s['size'] for s in current_supp),
                   all_supplementary_bytes_match=True, all_sources_unchanged_at_final_check=True,
                   incomplete_dimension_records=len(unknown), controls=controls)
    write('current_summary.json', summary)
    write('source_hash_state.json', dict(records=source_state))
    write('current_gaps.json', dict(gaps=gaps))
    write('current_unassessable_dimensions.json', dict(scope='缺少维度，不计作确认遗漏', records=unknown))
    write('current_exclusions.json', dict(scope='6个显式未声明代码范围及8个数据表；不计入函数尾块遗漏', records=unresolved))
    write('current_tail_supplements.json', dict(status='仅导出补证', disk_sha256=digest, chunks=current_supp))
    lines = ['// ============================================================================', '// 当前仍存在的逐源文件与函数范围缺口', '// ============================================================================',
             '// 以source_snapshot_final.json和source_hash_state.json最终哈希核对为准。',
             '// 旧发现保留于01_逐文件缺口.txt及初始批次，不用旧条目覆盖作者之后的补证。',
             '// 每项给出JSON位置、IDA块范围、缺原字节覆盖的指令数、缺带地址汇编的条目数。', '']
    last = None
    for g in gaps:
        if last != g['source']:
            lines += ['', '// 文件：' + g['source']]
            last = g['source']
        label = '主块对齐项' if g['is_main'] else '尾块'
        lines.append(f"//   {g['va']} {label} [{g['chunk_start']},{g['chunk_end']})：{g['json_pointer']}")
        lines.append(f"//     缺原字节覆盖指令{len(g['missing_byte_instruction_vas'])}条；缺带地址汇编{len(g['missing_assembly_vas'])}条。")
    (OUT / '02_当前逐文件缺口.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=True))


if __name__ == '__main__':
    main()
