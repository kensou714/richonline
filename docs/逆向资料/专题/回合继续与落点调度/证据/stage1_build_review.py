"""只读复核 stage1 导出证据，生成显式审阅清单和磁盘一致性报告。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
TOPIC = ROOT / 'docs/逆向资料/专题/回合继续与落点调度'
EVIDENCE = TOPIC / '证据'
NOTES = {
    '0x7c54b0': '主函数前置门槛、70项switch、构造与返回值逐分支审阅；消费者闭环待续。',
    '0x627b60': '文字对象单例分配12字节并构造；分配器及文字加载器未展开。',
    '0x629d90': '返回this[2]+this[0]*index；未见边界检查。',
    '0x63e160': '模式字段this+24传给63E1A0，判模式3。',
    '0x63e410': '读取演员this+1464当前位置。',
    '0x63e4d0': '演员有符号字节this+1488等于7。',
    '0x63e500': '演员字节this+1499非零。',
    '0x63e990': '模式字段this+24传给629E10，判模式4。',
    '0x63eca0': '模式0或模式2且子类型0。',
    '0x63edf0': '模式1、模式2子类型1、模式3或模式4。',
    '0x63f080': '6000构造器；初始化8/12/16 DWORD，不整体清零。',
    '0x63f390': '读取G+3672+slot标志。',
    '0x63f4d0': '演员有符号字节this+1500大于0。',
    '0x63f5f0': '读取演员this+1512数量。',
    '0x63f620': '读取演员this+1504数量。',
    '0x63f730': '写6063 WORD；其余由调用点赋值。',
    '0x64fa50': '按Size拷贝后传288字节槽、cursor和mode=1给6980F0；检查汇编实参。',
    '0x693260': '6002构造器及局部初始化，见消息布局。',
    '0x6932b0': '6003构造器及局部初始化，见消息布局。',
    '0x693320': '6060构造器及局部初始化，见消息布局。',
    '0x693420': '6001构造器及局部初始化，见消息布局。',
    '0x6937d0': '只写6005 WORD。',
    '0x693800': '只写606C WORD。',
    '0x693b80': '写G+83833字节；stage1 type67写0。',
    '0x693cb0': '写G+83832字节；stage1 type9写0。',
    '0x694140': '8字节全局载荷第二DWORD清零；第一DWORD由调用点写。',
    '0x694460': '6062构造器；+3/+4字节清零，见消息布局。',
    '0x69b0e0': '数量>=50取19，30..49取20，小于30取21。',
    '0x7c07d0': '扫描G+E20个参与者，标志非零且演员+5D6非-1即返回1。',
    '0x7c0850': '扫描G+E20个参与者，标志非零且演员+5D7非-1即返回1。',
    '0x7d5e10': 'G+83830有符号字节非-1。',
    '0x7d6f30': '地图this+52指针的position*8首有符号字节。',
    '0x7d6f60': '只写608B WORD。',
    '0x7d6f90': 'G+83809有符号字节大于0。',
    '0x7d9d10': '扫描this+1..32是否存在-1；调用点this=G+C5C。',
    '0x7e2730': '类型允许集合0..10、28、41..43、51..62、67..70；负值不通过。',
    '0x7e6910': 'type28/61分别扫描两个WORD位置，选不同于输入者；找不到返回0。',
    '0x7fab70': '演员位置数组查对应状态，未找到返回1。',
    '0x7fabe0': '演员状态数组全部非零返回1；空数组也返回1。',
    '0x7facb0': '按演员WORD计数清零状态数组；返回值不用于stage1。',
    '0x629e10': '整数等于4。',
    '0x63e1a0': '整数等于3；忽略错误的库符号名。',
    '0x63e7d0': 'G+3632+slot参与扫描标志。',
    '0x63ed10': '模式字段传629DD0，判模式0。',
    '0x63ed50': '模式2且子类型0。',
    '0x63ee90': '模式字段传629DF0，判模式1。',
    '0x63eed0': '模式2且子类型1。',
    '0x63ef50': '演员+1494有符号字节非-1。',
    '0x63ef80': '演员+1495有符号字节非-1。',
    '0x6980f0': '环形队列按游标插入288字节槽；满返回-1，mode1返回后继。汇编复核。',
    '0x6d7170': '文字表对象+8 DWORD清零；不执行文件加载。',
    '0x629dd0': '整数等于0。',
    '0x629df0': '整数等于1。',
    '0x63edd0': '整数等于2。',
    '0x698640': 'head==(tail+1)%capacity判满。',
    '0x698680': '后继(index+1)%capacity。',
    '0x6986b0': '前驱index-1，小于0时capacity-1。',
}


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt + 40 * i + 8) for i in range(count)]

    def disk(ea, size):
        for _vsize, rva, raw_size, raw_offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return blob[raw_offset + relative:raw_offset + relative + size]
        raise ValueError(hex(ea))

    functions, checks, refs = {}, [], {}
    for name in ['continue_stages.json', 'stage1_dependencies.json', 'stage1_dependencies2.json', 'stage1_dependencies3.json']:
        data = json.loads((EVIDENCE / name).read_text(encoding='utf-8'))
        selected = [f for f in data['functions'] if name != 'continue_stages.json' or f['va'] == '0x7c54b0']
        for f in selected:
            functions[f['va']] = f
            refs[f['va']] = '证据/' + name
            for r in f['byte_ranges']:
                checks.append({'kind': '函数字节', 'owner': f['va'], 'va': r['va'], 'size': r['size'],
                               'matching': disk(int(r['va'], 16), r['size']).hex() == r['idb_hex']})
        used_thunks = {t for f in selected for c in f['calls'] for t in c['thunks']}
        for t in data['thunks']:
            if t['va'] in used_thunks:
                checks.append({'kind': '直接跳板', 'va': t['va'], 'size': t['size'],
                               'matching': disk(int(t['va'], 16), t['size']).hex() == t['idb_hex']})
    sw = json.loads((EVIDENCE / 'stage1_switch.json').read_text(encoding='utf-8'))
    for key in ['dispatch_instruction', 'index', 'targets']:
        raw = bytes.fromhex(sw[key + '_hex'])
        checks.append({'kind': '跳表数据', 'va': sw[key + '_va'], 'size': len(raw),
                       'matching': disk(int(sw[key + '_va'], 16), len(raw)) == raw})
    review = []
    for va, f in sorted(functions.items(), key=lambda x: int(x[0], 16)):
        known = va in NOTES
        review.append({'va': va, 'name_from_idb': f['name'], 'evidence': refs[va],
                       'review_status': '局部语义已审阅' if known else '仅导出_未审阅',
                       'note': NOTES.get(va, 'CRT/运行时辅助仅归档，不计入人工完成。'),
                       'full_dependency_closure': False,
                       'outgoing_functions': sorted(set(c['implementation'] for c in f['calls']))})
    direct = {c['implementation'] for f in functions.values() if f['va'] in NOTES for c in f['calls']}
    for va in sorted(direct - functions.keys(), key=lambda x: int(x, 16)):
        review.append({'va': va, 'review_status': '未导出_未审阅', 'note': '已审阅函数可达的CRT/内存辅助依赖，尚未展开。',
                       'full_dependency_closure': False})
    manifest = {'scope': 'stage1业务函数局部语义审阅；不是消费者/CRT完整依赖闭环',
                'main_va': '0x7c54b0', 'functions': review,
                'pending_message_consumers': ['6000', '6001', '6002', '6003', '6005', '6060', '6062', '6063', '606C', '608B'],
                'pending_data_sources': ['A87104', 'A87108', 'A87110', '文字表加载和索引容量', '演员type67数组容量'],
                'local_semantics_reviewed': len(NOTES), 'full_dependency_closure': False,
                'real_client_verified': False}
    (TOPIC / '阶段1_函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    report = {'disk_sha256': hashlib.sha256(blob).hexdigest(), 'image_base': hex(base),
              'exported_functions': len(functions), 'local_semantics_reviewed': len(NOTES),
              'checks': checks, 'all_matching': all(c['matching'] for c in checks),
              'case_mapping_count': len(sw['case_targets']), 'real_client_verified': False}
    (EVIDENCE / 'stage1_validation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    assert len(sw['case_targets']) == 70
    assert all(c['matching'] for c in checks)
    assert set(NOTES) <= functions.keys()
    print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
