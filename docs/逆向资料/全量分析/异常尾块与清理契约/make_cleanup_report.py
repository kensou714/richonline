"""把只读 JSON 证据整理为中文 C++ 注释式资料；不改变中央审计原证。"""
import json
import re
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/全量分析/异常尾块与清理契约'

def op_class(asm):
    text = ' '.join(i['text'] for i in asm)
    if 'ExitProcess' in text:
        return '旧式SEH过滤器的致命退出路径'
    if 'operator delete[]' in text and 'operator delete(void *)' in text:
        return '数组释放与标量释放混合的异常清理动作'
    if 'operator delete[]' in text:
        return 'operator delete[]异常清理动作'
    if 'operator delete(void *)' in text:
        return 'operator delete标量异常清理动作'
    if 'and     eax, 0FFFFFF' in text and 'dword_' in text:
        return '全局静态初始化guard位回滚（可混有其他清理动作）'
    if 'OnInitialUpdate' in text:
        return '字符串兼容布局对象的清理跳板（自动MFC名称不可信）'
    if 'j_unknown_libname' in text:
        return '库对象成员清理跳板，具体类型待补'
    if 'lea     ecx' in text or 'mov     ecx' in text:
        return '局部或成员对象的展开清理跳板；完整类型待定'
    return '异常尾块，动作语义待补'

def state_summary(r):
    if not r['func_info']:
        return '无C++ FuncInfo；主函数挂接旧式SEH。'
    fi = r['func_info']
    entries = fi['unwind_entries']
    targets = len({x['action'] for x in entries})
    resets = sum(x['to_state'] == -1 for x in entries)
    return ('FuncInfo magic=%s，maxState=%d，UnwindMap=%s，唯一动作入口%d个，'
            'toState=-1项%d；动作必须按异常发生时的state逆向执行。' %
            (fi['magic'], fi['max_state'], fi['unwind_map_va'], targets, resets))

def main():
    d = json.loads((HERE / 'cleanup_evidence.json').read_text(encoding='utf-8'))
    contracts = json.loads((HERE / 'cleanup_contracts.json').read_text(encoding='utf-8'))
    by_va = {r['function_va']: r for r in contracts['records']}
    lines = []
    def put(s=''):
        lines.append('// ' + s if s else '//')
    put('RnClient.exe 异常尾块与清理契约资料')
    put('')
    put('用途：记录当前版本异常处理尾块、FuncInfo、UnwindMap 与主函数状态写点。')
    put('证据范围：仅使用 IDA-MCP 只读数据库和当前 PE 原始字节；不把反编译命名当作事实。')
    put('PE SHA-256：' + d['disk_sha256'])
    put('中央尾证 SHA-256：' + d['central_source_sha256'])
    put('')
    put('阅读约定：尾块是异常动作入口，不是正常控制流；toState 链决定已构造对象的逆序清理范围。')
    put('operator delete 只说明释放原始存储，不能单独推出对象的 C++ 类型；跳板目标需结合其实现。')
    put('所有条目均保留未知边界；未做运行时触发测试，结论等级为静态证据。')
    put('FuncInfo bytes 字段只保存从入口起36字节的原证窗口；19930520旧格式可能仅32字节，末4字节可能是相邻数据。')
    put('只明确解释头20字节的 magic/maxState/pUnwindMap/nTryBlocks/pTryBlockMap；remaining_words 不视为已定型字段。')
    put('')
    put('总体统计：记录 %d 条；FuncInfo %d 条；旧式SEH %d 条；主函数/FuncInfo字节不一致 0 条。' %
        (len(d['records']), sum(r['func_info'] is not None for r in d['records']),
         sum(r['func_info'] is None for r in d['records'])))
    by_state = {}
    for r in d['records']:
        key = r['func_info']['max_state'] if r['func_info'] else 'SEH'
        by_state[key] = by_state.get(key, 0) + 1
    put('maxState 分布：' + '，'.join('%s=%d' % (k, by_state[k]) for k in sorted(by_state, key=str)))
    put('状态动作项376项、唯一动作入口375个；87EE40的state1/state2共用A1893B，回退状态不同。')
    put('')
    put('复杂专题')
    put('7DF010：13状态，state 1..6 为数组释放，7..12 为标量释放；state 0 清理 var_A0 双指针对象。')
    put('          UnwindMap 0->-1、1..12->0，说明异常状态回退到已完成的基础对象层；不能线性执行全部13项。')
    put('87FD30：61状态；0为局部对象清理、1..35为独立分支new后构造失败delete、36..43为guard位回滚。')
    put('          44->-1；45->44；46..51->45；52..55->44；56、57、58->-1；59->58；60->59。')
    put('          60异常实际最多经60、59、58三动作退出；state51经51、45、44三动作退出，不能顺序执行61个动作。')
    put('8E24D0：13个 switch 分支共享异常框架，全部 toState=-1；每个动作只释放本分支构造前分配的存储。')
    put('          931190:_CallSettingFrame 接收注册节点R，将EBP设为R+0Ch后call动作；主函数入口ESP=S，R=S-0Ch。')
    put('          所以尾块 [ebp+4]=[S+4]，即主函数arg_0；各case将operator new结果覆写到该参数槽再置state。')
    put('          仍不能据此认定同一对象被重复释放；每个 case 在进入构造调用前写入各自状态。')
    put('91FBB0：旧式 __except_handler3；尾块前两条返回1，后续恢复esp、写异常状态并 ExitProcess(3)。')
    put('          不存在 C++ UnwindMap，不能套用 FuncInfo 清理模型。')
    put('字符串清理：62B8A0 自动名 CControlBar::OnInitialUpdate 不可靠；实参为1和0并转62BAD0。')
    put('          62BAD0 仅在capacity(+18h)>=10h且释放标志非0时释放+4处堆指针，随后capacity=0Fh。')
    put('          62BE10 写length(+14h)并在字符存储length处写NUL；62BFC0调用operator delete。')
    put('          该布局和行为支持带15字符内联存储的string清理契约，不支持按MFC窗口初始化来理解尾块。')
    put('双指针对象：81AD50->81AD80 分别非空检查+0/+4，operator delete后清零；7DF010 state0使用该契约。')
    put('数组对象：7ECD80->7ECF70 检查this+0Ch，operator delete[]后清零；完整类名保持未知。')
    put('结构对象：819220->8193F0 清零+0/+8Ch/+90h/+94h，并释放与清零+4指针；具体类名未知。')
    put('说明：75个真实清理目标实现保存于 cleanup_targets_full.json；运行库3个函数见 unwind_runtime.json。')
    put('')
    put('逐尾块记录（239项）')
    overview_end = len(lines)-1
    directory_blocks = {}
    for n, r in enumerate(sorted(d['records'], key=lambda x: int(x['function_va'], 16)), 1):
        block_start = len(lines)
        t = r['tail']
        put('[%03d] 主函数 %s；尾块 %s-%s（%d字节）；PE/IDB=%s。' %
            (n, r['function_va'], t['va'], hex(int(t['end_va'], 16)), t['size'],
             '一致' if t['matching'] and r['main_bytes']['matching'] else '不一致'))
        put('      分类：%s。' % op_class(t['assembly']))
        put('      %s' % state_summary(r))
        if r['func_info']:
            fi = r['func_info']
            put('      FuncInfo=%s；UnwindMap动作（state->入口）：' % fi['bytes']['va'])
            for offset in range(0, len(fi['unwind_entries']), 6):
                actions = ', '.join('%s->%s' % (e['state'], e['action'])
                                    for e in fi['unwind_entries'][offset:offset+6])
                put('        ' + actions + '。')
            for e in fi['unwind_entries']:
                start = int(e['action'], 16)
                starts = sorted(int(x['action'], 16) for x in fi['unwind_entries'] if int(x['action'], 16)>start)
                end = starts[0] if starts else int(t['end_va'], 16)-10
                asm = [i for i in t['assembly'] if start <= int(i['va'], 16) < end]
                first = asm[0]['text'] if asm else '动作未落在本尾块范围'
                put('      state %d -> %d；%s：%s；对象/槽证据=%s。' %
                    (e['state'], e['to_state'], e['action'], op_class(asm), first))
            put('      主state写点：' + '；'.join(i['va'] for i in r['state_writes']) + '。')
        else:
            put('      主函数状态写点：' + ('；'.join(i['va'] + ' ' + i['text'] for i in r['state_writes']) or '未识别') + '。')
        src = r.get('sources') or []
        if src:
            put('      历史来源：')
            for source in src:
                put('        ' + source.get('source', '') + '#' + source.get('json_pointer', ''))
        put('      语义边界：尾块指令字节已核验；对象完整类型、异常实机触发顺序未由本条静态证据单独证明。')
        directory_blocks[r['function_va']] = lines[block_start:]
    put('')
    put('复核入口：cleanup_evidence.json 保存每条主函数、尾块、FuncInfo 36字节、UnwindMap 8字节项及跳板目标。')
    put('复核脚本：export_cleanup_evidence.py；运行前确认 IDA-MCP 数据库指向当前 PE。')
    put('')
    put('主构造状态与原始存储释放的边界')
    put('136个相同var_14标量delete尾块，均逐主函数核验：operator new返回值存入var_14，再将SEH状态写0。')
    put('主流程接着非空判断并调用构造目标，成功后写state=-1；UnwindMap仅0->-1，一个delete动作。')
    put('这是构造抛出时释放已经分配的原始存储；new自身抛出发生在state置0之前，不能归到该尾块。')
    put('new返回NULL时主流程跳过构造，并走正常路径；该尾块也不是“分配返回NULL”的普通清理分支。')
    put('')
    put('逐动作中文结论（完整条件窗口见 cleanup_contracts.json）')
    detail_blocks = {}
    for r in d['records']:
        block_start = len(lines)
        contract = by_va[r['function_va']]
        put(r['function_va'] + '：' + contract['conclusion'])
        put('    IDA尾块父函数：' + ','.join(r['chunk_parents']) + '；中央历史出处在上方逐项记录。')
        for a in contract['actions']:
            put('    state %d -> %d；动作%s；%s' % (a['state'], a['to_state'], a['va'], a['conclusion']))
            put('    主函数设置证据=' + (','.join(x['write']['va'] for x in a['state_set_evidence']) or '无直接写点') +
                '；完全展开链=' + '->'.join(map(str,a['unwind_chain_to_minus_one'])) + '->-1。')
            put('    未闭合=' + '；'.join(a['unknowns']))
        if r['function_va'] == '0x87ee40':
            put('    特例：state1与state2共用A1893B，1->0而2->-1；主函数从0直接写2，并手动销毁var_200。')
            put('    state1没有直接写点，不判为实机可触发；它在表中保留的历史/编译原因仍未知。')
        detail_blocks[r['function_va']] = lines[block_start:]
    entries = HERE/'逐项记录'
    entries.mkdir(exist_ok=True)
    overview = lines[:overview_end]
    overview += ['//', '// 136个var_14单delete尾块均核验new结果保存、置state0、构造调用及成功state=-1。',
                 '// 它们是已分配原始存储的构造失败回收，new自身抛出与NULL正常分支不触发该动作。',
                 '// 239条目按主函数地址分册，单册最多16个主函数；376状态动作项的结论附在对应主函数后。',
                 '// 机器原证及条件窗口：cleanup_contracts.json；可复验脚本：validate_cleanup.py。', '//']
    ordered = sorted(d['records'], key=lambda x: int(x['function_va'],16))
    for n in range(0,len(ordered),16):
        group = ordered[n:n+16]
        file_name = '%02d_%s_%s.txt' % (n//16+1,group[0]['function_va'][2:].upper(),group[-1]['function_va'][2:].upper())
        content = ['// 异常尾块逐项记录 / '+file_name, '// 来源：cleanup_evidence.json与cleanup_contracts.json；仅静态证据。','//']
        for r in group:
            content += directory_blocks[r['function_va']] + ['//'] + detail_blocks[r['function_va']] + ['//']
        (entries/file_name).write_text('\n'.join(content)+'\n',encoding='utf-8')
        overview.append('// 分册 '+file_name+'；'+str(len(group))+'主函数；'+str(sum(len(by_va[r['function_va']]['actions']) for r in group))+'状态动作项。')
    (HERE / '异常尾块与清理契约.txt').write_text('\n'.join(overview) + '\n', encoding='utf-8')
    return len(lines)

if __name__ == '__main__':
    main()
