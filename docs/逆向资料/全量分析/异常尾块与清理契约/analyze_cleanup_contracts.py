"""拆分清理动作并关联主函数证据，未证明的类型与执行条件显式保留。"""
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent

def immediate(text):
    match = re.search(r',\s*([0-9A-F]+h|[0-9]+)(?:\s*;.*)?$', text)
    if not match:
        return None
    value = match.group(1)
    number = int(value[:-1], 16) if value.endswith('h') else int(value)
    return number - 0x100000000 if number >= 0x80000000 else number

def state_write(i):
    text = i['text']
    return text.lstrip().startswith('mov ') and ('var_4]' in text or '[ebp-4]' in text)

def main():
    evidence = json.loads((HERE / 'cleanup_evidence.json').read_text(encoding='utf-8'))
    target_data = json.loads((HERE / 'cleanup_targets_full.json').read_text(encoding='utf-8'))
    targets = {f['va']: f for f in target_data['functions']}
    records = []
    for record in evidence['records']:
        tail = record['tail']
        assembly = record['main_assembly']
        fi = record['func_info']
        entry = dict(function_va=record['function_va'], tail_va=tail['va'],
                     status='静态动作与表关联已核验；未进行运行时异常触发',
                     sources=record['sources'], actions=[], unknowns=[],
                     full_evidence='cleanup_evidence.json#/records/%d' % evidence['records'].index(record))
        if fi is None:
            entry['classification'] = '安全cookie失败路径的旧式SEH退出'
            entry['conclusion'] = '返回1的过滤器，handler恢复ESP后调用ExitProcess(3)；主范围挂接__except_handler3。'
            entry['scope_table'] = evidence['seh_scope']
            entry['unknowns'] = ['未注入异常实测。']
            records.append(entry)
            continue
        table = fi['unwind_entries']
        starts = sorted(int(e['action'], 16) for e in table)
        for state in table:
            start = int(state['action'], 16)
            end = min([p for p in starts if p>start] or [int(tail['end_va'], 16)-10])
            insns = [i for i in tail['assembly'] if start<=int(i['va'],16)<end]
            text = '\n'.join(i['text'] for i in insns)
            action = dict(state=state['state'], to_state=state['to_state'], va=state['action'],
                          instructions=insns, state_set_evidence=[], main_slot_references=[],
                          implementation_evidence=[], conclusion='', unknowns=[])
            # 状态关联只记录明确立即数写入；局部var_4也可能是普通变量，需SEH框架交叉核对。
            for n, i in enumerate(assembly):
                if state_write(i) and immediate(i['text']) == state['state']:
                    action['state_set_evidence'].append(dict(write=i, before=assembly[max(0,n-6):n],
                                                            after=assembly[n+1:n+9]))
                elif state_write(i) and state['state'] == 0 and immediate(i['text']) is None:
                    source = re.search(r',\s*([a-z]{3})$', i['text'])
                    if source:
                        reg = source.group(1)
                        prev = assembly[max(0,n-128):n]
                        writes = [p for p in prev if re.match(r'(?:xor|mov|or|add|sub|pop)\s+'+reg+r'\b',p['text'].strip())]
                        if writes and re.match(r'xor\s+'+reg+r',\s*'+reg+r'$',writes[-1]['text'].strip()):
                            action['state_set_evidence'].append(dict(write=i, zero_register_evidence=writes[-1],
                                                                    before=prev,after=assembly[n+1:n+9]))
            slots = list(dict.fromkeys(re.findall(r'\[(?:ebp[^\]]*)\]', text)))
            for slot in slots:
                refs = [i for i in assembly if slot in i['text']]
                action['main_slot_references'].append(dict(slot=slot, instructions=refs))
            implementation = []
            for i in insns:
                for target in i.get('direct_targets', []):
                    va = target['implementation']
                    implementation.append(va)
                    if va in targets:
                        action['implementation_evidence'].append(dict(va=va,
                            evidence='cleanup_targets_full.json#/functions/%d' % target_data['functions'].index(targets[va])))
            if 'operator delete[]' in text:
                action['classification'] = '数组原始存储释放'
                action['conclusion'] = '从%s取指针后调用operator delete[]；动作返回，不向下一动作自然贯穿。' % (slots[0] if slots else '栈槽')
                action['unknowns'] = ['元素类型与数组构造过程需结合主函数调用目标确认。']
            elif 'operator delete(void *)' in text:
                action['classification'] = '标量原始存储释放'
                action['conclusion'] = '从%s取指针后调用operator delete；动作返回，不调用该指针对象的完整析构函数。' % (slots[0] if slots else '栈槽')
                action['unknowns'] = ['具体构造类名不由delete入口证明。']
            elif 'and     eax, 0FFFFFF' in text and 'dword_' in text:
                action['classification'] = '静态初始化guard回滚'
                action['conclusion'] = '按立即掩码清除全局guard位；主函数guard引用及置位由guard_evidence保存。'
                globals_ = list(dict.fromkeys(re.findall(r'dword_[0-9A-F]+', text)))
                action['guard_evidence'] = [i for i in assembly if any(g in i['text'] for g in globals_)]
                action['unknowns'] = ['guard对应对象的正式C++类型与跨线程安全性未闭合。']
            elif '0x62b8a0' in implementation:
                action['classification'] = '15字符内联string兼容布局清理'
                action['conclusion'] = '62B8A0传(释放标志1,长度0)至62BAD0；capacity>=16时释放堆指针，随后恢复capacity15和length0。'
                action['unknowns'] = ['精确模板typedef及字符串字符编码未由清理函数证明。']
            elif '0x81ad50' in implementation:
                action['classification'] = '双指针成员清理'
                action['conclusion'] = '81AD50->81AD80分别释放对象+0/+4非空指针并清零。'
                action['unknowns'] = ['双指针对象业务类型未闭合。']
            elif '0x819220' in implementation:
                action['classification'] = '结构对象成员清理'
                action['conclusion'] = '819220->8193F0释放+4指针，并清零+0/+8Ch/+90h/+94h。'
                action['unknowns'] = ['业务类型和各已清零字段的正式名未闭合。']
            elif '0x7ecd80' in implementation:
                action['classification'] = '数组指针成员清理'
                action['conclusion'] = '7ECD80->7ECF70非空检查对象+0Ch指针，调用operator delete[]后清零。'
                action['unknowns'] = ['完整业务类名、数组元素类型与构造过程未闭合。']
            elif '0x642580' in implementation:
                action['classification'] = '无资源动作的空清理'
                action['conclusion'] = '642580只保存this、恢复栈并return，不释放或改写对象成员。'
                action['unknowns'] = ['空析构类的正式类型未知。']
            else:
                action['classification'] = '对象展开清理目标'
                action['conclusion'] = 'ECX调整、直接调用/跳转的真实目标已核验，详见本动作指令及implementation_evidence。'
                action['unknowns'] = ['完整业务类名与详细资源契约仍待补；cleanup_targets_full.json保存目标完整原证，不代表目标语义已闭合。']
            chain = []
            cursor = state['state']
            while cursor >= 0:
                if cursor in chain or cursor >= len(table):
                    raise ValueError(('异常展开链', record['function_va'], cursor))
                chain.append(cursor)
                cursor = table[cursor]['to_state']
            action['unwind_chain_to_minus_one'] = chain
            if not action['state_set_evidence']:
                action['unknowns'].append('主函数未找到直接设置该state的写点；仅有展开表引用，可能是仅供回退的中间状态。')
            entry['actions'].append(action)
        entry['classification'] = '；'.join(dict.fromkeys(a['classification'] for a in entry['actions']))
        entry['conclusion'] = '%d个状态动作项、%d个唯一动作入口；逐state链与栈槽已分离，所有动作入口均位于中央尾块内。' % (len(table),len(set(a['va'] for a in entry['actions'])))
        entry['unknowns'] = ['静态状态链描述异常展开契约，不能声称已实机触发全部路径。']
        tail_ins = tail['assembly']
        if len(tail_ins)==7 and 'operator delete(void *)' in tail_ins[2]['text'] and '[ebp+var_14]' in tail_ins[0]['text']:
            proof=[]
            for n,i in enumerate(assembly):
                if not re.search(r'mov\s+\[ebp\+var_4\], 0$',i['text']):continue
                before=assembly[max(0,n-4):n]
                if not (any('operator new(uint)' in x['text'] for x in before) and
                        any(re.search(r'mov\s+\[ebp\+var_14\], eax',x['text']) for x in before)):
                    continue
                reset=next((p for p in range(n+1,len(assembly))
                            if re.search(r'mov\s+\[ebp\+var_4\], 0FFFFFFFFh$',assembly[p]['text'])),None)
                if reset is not None:
                    proof=assembly[max(0,n-5):reset+1]
                    break
            if proof:
                entry['construction_failure_proof'] = proof
                entry['classification'] = 'operator new成功后构造失败的原始存储回收'
                entry['conclusion'] = 'new结果写var_14，设置state0后执行非空判断和构造调用，成功状态重置-1；异常只执行一项delete。'
                entry['actions'][0]['conclusion'] += ' 主构造时序已逐项核验，new自身抛出及NULL正常分支不触发此动作。'
        records.append(entry)
    output = dict(disk_sha256=evidence['disk_sha256'], records=records,
                  summary=dict(records=len(records), state_action_items=sum(len(r['actions']) for r in records),
                               unique_action_entries=len({a['va'] for r in records for a in r['actions']}),
                               no_state_write=[(r['function_va'],a['state']) for r in records for a in r['actions'] if not a['state_set_evidence']]))
    (HERE/'cleanup_contracts.json').write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf-8')
    reviews = []
    for index, record in enumerate(records):
        unknowns = list(dict.fromkeys(record['unknowns'] +
                        [u for a in record['actions'] for u in a['unknowns']]))
        reviews.append(dict(va=record['function_va'], status='异常尾块局部契约已核',
            conclusion='仅异常尾块局部契约：' + record['conclusion'],
            unknown='主函数完整语义未由本次局部契约审阅证明；' + '；'.join(unknowns),
            evidence=['cleanup_contracts.json#/records/%d' % index, record['full_evidence']],
            full_dependency_closure=False))
    review_data = dict(disk_sha256=evidence['disk_sha256'],
        scope='239主函数的异常尾块局部契约；不等于主函数完整语义审阅或运行时验证', functions=reviews)
    (HERE/'function_review.json').write_text(json.dumps(review_data,ensure_ascii=False,indent=2),encoding='utf-8')
    return output['summary']

if __name__ == '__main__':
    print(main())
