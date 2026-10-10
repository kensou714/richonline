"""固定七种子清单；根与运行库转换只登记历史窄契约。"""
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    sources={name:json.loads((HERE/name).read_text('utf-8')) for name in
             ('formal_functions.json','reused_functions.json','bounded_raw.json')}
    specs=[
        (0,'无符号输入DIV100，商先round到float32，乘+33C经922798取低DWORD后与+340作unsigned max，ret4。',
         '系数/下界生产者、数值单位、特殊浮点和运行时FPU状态未闭；无NULL或错误码门。',
         [('0x6c1ca3',['xor','edx']),('0x6c1caa',['div','ecx']),('0x6c1cb6',['fild','qword']),
          ('0x6c1cb9',['fstp','dword']),('0x6c1cc2',['fmul','0x33c']),('0x6c1cc8',['call','0x60c4c6']),
          ('0x6c1cdc',['jbe']),('0x6c1cf8',['ret','4'])]),
        (1,'与6C1C80同ABI和运算次序，系数用+344、unsigned下界用+348，ret4。',
         '字段生产者、数值单位、特殊浮点和运行时FPU状态未闭；不宣称32位饱和或错误哨兵。',
         [('0x6c1d2a',['div','ecx']),('0x6c1d36',['fild','qword']),('0x6c1d39',['fstp','dword']),
          ('0x6c1d42',['fmul','0x344']),('0x6c1d56',['cmp','0x348']),('0x6c1d5c',['jbe']),('0x6c1d78',['ret','4'])]),
        (2,'返回this+34C字段DWORD；不读取栈参数但ret4由callee清一个DWORD槽。',
         '字段生产者/单位/所有权未闭；本体不检查this指针。',
         [('0x6c1d91',['mov','0x34c']),('0x6c1d9a',['ret','4'])]),
        (3,'两个记录各以+1C乘+10低DWORD输入三helper，三项回绕相加后产生unsigned score(a)<score(b)的0/1。',
         '记录字段生产和回调实际消费未闭；返回诊断异常路径另限；不是qsort三态。',
         [('0x6c08db',['0x1c']),('0x6c08de',['imul','0x10']),('0x6c0918',['call','0x605ce3']),
          ('0x6c0949',['cmp','esi, edi']),('0x6c094b',['sbb','eax, eax']),('0x6c094d',['neg','eax'])]),
        (4,'与6C08B0同取值与三项组合，但产生unsigned score(a)>score(b)的0/1。',
         '记录类型和真实回调执行未知；相等产生0，不提供三态排序契约。',
         [('0x6c098e',['imul','0x10']),('0x6c09c8',['call','0x605ce3']),('0x6c09f9',['cmp','edi, esi']),('0x6c09fd',['neg','eax'])]),
        (5,'两个记录各以+C乘+8低DWORD输入前两helper；各自+4为1或2时加常量第三项，产生unsigned strict <。',
         '类型标签1/2业务含义、字段生产和回调消费未闭；32位乘/加均回绕。',
         [('0x6c0c1c',['imul','8']),('0x6c0c74',['cmp','4','1']),('0x6c0c7d',['cmp','4','2']),
          ('0x6c0c8a',['call','0x605ce3']),('0x6c0cbc',['cmp']),('0x6c0cc1',['neg','eax'])]),
        (6,'与6C0BF0同字段、各自条件及组合，但产生unsigned strict >；相等产生0。',
         '标签和记录类型未命名；运行期字段修改、NULL失败及诊断异常影响不由静态本体验证。',
         [('0x6c0d0c',['imul','8']),('0x6c0d64',['cmp','4','1']),('0x6c0d6d',['cmp','4','2']),
          ('0x6c0d9e',['call','0x605ce3']),('0x6c0dac',['cmp']),('0x6c0db1',['neg','eax'])])]
    functions=[]
    for index,conclusion,unknown,anchors in specs:
        row=sources['formal_functions.json']['functions'][index]
        functions.append(dict(va=row['va'],status='完整分析',conclusion=conclusion,unknown=unknown,
                              evidence_refs=[dict(file='formal_functions.json',pointer='/functions/'+str(index))],
                              declared_chunks=row['declared_chunks'],instruction_count=sum(x['is_code'] for x in row['normalized_assembly']),
                              semantic_anchors=[dict(va=va,tokens=tokens) for va,tokens in anchors]))
    contracts=[]
    for index,anchors in ((0,[('0x628410',['0xa76744']),('0x628419',['0xca0']),('0x628460',['0xa76744'])]),
                          (1,[('0x9227a7',['fistp','qword']),('0x9227ab',['fild','qword']),('0x9227d3',['adc','eax']),
                              ('0x9227da',['adc','edx']),('0x9227eb',['sbb','eax']),('0x9227f2',['sbb','edx'])])):
        row=sources['reused_functions.json']['functions'][index]
        contracts.append(dict(va=row['va'],status='既有局部契约复用',source_path=row['source_path'],source_pointer=row['source_pointer'],
                              source_sha256=row['source_sha256'],evidence_ref=dict(file='reused_functions.json',pointer='/functions/'+str(index)),
                              instruction_count=sum(x['is_code'] for x in row['normalized_assembly']),
                              semantic_anchors=[dict(va=va,tokens=tokens) for va,tokens in anchors]))
    windows=[]
    for index,row in enumerate(sources['bounded_raw.json']['explicit_owner_windows']):
        items=row['assembly'];last=items[-1]
        windows.append(dict(owner_va=row['owner_va'],site_va=row['site_va'],start_va=items[0]['site_va'],
                            end_va=hex(int(last['site_va'],16)+last['bytes']['size']),status='局部窗口分析',
                            conclusion='仅77EE40相邻参数和数值辅助组合。',unknown='槽-10完整生产、6070F7桥与候选6C1A20及owner整业务未闭。',
                            evidence_ref=dict(file='bounded_raw.json',pointer='/explicit_owner_windows/'+str(index))))
    summary=dict(reviewed_functions=7,complete=7,partial=0,new_seed_bodies=7,reviewed_instructions=sum(x['instruction_count'] for x in functions),
                 historical_contracts=len(contracts),historical_contract_instructions=sum(x['instruction_count'] for x in contracts),
                 owner_windows=len(windows),direct_bridges=len(sources['bounded_raw.json']['verified_direct_bridges']))
    ledger=dict(disk_sha256=SHA,scope='第二十五批；完整指七本体局部指令契约，不认运行值、字段producer或完整游戏业务闭合。',
                functions=functions,historical_contracts=contracts,owner_windows=windows,summary=summary)
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n','utf-8');print(json.dumps(summary))


if __name__=='__main__': main()
