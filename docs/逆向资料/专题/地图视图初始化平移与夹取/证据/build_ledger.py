"""固定种子、尺寸本体、桥与历史契约分级登记，不扩大窗口覆盖。"""
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    sources={name:json.loads((HERE/name).read_text('utf-8')) for name in
             ('formal_functions.json','formal_dependencies.json','reused_functions.json','bounded_raw.json')}
    specs=[
        ('formal_functions.json',0,'完整分析','四DWORD槽取低WORD，初始化两矩形、地图边界及两零字段，ret10h并返回this。',
         '未写字段和第二矩形实际显示用途未知；本体不做夹取或参数校验。',
         [('0x7b6ca1',['word ptr','8']),('0x7b6ca5',['word ptr','[eax]']),('0x7b6cf4',['0x18']),
          ('0x7b6cff',['0x1a']),('0x7b6d06',['0x262']),('0x7b6d0f',['0x218']),('0x7b6d46',['ret','0x10'])]),
        ('formal_functions.json',1,'完整分析','符号扩展两套左上WORD，加DWORD位移，截断写回后调用7B6D50；ret8。',
         '栈诊断深层行为未扩；返回寄存器不作为统一成功标志。',
         [('0x7b6f01',['movsx','4']),('0x7b6f05',['add','dword ptr']),('0x7b6f2d',['word ptr','0x20']),
          ('0x7b6f45',['call','0x611697']),('0x7b6f57',['ret','8'])]),
        ('formal_functions.json',2,'部分分析','从G+C14第一矩形左上向C+18/+1C目标按步进移动，未达经计时门，已达返回1。',
         '对象生命周期、目标和步进生产者、计时初值及触发时机未闭；到达当步仍返回0。',
         [('0x63817f',['call','0x60be81']),('0x63819e',['0x18']),('0x6381b2',['eax','1']),
          ('0x6381c2',['call','0x6107f1']),('0x63821e',['0xc']),('0x6382cf',['call','0x60ee10']),('0x6382d4',['xor','eax'])]),
        ('formal_functions.json',3,'部分分析','坐标阈值或37/39及38/40门产生25单位位移；左、上优先；非零时平移G+C14。',
         '外部输入对象、坐标空间、按键值来源和触发时机未闭；无统一成功返回。',
         [('0x650c2a',['0x19']),('0x650c51',['cmp']),('0x650c55',['push','0x25']),('0x650c72',['jmp','0x650cad']),
          ('0x650cc3',['push','0x26']),('0x650ce1',['jmp','0x650d1c']),('0x650d33',['0xc14']),('0x650d39',['call','0x60ee10'])]),
        ('reused_functions.json',0,'完整分析','两矩形各先左上夹零，再写WORD右下，超地图界时回推左上；有符号WORD比较。',
         '地图界小于视图尺寸时会回推负左上；无二次夹零，WORD回绕不等于无限精度clamp；EAX路径相关。',
         [('0x7b6d61',['movsx','4']),('0x7b6d98',['word ptr','8']),('0x7b6dc3',['jle']),
          ('0x7b6de5',['word ptr','4']),('0x7b6e2e',['word ptr','0x20']),('0x7b6ee0',['word ptr','0x22'])]),
        ('reused_functions.json',1,'完整分析','对编号两次有符号除以M+1C，余数写outX，商写outY且返回商；ret0Ch。',
         '不检查除零、INT_MIN/-1、索引范围和输出指针。',
         [('0x7e1614',['cdq']),('0x7e1615',['idiv','0x1c']),('0x7e161b',['edx']),
          ('0x7e1624',['idiv','0x1c']),('0x7e162a',['eax']),('0x7e162f',['ret','0xc'])]),
        ('reused_functions.json',2,'完整分析','除余得格坐标，DWORD中心64*x+32、48*y+24减signed WORD尺寸SAR1，截断写两左上后夹取。',
         '负奇数半尺寸向负无穷，中心与WORD可回绕；编号合法性和诊断依赖未扩。',
         [('0x7b6f98',['call','0x607eb7']),('0x7b6fa0',['shl','6']),('0x7b6fa9',['imul','0x30']),
          ('0x7b6fc7',['sar','1']),('0x7b6fd1',['word ptr','4']),('0x7b7017',['call','0x611697'])]),
        ('formal_dependencies.json',2,'完整分析','返回DWORD[M+1C]左移6所得地图横向像素界；无内部调用。',
         '列数生产者和有效范围不在本体；DWORD回绕保留。', [('0x691a01',['0x1c']),('0x691a04',['shl','6'])]),
        ('formal_dependencies.json',3,'完整分析','返回DWORD[M+20]乘48所得地图纵向像素界；无内部调用。',
         '行数生产者和有效范围不在本体；DWORD回绕保留。', [('0x691a31',['0x20']),('0x691a34',['imul','0x30'])])]
    def record(name,index,status,conclusion,unknown,anchors):
        row=sources[name]['functions'][index]
        return dict(va=row['va'],status=status,conclusion=conclusion,unknown=unknown,
                    evidence_refs=[dict(file=name,pointer='/functions/'+str(index))],
                    declared_chunks=row['declared_chunks'],instruction_count=sum(x['is_code'] for x in row['normalized_assembly']),
                    semantic_anchors=[dict(va=va,tokens=tokens) for va,tokens in anchors])
    functions=[record(*spec) for spec in specs]
    contracts=[]
    for index,anchors in ((3,[('0x64f504',['0x65c']),('0x64f50f',['push','eax']),('0x64f51f',['0x239']),
                            ('0x64f524',['0x26d']),('0x64f52c',['0xc14']),('0x64f541',['push','0'])]),
                          (4,[('0x63e0f1',['add','0xc14'])]),(5,[('0x63e011',['add','4'])]),
                          (6,[('0x81bd43',['jbe']),('0x81bd53',['jb']),('0x81bd67',['4','eax']),('0x81bd6a',['al','1'])])):
        row=sources['reused_functions.json']['functions'][index]
        contracts.append(dict(va=row['va'],status='既有局部契约复用',source_path=row['source_path'],
                              source_pointer=row['source_pointer'],source_sha256=row['source_sha256'],
                              evidence_ref=dict(file='reused_functions.json',pointer='/functions/'+str(index)),
                              instruction_count=sum(x['is_code'] for x in row['normalized_assembly']),
                              semantic_anchors=[dict(va=va,tokens=tokens) for va,tokens in anchors]))
    bridges=[]
    for index,target in ((0,'0x6919f0'),(1,'0x691a20')):
        row=sources['formal_dependencies.json']['functions'][index]
        bridges.append(dict(va=row['va'],status='直接跳板核验',source_sha256=row['source_sha256'],
                            evidence_ref=dict(file='formal_dependencies.json',pointer='/functions/'+str(index)),
                            instruction_count=1,semantic_anchors=[dict(va=row['va'],tokens=['jmp',target])]))
    windows=[]
    for index,row in enumerate(sources['bounded_raw.json']['explicit_owner_windows']):
        items=row['assembly'];last=items[-1]
        windows.append(dict(owner_va=row['owner_va'],site_va=row['site_va'],start_va=items[0]['site_va'],
                            end_va=hex(int(last['site_va'],16)+last['bytes']['size']),status='局部窗口分析',
                            conclusion='仅初始化尺寸、参数栈与居中调用局部契约。',unknown='不认领64F2A0全业务控制流。',
                            evidence_ref=dict(file='bounded_raw.json',pointer='/explicit_owner_windows/'+str(index))))
    summary=dict(reviewed_functions=9,complete=7,partial=2,new_seed_bodies=4,deepened_historical_bodies=3,
                 new_dimension_bodies=2,direct_bridges=2,owner_windows=4,historical_contracts=4,
                 reviewed_instructions=sum(x['instruction_count'] for x in functions),
                 historical_contract_instructions=sum(x['instruction_count'] for x in contracts))
    ledger=dict(disk_sha256=SHA,scope='第二十四批；完整指声明块内局部契约，不表示全部外部调用图闭合。',
                functions=functions,direct_bridges=bridges,owner_windows=windows,historical_contracts=contracts,summary=summary)
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(summary,ensure_ascii=True))


if __name__=='__main__':
    main()
