"""从固定适配证据生成分级清单；历史外部契约不重复认领。"""
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    sources={name:json.loads((HERE/name).read_text('utf-8')) for name in
             ('formal_functions.json','formal_dependencies.json','reused_functions.json','bounded_raw.json')}
    specs=[
        ('formal_functions.json',0,'部分分析','从当前124字节记录模式选择列表，复制首项到U+D0并提交mask4栈参数。',
         '真实虚槽目标、外部列表生命周期和运行态交互未闭；返回值来自虚调用。',
         [('0x73fcb3',['0x38']),('0x73fd9a',['0x129','0']),('0x73fdb9',['ecx','0x10']),
          ('0x73fdbc',['call','0x60e712']),('0x73fdd4',['0xa4','4']),('0x73fdef',['call','0x10'])]),
        ('formal_functions.json',1,'完整分析','s=0/1/2分别返回R+520/52C/538字段DWORD，其他s返回零。',
         '字段生产者、所指对象分配/释放不在此本体；外部栈诊断深层语义未扩。',
         [('0x6aa86c',['[eax]']),('0x6aa888',['0x520']),('0x6aa893',['0x52c']),('0x6aa89e',['0x538']),('0x6aa8a6',['xor','eax'])]),
        ('formal_functions.json',2,'完整分析','s=0/1/2分别返回R+524/530/53C字段DWORD，其他s返回零。',
         '字段生产者、所指对象分配/释放不在此本体；外部栈诊断深层语义未扩。',
         [('0x6aa908',['0x524']),('0x6aa913',['0x530']),('0x6aa91e',['0x53c']),('0x6aa926',['xor','eax'])]),
        ('formal_functions.json',3,'完整分析','无条件返回R+514字段DWORD；无参数索引和无内部调用。',
         '该字段生产者及对象所有权未闭；本体不校验this指针。',
         [('0x6aa951',['0x514']),('0x6aa95a',['ret'])]),
        ('formal_functions.json',4,'完整分析','仅s==2返回R+51C，所有其他s返回R+518字段DWORD。',
         '字段生产者、所指对象分配/释放不在此本体；外部栈诊断深层语义未扩。',
         [('0x6aa991',['cmp','2']),('0x6aa99c',['0x51c']),('0x6aa9a7',['0x518'])]),
        ('formal_functions.json',5,'完整分析','s=0/1/2分别返回R+528/534/540字段DWORD，其他s返回零。',
         '字段生产者、所指对象分配/释放不在此本体；外部栈诊断深层语义未扩。',
         [('0x6aaa08',['0x528']),('0x6aaa13',['0x534']),('0x6aaa1e',['0x540']),('0x6aaa26',['xor','eax'])]),
        ('formal_dependencies.json',0,'完整分析','直接返回列表对象+8保存的DWORD；不遍历链表计数。',
         '计数字段更新/生产路径未在本体定义；不保证与链长一致。',
         [('0x79a1f1',['[eax + 8]']),('0x79a1f7',['ret'])]),
        ('formal_dependencies.json',1,'完整分析','从head按+80 next遍历索引，再无条件复制32 DWORD至out并返回out，ret8。',
         '不校验源/目标/索引/环/DF/重叠；分配总大小和字符串终止约束未闭。',
         [('0x79ca6a',['[eax]']),('0x79ca82',['0x80']),('0x79ca99',['0x20']),
          ('0x79caa1',['rep movsd']),('0x79caa3',['[ebp + 8]']),('0x79caab',['ret','8'])]),
        ('formal_dependencies.json',2,'完整分析','从head按+80 next遍历到索引或NULL，返回当前节点，ret4。',
         '不使用count，不校验负索引、环、计数回绕或节点有效性；所有权未闭。',
         [('0x79caf8',['[eax]']),('0x79cb10',['0x80']),('0x79cb24',['eax','0xc']),('0x79cb2a',['ret','4'])]),
        ('reused_functions.json',0,'部分分析','复读mask1/2/4、U字段及最多三条链表分页消费；与首项虚调仅形态相容。',
         '外部配置/控件/预览契约未全闭；模式来源等价、真实虚槽归属与运行态交互未知。',
         [('0x73f471',['0x4c']),('0x73f4b9',['call','0x60d05b']),('0x73f642',['call','0x6075b6']),
          ('0x73f6bf',['call','0x609cf3']),('0x73f6fd',['call','0x607c32'])])]
    functions=[]
    for name,index,status,conclusion,unknown,anchors in specs:
        evidence=sources[name]['functions'][index]
        functions.append(dict(va=evidence['va'],status=status,conclusion=conclusion,unknown=unknown,
                              evidence_refs=[dict(file=name,pointer='/functions/'+str(index))],
                              semantic_anchors=[dict(va=va,tokens=tokens) for va,tokens in anchors],
                              declared_chunks=evidence['declared_chunks'],
                              instruction_count=sum(item['is_code'] for item in evidence['normalized_assembly'])))
    windows=[]
    for index,row in enumerate(sources['bounded_raw.json']['explicit_owner_windows']):
        assembly=row['assembly'];last=assembly[-1]
        windows.append(dict(owner_va=row['owner_va'],site_va=row['site_va'],
                            start_va=assembly[0]['site_va'],
                            end_va=hex(int(last['site_va'],16)+last['bytes']['size']),
                            status='局部窗口分析',conclusion='仅承认采证窗口内的读取器调用和相邻参数消费。',
                            unknown='不认领窗口owner整函数或其完整控制流。',
                            evidence_ref=dict(file='bounded_raw.json',pointer='/explicit_owner_windows/'+str(index))))
    reused=[dict(va=row['va'],status='既有局部契约复用',source_path=row['source_path'],
                 source_pointer=row['source_pointer'],source_sha256=row['source_sha256'],
                 instruction_count=sum(item['is_code'] for item in row['normalized_assembly']))
            for row in sources['reused_functions.json']['functions'][1:]]
    ledger=dict(disk_sha256=SHA,scope='第二十三批地图选择字段与列表消费；完整指局部本体契约，不代表外部调用图全闭。',
                functions=functions,owner_windows=windows,historical_contracts=reused,
                summary=dict(reviewed_functions=10,complete=8,partial=2,owner_windows=len(windows),
                             historical_contracts=len(reused),
                             historical_contract_instructions=sum(row['instruction_count'] for row in reused)))
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(ledger['summary'],ensure_ascii=True))


if __name__=='__main__':
    main()
