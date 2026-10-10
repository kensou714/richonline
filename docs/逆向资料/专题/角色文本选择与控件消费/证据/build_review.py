"""生成固定分级清单；语义为作者逐指令审阅结果，计数从冻结原证计算。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SPEC = {
 '0x6f4db0': ('完整分析', 'cdecl一参数；R的记录类别为2或7时，按另一根的有符号数量扫描R的角色标记BYTE，首非零i调用T的(10,47,i+40,-1)并直接返回；未匹配返回-1。', '输入索引合法域、标记数组容量、资源47业务名及运行时UI效果未证。', [('0x6f4ddf',['cmp eax, 2']),('0x6f4df0',['cmp eax, 7']),('0x6f4e1c',['jge']),('0x6f4e2e',['movzx eax, al']),('0x6f4e3c',['0x28']),('0x6f4e40',['0x2f']),('0x6f4e42',['0xa']),('0x6f4e50',['jmp 0x6f4e55']),('0x6f4e52',['0xffffffff']),('0x6f4e62',['ret'])]),
 '0x7014a0': ('完整分析', 'thiscall一索引、ret4；读DWORD[DWORD[this]+1128*index+12]，本体无范围或空指针检查。', '记录生产者对index与根初始化的保障不在本函数内；类别2/7正式业务名待证。', [('0x7014b1',['0x468']),('0x7014ba',['[ecx]']),('0x7014bc',['0xc']),('0x7014c3',['ret 4'])]),
 '0x756460': ('部分分析', '输入指针两DWORD分别写this+48/+4C；this+4C传6F4DB0，结果无-1过滤进入控件7的6FA7F0；另有期限图像及文本接口。', '列表提供者、虚函数具体派生实现及调用注册/用户触发未完整恢复；不认整函数业务完成。', [('0x75649a',['0x48']),('0x7564a6',['0x4c']),('0x75663a',['0x4c']),('0x75663e',['call 0x60bfdf']),('0x756646',['push eax']),('0x756649',['push 7']),('0x756658',['call 0x60bb48'])]),
 '0x762e10': ('部分分析', 'this+64与第二gate的AL共同决定刷新；取DWORD[buffer+4*selection+4]给6F4DB0，无-1门直交控件C3；门失败仍进入76308F后布局路径；ret4但未读取栈参数。', '选择列表生产、容量与后半尺寸/位置函数完整业务契约未恢复；不认整函数业务完成。', [('0x762e3a',['0x64']),('0x762e40',['je 0x76308f']),('0x762e57',['je 0x76308f']),('0x762e60',['0x64','0']),('0x762ead',['ecx*4 + 4']),('0x762fcc',['call 0x60bfdf']),('0x762fd4',['push eax']),('0x762fd7',['0xc3']),('0x762fe9',['call 0x60bb48']),('0x76315d',['ret 4'])]),
 '0x627c20': ('复用局部契约', 'A766E0懒取根R，分配14C；R+0为本批1128字节记录数组基址。', '构造器及分配失败业务恢复不展开。', [('0x627c50',['0xa766e0']),('0x627c59',['0x14c']),('0x627ca0',['0xa766e0'])]),
 '0x6dba40': ('复用局部契约', 'case10由48字节跳表独证；有符号检查两个索引，读DWORD[T的3AC00指针+1200*a3+12*a4+4]，本题a3=47/a4=i+40。', '其他case及图像记录生产不在本批语义认领；case10没有根或数据指针NULL门。', [('0x6dba74',['0x6dbdb4']),('0x6dbac1',['jl']),('0x6dbac9',['0x3abfc']),('0x6dbacf',['jge']),('0x6dbad7',['0x64']),('0x6dbadb',['jge']),('0x6dbae0',['0x4b0']),('0x6dbae9',['0x3ac00']),('0x6dbaf2',['0xc']),('0x6dbaf5',['+ 4]'])]),
 '0x6276a0': ('复用局部契约', 'A766D0懒取独立档案根，分配8；本题仅经646590读取根首DWORD计数。', '档案3204字节记录不与R的1128字节记录合并。', [('0x6276d0',['0xa766d0']),('0x6276d9',['push 8']),('0x62771d',['0xa766d0'])]),
 '0x627760': ('复用局部契约', 'A766B0懒取图像资源根T，分配99FE8；供6DBA40查询。', '根构造和加载过程不在本批展开。', [('0x627790',['0xa766b0']),('0x627799',['0x99fe8']),('0x6277e0',['0xa766b0'])]),
 '0x646610': ('复用局部契约', 'ECX=R，两个参数为i/input；取record(input)+14h的指针后读第i个BYTE，ret8。', '指针容量、i上限和input合法域无本地保护。', [('0x646621',['0x468']),('0x64662c',['0x14']),('0x646633',['mov al, byte ptr [eax + ecx]']),('0x646639',['ret 8'])]),
 '0x6fa7f0': ('复用局部契约', 'ECX=C，单个数值参数包装为8E1C70(C,C+A4,0,value)；ret4。', '返回寄存器不定义统一成功标志；资源加载与绘制不在包装器内。', [('0x6fa802',['push 0']),('0x6fa807',['0xa4']),('0x6fa811',['call 0x60da8d']),('0x6fa823',['ret 4'])]),
 '0x646590': ('复用局部契约', '返回DWORD[this]；本题this来自6276A0，解释为扫描数量。', '单独函数无类别、计数正值或NULL检查。', [('0x6465a1',['mov eax, dword ptr [eax]'])]),
 '0x8e1c70': ('复用局部契约', '写P+40*state+24图像数值；旧值变化且旧值非-1时可调ACC3C8+2C回调，再写新值；依据C+180/+181门刷新。', '回调表实例及绘图效果复用旧专题；没有value=-1拒绝门。', [('0x8e1c85',['eax*8 + 0x18']),('0x8e1c91',['cmp eax, -1']),('0x8e1c9c',['0x2c']),('0x8e1caa',['mov dword ptr [ebx], ebp']),('0x8e1cac',['0x181']),('0x8e1cb6',['0x180']),('0x8e1cd5',['call 0x6033ee'])]),
}


def main():
    groups = {}
    for name in ('formal_functions.json','reused_functions.json'):
        data = json.loads((HERE/name).read_text('utf-8'))
        for i, source in enumerate(data['functions']):
            va = source['va']
            status, conclusion, unknown, anchors = SPEC[va]
            groups[va] = dict(va=va, status=status, conclusion=conclusion, unknown=unknown,
                              evidence_ref=dict(file=name,pointer='/functions/'+str(i)),
                              source_sha256=source['source_sha256'],declared_chunks=source['declared_chunks'],
                              instruction_count=sum(x['is_code'] for x in source['normalized_assembly']),
                              semantic_anchors=[dict(va=address,tokens=tokens) for address,tokens in anchors])
    seeds = ['0x6f4db0','0x7014a0','0x756460','0x762e10']
    functions = [groups[x] for x in seeds]
    historical = [value for va,value in groups.items() if va not in seeds]
    raw = json.loads((HERE/'bounded_raw.json').read_text('utf-8'))
    windows = []
    for i, row in enumerate(raw['explicit_owner_windows']):
        last = row['assembly'][-1]
        windows.append(dict(owner_va=row['owner_va'],site_va=row['site_va'],status='局部窗口分析',
                            start_va=row['assembly'][0]['site_va'],end_va=hex(int(last['site_va'],16)+last['bytes']['size']),
                            evidence_ref=dict(file='bounded_raw.json',pointer='/explicit_owner_windows/'+str(i)),
                            conclusion=('对象+50传入，返回后压0/7' if i==0 else '局部var_140传入，返回后压0/139Fh'),
                            unknown='前后五指令窗口不能证明完整owner、变量生产或最终控件调用。'))
    ledger = dict(schema='richonline.bounded-semantic-review.v1',disk_sha256=SHA,
                  topic='角色标记图像选择与控件消费；历史目录名保留',functions=functions,historical_contracts=historical,owner_windows=windows,
                  data_evidence=[dict(file='switch_table/bounded_raw.json',pointer='/data_windows/0',conclusion='6DBDB4起12项48B，slot10=6DBABD；不计函数覆盖')],
                  summary=dict(reviewed_functions=4,complete=2,partial=2,reviewed_instructions=sum(x['instruction_count'] for x in functions),
                               historical_contracts=8,historical_contract_instructions=sum(x['instruction_count'] for x in historical),
                               owner_windows=2,direct_bridges=32),
                  boundary='完整仅指两新函数局部静态契约；两旧consumer部分分析、八旧helper复用、两显式窗口分列；非客户端动态验证。')
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(ledger['summary'],ensure_ascii=True))


if __name__ == '__main__':
    main()
