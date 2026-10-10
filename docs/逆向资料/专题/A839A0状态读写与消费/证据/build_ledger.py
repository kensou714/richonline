"""将人工逐指令结论编入稳定清单；不自动提升未知依赖。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    rows = []
    def add(va, file, index, conclusion, anchors, unknown, exported=True):
        rows.append(dict(va=va, status='完整审阅', conclusion=conclusion, unknown=unknown,
                         coverage='本批新导出并审阅' if exported else '历史仅导出记录在本批审阅；不是新增导出',
                         evidence_refs=[dict(file=file, pointer='/functions/' + str(index))],
                         semantic_anchors=[dict(va=site, tokens=tokens) for site, tokens in anchors]))
    add('0x6b8320', 'formal_functions.json', 0,
        'cdecl整DWORD覆盖A839A0并在EAX返回参数；不校验、规范化或保留旧值的未知位。',
        [('0x6b8323', ['mov', 'eax, dword ptr [ebp + 8]']), ('0x6b8326', ['mov', 'dword ptr [0xa839a0], eax']), ('0x6b832c', ['ret'])],
        '生产参数范围、业务初值与线程约束未闭合。')
    for va, mask, index, exported in [('0x6b77b0',2,0,False), ('0x796db0',4,1,True), ('0x7978b0',8,2,True)]:
        ea = int(va,16)
        add(va, 'formal_functions.json' if exported else 'reused_functions.json', index,
            f'读取A839A0 DWORD，返回对应掩码{mask}未设置时的32位1，否则0；NEG/SBB/INC归一化。',
            [(hex(ea+3),['mov','dword ptr [0xa839a0]']), (hex(ea+8),['and',f'eax, {mask}']),
             (hex(ea+11),['neg','eax']), (hex(ea+13),['sbb','eax, eax']), (hex(ea+15),['inc','eax'])],
            '位业务命名与完整上层可达条件未闭合。',exported)
    add('0x798d10', 'formal_functions.json', 3, '读取A839A0完整DWORD并通过EAX原样返回。',
        [('0x798d13',['mov','eax, dword ptr [0xa839a0]']),('0x798d19',['ret'])],
        '共享状态的有效域与运行初值未知。')
    for va, mask, index in [('0x798d20',2,4),('0x798d40',4,5),('0x798d60',8,6)]:
        ea=int(va,16)
        add(va,'formal_functions.json',index,
            f'A839A0 DWORD读-或{mask}-写，保留其他位，EAX返回整个新DWORD；非原子读改写。',
            [(hex(ea+3),['mov','dword ptr [0xa839a0]']), (hex(ea+8),['or',f'eax, {mask}']),
             (hex(ea+11),['mov','dword ptr [0xa839a0], eax'])],
            '未知位业务含义、并发约束及状态持久化不在本体内。')
    add('0x768080','formal_functions.json',7,
        '完整本体恢复四路事件分派、DWORD记录和页索引、BYTE选择、DWORD计时；分页更新控件，选择提交按记录1/2/3置位并将整状态有符号十进制串传828F60(60,buffer)，正常返回AL=1。外依赖及真实用户可达性按正文限定。',
        [('0x7680ba',['mov','ecx, dword ptr [ebp + 8]']),('0x7680c8',['sub','ecx, 0xb']),
         ('0x7680db',['jmp','0x768455']),('0x7680f4',['mov','dword ptr [ecx + 0x54], eax']),
         ('0x768103',['mov','dword ptr [ecx + 0x4c], eax']),('0x768210',['mov','dword ptr [edx + 0x4c], ecx']),
         ('0x7682f6',['movzx','byte ptr [edx + 0x50]']),('0x768307',['cmp','1']),
         ('0x76830d',['cmp','2']),('0x768313',['cmp','3']),('0x76831b',['call','0x6114ad']),
         ('0x768322',['call','0x61224a']),('0x768329',['call','0x604de3']),
         ('0x768350',['call','0x60d92a']),('0x76835b',['lea','[ebp - 0x44]']),
         ('0x76836b',['push','0x3c']),('0x76836d',['call','0x6042da']),
         ('0x76839c',['cmp','dword ptr [eax + 0x48], 0']),('0x7683a0',['jle','0x7683f9']),
         ('0x7683b1',['mov','byte ptr [eax + 0x50], dl']),('0x7683f9',['mov','al, 1']),('0x768423',['ret','8'])],
        '真实对象构造、入口触发、虚槽实现、资源范围校验、分派下层网络效果、并发与时间戳消费者未闭合。')
    dependency=json.loads((HERE/'case60_dependency_raw.json').read_text('utf-8'))
    for index, row in enumerate(dependency['functions']):
        va=row['va']
        if va=='0x82e230':
            add(va,'case60_dependency_raw.json',index,
                '完整69字节本体，原栈字符串作为参数交6059A0->8A06C0；ECX保存后恢复并透传下层；ret4，返回下层结果。',
                [('0x82e25a',['call','0x6059a0']),('0x82e272',['ret','4'])],
                '8A06C0未满足本批字节原证条件；借用指针的复制、排队、网络与持久化未知。')
        else:
            target={'0x6005e0':'0x82ab80','0x600cc5':'0x82e230','0x60df01':'0x82a900','0x60ed48':'0x8976e0'}[va]
            add(va,'case60_dependency_raw.json',index,'完整5字节E9直接跳转到'+target+'，不自行改动参数。',
                [(va,['jmp',target])], '仅桥身份；不将目标函数全部行为并入桥的语义。')
    bounded=json.loads((HERE/'bounded_raw.json').read_text('utf-8'))
    windows=[]
    for index, row in enumerate(bounded['explicit_owner_windows']):
        items=row['assembly']
        windows.append(dict(owner_va=row['owner_va'], site_va=row['site_va'],
                            start_va=items[0]['site_va'],
                            end_va=hex(int(items[-1]['site_va'],16)+items[-1]['bytes']['size']),
                            evidence_file='bounded_raw.json', evidence_pointer='/explicit_owner_windows/'+str(index),
                            status='局部审阅；不是新增完整入口'))
    supplement=json.loads((HERE/'navigation_supplement/bounded_raw.json').read_text('utf-8'))
    for index,row in enumerate(supplement['explicit_owner_windows']):
        items=row['assembly']
        windows.append(dict(owner_va=row['owner_va'],site_va=row['site_va'],start_va=items[0]['site_va'],
                            end_va=hex(int(items[-1]['site_va'],16)+items[-1]['bytes']['size']),
                            evidence_file='navigation_supplement/bounded_raw.json',evidence_pointer='/explicit_owner_windows/'+str(index),
                            status='局部审阅；不是新增完整入口'))
    data=dict(disk_sha256=SHA, topic='A839A0状态读写与消费', functions=rows, owner_windows=windows,
              scope='九个固定入口加一完整依赖和四E9桥，共14清单项；旧契约复用不重复计数。')
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n','utf-8')


if __name__=='__main__':
    main()
