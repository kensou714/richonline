"""四新本体、七历史复用分列；大loader只认OTHER局部语义。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SPECS = [
    ('完整局部分析', '按12字节步长构造100项，构造回调为6D76C0；返回原this。', '异常构造与调用者内存容量未动态验证。', [0x6DFA1E,0x6DFA23,0x6DFA25,0x6DFA2B,0x6DFA30]),
    ('完整局部分析', '依次把this+8、+4、+0三个DWORD写FFFFFFFF，返回this。', '12字节以外字段及后续使用不属于本体契约。', [0x6D76D1,0x6D76DB,0x6D76E5,0x6D76EB]),
    ('完整局部分析', '清this+0组数与this+4数组指针，返回this；owner传C+3ABFC。', '不证明整个配置根初始化及失败清理闭合。', [0x6D7C11,0x6D7C1A,0x6D7C21]),
    ('完整局部分析', 'this+4非零时调用delete[]包装并清+4；从未清this+0。', '未审堆释放底层，析构后组数仍旧值不等于运行时可安全复用。', [0x6D7C4A,0x6D7C4E,0x6D7C5D,0x6D7C68]),
    ('既有窄契约复用', '传原ECX给6DFD10，正常RTC路径保留返回槽值。', '未替代取槽函数的空池与容量前置条件。', [0x6D766E,0x6D7671,0x6D767B]),
    ('既有窄契约复用', '先将pool+8递减1，再从[pool+0]+index*4返回DWORD；无空池门。', 'pool+0/+4/+8的完整生产、容量、归还、去重及并发生命周期未闭。', [0x6DFD21,0x6DFD24,0x6DFD2A,0x6DFD36,0x6DFD38]),
    ('部分分析', 'OTHER段累加组数；正数组数分配每组1200字节；逐组首缺O节即止；npid与槽写+0/+4，反向表登记记录指针。', '仅6DA1A1..6DA473业务；整个9768B主块及200B异常块只机械核；缺键、分配失败、池容量及重载未闭。', [0x6DA1A1,0x6DA1D2,0x6DA23E,0x6DA25F,0x6DA264,0x6DA268,0x6DA279,0x6DA284,0x6DA28B,0x6DA2A6,0x6DA2BF,0x6DA2C8,0x6DA2D4,0x6DA2E0,0x6DA2F3,0x6DA316,0x6DA334,0x6DA33A,0x6DA361,0x6DA365,0x6DA373,0x6DA399,0x6DA39D,0x6DA3AD,0x6DA3C4,0x6DA3D0,0x6DA3F0,0x6DA3F9,0x6DA416,0x6DA457,0x6DA463]),
    ('既有窄契约复用', '等步长调用构造回调，正常路径ret10h；支持100项及组数两层构造。', 'CRT异常安全与回调失败外部语义不扩审。', [0x622D5D,0x622D64,0x622D71,0x622D82]),
    ('既有窄契约复用', '既有数组释放包装提供释放调用目标身份。', '只审转发路径；不声称实际对象或系统资源已释放。', []),
    ('既有窄契约复用', 'RTC正常相等路径直接ret并保留EAX。', '不研究诊断失败路径行为。', [0x91F6D0,0x91F6D2]),
    ('既有窄契约复用', 'Q+12C4+12*i等于group4第i项+4；统计不为FFFFFFFF的100槽数量。', '缺组与NULL指针无门；记录生产不能证明当前运行返回39。', [0x6DBA07,0x6DBA10,0x6DBA19,0x6DBA1C,0x6DBA24,0x6DBA29]),
]


def main():
    rows = []
    for filename in ('formal_functions.json','reused_functions.json'):
        d=json.loads((HERE/filename).read_bytes())
        for i,r in enumerate(d['functions']):
            status,conclusion,unknown,addresses=SPECS[len(rows)]
            byva={a['site_va']:a for a in r['normalized_assembly']}
            anchors=[dict(va=hex(a),original_text=byva[hex(a)]['text']) for a in addresses]
            rows.append(dict(va=r['va'],status=status,conclusion=conclusion,unknown=unknown,
                             source_path=r['source_path'],source_pointer=r['source_pointer'],source_sha256=r['source_sha256'],
                             declared_chunks=r['declared_chunks'],evidence_ref=dict(file=filename,pointer='/functions/'+str(i)),
                             semantic_anchors=anchors,
                             mechanical_items=len(r['normalized_assembly'])))
    result=dict(disk_sha256=SHA, scope='4新完整局部本体；2旧种子复用；旧loader仅OTHER局部；4旧辅助契约。桥和窗口不新增函数审阅。',
                functions=rows[:4],historical_contracts=rows[4:],
                summary=dict(new_bodies=4,new_bytes=216,new_instructions=70,historical_records=7,
                             historical_mechanical_items=sum(r['mechanical_items'] for r in rows[4:]),
                             explicit_owner_windows=8,formal_direct_bridges=9))
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result['summary']))


if __name__=='__main__':
    main()
