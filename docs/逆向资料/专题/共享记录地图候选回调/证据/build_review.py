import json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def build():
 raw=json.loads((HERE/'bounded_raw.json').read_bytes());formal=json.loads((HERE/'formal_functions.json').read_bytes())
 rows=[dict(va='0x6ba170',status='完整函数静态审阅',conclusion='非空门后按+80h链指针调用__cdecl回调；回调非零即返回1，否则继续',unknown='节点总大小、回调上下文和所有链表生产者未知',evidence='证据/formal_functions.json#/functions/0',document='01_共享记录遍历与回调ABI.txt',coverage_origin='本批新增完整主体'),dict(va='0x6aaa40',status='完整函数静态审阅',conclusion='按实际压栈顺序strcmp两char指针；完整EAX零比较后返回32位1/0',unknown='NULL/终止符/编码契约未知',evidence='证据/formal_functions.json#/functions/1',document='01_共享记录遍历与回调ABI.txt',coverage_origin='本批新增完整主体')]
 rows += [dict(va=b['start_va'],status='直接桥静态核验',conclusion='E9到'+b['target_va'],unknown='只证明桥字节，不证明后端全语义',evidence=f'证据/bounded_raw.json#/verified_direct_bridges/{i}',document='03_来源分层与复核边界.txt',coverage_origin='本批IDA桥；不计主体') for i,b in enumerate(raw['verified_direct_bridges'])]
 deps=[dict(va=f['va'],contract='复用原主体，仅补当前PE字节与来源绑定',scope='本批不重复新增旧主体审阅记录',evidence=f'证据/formal_functions.json#/legacy_reused_functions/{i}',document='03_来源分层与复核边界.txt') for i,f in enumerate(formal['legacy_reused_functions'])]
 out=dict(stage='作者静态审阅；独审另记',disk_sha256=raw['disk_sha256'],functions=rows,legacy_reused=deps,windows=[dict(owner_va=w['owner_va'],window_status='有限调用窗口',window_conclusion='参数与分流导航；不认领完整owner',evidence=f'证据/bounded_raw.json#/explicit_owner_windows/{i}',document='01_共享记录遍历与回调ABI.txt',coverage_origin='旧主体窗口') for i,w in enumerate(raw['explicit_owner_windows'])],scope='2新增主体+4IDA桥；4旧主体及12窗口独立分层')
 (HERE.parent/'函数审阅清单.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
if __name__=='__main__':build()
