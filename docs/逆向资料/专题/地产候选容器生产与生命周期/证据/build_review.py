"""新主体、重采主体、直接桥与旧依赖分开计量。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    raw = json.loads((HERE/'bounded_raw.json').read_bytes())
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    conclusions = ('ECX容器构造只清+0C指针并返回this；不清数量/容量/增长',
                   'ECX容器析构转7ECF70；恢复this，正常释放后只清指针，无业务成功值')
    functions = [dict(va=f['va'], status='完整函数静态审阅', conclusion=conclusions[i],
        unknown='完整类名、上层重建时机与分配失败策略未闭合',
        evidence=f'证据/formal_functions.json#/functions/{i}',
        document='01_容器字段与生命周期.txt', coverage_origin=f['coverage_origin']) for i,f in enumerate(formal['functions'])]
    functions += [dict(va=b['start_va'], status='直接桥静态核验', conclusion='E9到'+b['target_va'],
        unknown='仅本桥静态目标，不证明后端全部语义或动态可达',
        evidence=f'证据/bounded_raw.json#/verified_direct_bridges/{i}',
        document='03_来源分层与复核边界.txt', coverage_origin='本批IDA桥原证；全局去重由中央完成') for i,b in enumerate(raw['verified_direct_bridges'])]
    contracts = ('初始化数量/容量/增长并覆盖分配指针，RET8',
                 'signed数量/容量比较，按旧容量复制，写低WORD并返回插入下标，RET4',
                 '运行时R+0 signed BYTE为11或12', '运行时R+1 signed BYTE为8/9/10')
    dependencies = [dict(va=f['va'], contract=contracts[i], scope=f['scope'],
        evidence=f'证据/formal_functions.json#/legacy_reused_functions/{i}') for i,f in enumerate(formal['legacy_reused_functions'])]
    dependencies.append(dict(va='0x7ecf70', contract='非空指针调用delete[]，返回后清+0C；其他三个DWORD不变',
        scope='旧完整原证短契约复用，非新原证', evidence='证据/formal_functions.json#/historical_dependencies/1'))
    windows = []
    for owner in ('0x7de310','0x7de5c0','0x7df010'):
        refs = [f'证据/formal_functions.json#/caller_windows/{i}' for i,w in enumerate(formal['caller_windows']) if w['owner_va']==owner]
        refs += [f'证据/bounded_raw.json#/explicit_owner_windows/{i}' for i,w in enumerate(raw['explicit_owner_windows']) if w['owner_va']==owner]
        windows.append(dict(owner_va=owner, window_status='有限生命周期与生产路径复核',
            window_conclusion='C实例、初始参数、递增分流或EH清理动作；不认领完整owner新成果',
            evidence=refs, document='02_地图生产顺序与筛选闭环.txt'))
    result = dict(stage='作者静态审阅；独审另记', disk_sha256=raw['disk_sha256'], functions=functions,
        dependency_contracts=dependencies, windows=windows,
        scope='2当次主体(1全局新+1旧重采)、4IDA桥；4中文旧体与1旧释放短契约独立分层')
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(functions=len(functions),dependencies=len(dependencies),owners=len(windows))))


if __name__ == '__main__':
    build()
