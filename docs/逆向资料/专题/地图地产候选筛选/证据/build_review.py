"""Keep new complete bodies, IDA bridges, dependency contracts and caller windows distinct."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    raw = json.loads((HERE/'bounded_raw.json').read_bytes())
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    conclusions = (
        'ECX实例+46Ch候选WORD按容器下标递增遍历；类型11/S0/owner匹配，严格低于阈值，稳定域同值留首个',
        '三DWORD参数RET0Ch；类型12/排除当前编号/owner匹配，严格低于阈值，稳定域同值留首个',
        '类型11/S0/owner匹配，signed等级>0且<=阈值，稳定域同值留最后者',
        '类型11/S1/owner匹配，signed等级>0且<=阈值，稳定域同值留最后者',
        '类型12/owner匹配，signed等级>0且<=阈值，无排除编号参数，稳定域同值留最后者',
    )
    functions = [dict(va=f['va'], status='完整函数静态审阅', conclusion=conclusions[i],
        unknown='无容量/索引/NULL保证；旧伪码ABI错误；候选填充及动态稳定性未知',
        evidence='证据/formal_functions.json#/functions/'+str(i),
        document='01_容器字段与五入口契约.txt', coverage_origin='本批新增完整主体') for i,f in enumerate(formal['functions'])]
    functions += [dict(va=b['start_va'],status='直接桥静态核验',conclusion='E9到'+b['target_va'],
        unknown='静态当前目标；不证明动态可达或后端全语义',evidence='证据/bounded_raw.json#/verified_direct_bridges/'+str(i),
        document='03_证据分层与未决项.txt',coverage_origin='本批IDA桥原证；不计业务主体') for i,b in enumerate(raw['verified_direct_bridges'])]
    windows = [dict(owner_va='0x7c6640',window_status='仅有限case与call窗口导航',
        window_conclusion='位置生产、两/三搜索回退与直接结果消费；不是完整17705字节owner审阅',
        evidence=['证据/formal_functions.json#/caller_windows/'+str(i) for i in range(len(formal['caller_windows']))] +
                 ['证据/bounded_raw.json#/explicit_owner_windows/'+str(i) for i in range(5)],
        document='02_旧调度器局部回退与消费.txt',coverage_origin='旧owner局部复用，不计完整函数')]
    dependencies = [dict(va=d['va'],contract=d['contract'],scope=d['scope'],
        evidence='证据/formal_functions.json#/dependency_contracts/'+str(i)) for i,d in enumerate(formal['dependency_contracts'])]
    result = dict(stage='作者静态审阅；独审另记', disk_sha256=raw['disk_sha256'],
        functions=functions, windows=windows, dependency_contracts=dependencies,
        scope='五新增完整主体+十四IDA桥；十八旧契约与一个owner有限case独立分层')
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(functions=len(functions),owner_windows=len(windows),dependencies=len(dependencies))))


if __name__ == '__main__':
    build()
