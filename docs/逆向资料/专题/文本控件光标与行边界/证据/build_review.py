"""Grade complete bodies, direct bridges, and owner navigation separately."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    descriptions = (
        ('模式低BYTE控制局部行，顺序边界分支后以宽度delta续接水平；正常末尾写354h', 'V=0、非法行索引、溢出及互递归终止无统一保证', '02_光标更新与递归边界.txt'),
        ('DWORD水平宽度更新；负值可跨上一行，宽度边界吸附，最终delta校正后写354h', '空文本/非法mode/=-1不写戳；最终X不保证位于[0,H]', '02_光标更新与递归边界.txt'),
        ('先清四选区，再删行；A>C严格门修正，C=0有条件创建续接', '负索引未在后端拒绝；等于C不修正，补空行与返回成功不保证', '03_选区清理与插入续接.txt'),
        ('普通/分段宽度到单元位置，delta输出及前缀递归；原子等宽flag0返回段起点', '缓存/链合法性与溢出未知；不是通用合法索引或双向逆映射', '01_行记录与位置量度.txt'),
        ('单元位置到宽度；完整节点用整宽，原子内部返回此前宽度', '普通pos无缓存长度钳制；链单位总数与wcslen一致性未知', '01_行记录与位置量度.txt'),
        ('后续单元边界；普通两flag均可跳零宽，分段原子返回段尾', 'NULL/负位置/循环链未设门；非Unicode字素接口', '01_行记录与位置量度.txt'),
        ('选区处理后WORD插入/文本替换，以90D120宽度续接8FC830并同步关联位置与范围', '5000h字节总容量/NUL空间未检查，外部回调及失败原子性未知', '03_选区清理与插入续接.txt'),
    )
    functions = [dict(va=f['va'], status='完整函数静态审阅', conclusion=c, unknown=u,
        evidence='证据/formal_functions.json#/functions/' + str(i), document=d,
        coverage_origin=f['coverage_origin']) for i, (f, (c, u, d)) in enumerate(zip(formal['functions'], descriptions))]
    functions.extend(dict(va=b['start_va'], status='直接桥静态核验', conclusion='E9到' + b['target_va'],
        unknown='仅当前静态相对目标；不证明动态可达或后端全部语义',
        evidence='证据/bounded_raw.json#/verified_direct_bridges/' + str(i),
        document='04_证据分层与未决项.txt', coverage_origin='直接桥；不计业务主体')
        for i, b in enumerate(raw['verified_direct_bridges']))
    windows = []
    for owner in sorted({w['owner_va'] for w in raw['explicit_owner_windows']}):
        indices = [i for i, w in enumerate(raw['explicit_owner_windows']) if w['owner_va'] == owner]
        windows.append(dict(owner_va=owner, window_status='仅有限窗口导航',
            window_conclusion='固定调用点前后五条指令；不据窗口计owner完整审阅',
            evidence=['证据/bounded_raw.json#/explicit_owner_windows/' + str(i) for i in indices],
            document='04_证据分层与未决项.txt', unknown='外部owner完整参数生产与行为不在窗口',
            coverage_origin='导航；8FAE70完整级别另由指定复用主体记录承担'))
    dependencies = [dict(va=d['va'], contract=d['contract'],
        evidence='证据/formal_functions.json#/dependencies/' + str(i),
        scope=d['scope']) for i, d in enumerate(formal['dependencies'])]
    result = dict(stage='作者完整主体静态审阅；独审另记', disk_sha256=raw['disk_sha256'],
        functions=functions, windows=windows, dependency_contracts=dependencies,
        scope='七唯一主体加十九直接桥；四owner六固定窗口纯导航；五旧短依赖不增加完整计数')
    (HERE.parent / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(functions=len(functions), windows=len(windows), dependencies=len(dependencies))))


if __name__ == '__main__':
    build()
