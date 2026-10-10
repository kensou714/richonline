"""按原证数组位置生成分级清单；正文语义由人工逐指令审阅。"""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TOPIC = ROOT / 'docs/逆向资料/专题'
SPECS = (
    ('avatar_raw.json', 0x641650, '03_释放与重载边界.txt', 'R+256非零时delete[]并清零；其它字段不清', '所有外层时序及delete实现未全追'),
    ('avatar_raw.json', 0x6416B0, '01_对象布局与初值.txt', '仅清A+132并返回this', '目录与N初始内存内容未知'),
    ('avatar_raw.json', 0x6416E0, '03_释放与重载边界.txt', '记录数组经flags3逐记录析构释放并清A+132，不清N', '全部生命周期与外层重载时序未全追'),
    ('avatar_raw.json', 0x641750, '02_配置加载与图片字段.txt', '连续计数/分配/prop与四图装载；成功重读覆盖旧指针', 'M生产链、共享解析异常与运行库后端未全闭合'),
    ('avatar_raw.json', 0x642320, '04_prop查询与坐标消费.txt', '每记录固定16prop首次比较命中返回记录指针，未命中0', '调用者完整prop域与全部可达性未审'),
    ('avatar_raw.json', 0x6464F0, '03_释放与重载边界.txt', 'flags控制标量或数组析构及delete；数组步长260', '析构运行库异常后端未全审'),
    ('supplement_raw.json', 0x6294D0, '03_释放与重载边界.txt', '先6416E0再按flags&1删除管理对象', '全部退出流程与delete后端未全审'),
    ('supplement_raw.json', 0x641590, '01_对象布局与初值.txt', '16prop与16图片槽写-1，R+256清零，coord不清', '未初始化coord内容未知'),
    ('supplement_raw.json', 0x646590, '01_对象布局与初值.txt', '仅返回DWORD[this]；本批调用者将其作M', '对象首字段生产者与M取值域未闭合'),
    ('coordinate_constructor_raw.json', 0x641550, '01_对象布局与初值.txt', 'memset2496字节为零并返回this', '完整memset运行库不在本批全审'),
)
REUSED = (
    ('TeachMode对象与消费者/证据/teachmode_raw.json', 0x627E70, '既有原证本地复核', '01_对象布局与初值.txt', 'A766F4懒单例分配136字节，构造返回与异常尾复核', '并发与分配后端未全审'),
    ('角色与精灵动画/证据/角色精灵_IDA原始导出.json', 0x642740, '部分审阅', '04_prop查询与坐标消费.txt', '五prop变化且>0才重查，<=0不清记录缓存', '完整角色状态机和绘制选图未审'),
    ('游戏时间与计时调度/证据/functions.json', 0x641EE0, '历史原证局部复用', '04_prop查询与坐标消费.txt', 'AVT路径、版本扫描与坐标公式核验；frame无<=3门', '全部绘制消费、M生产链及共享解析后端另核'),
    ('图像运行时接口/证据/draw_mapping_dependencies.json', 0x6DAA10, '既有完整契约复用', '02_配置加载与图片字段.txt', '复用十二前缀到运行时槽的名称解析本地契约', '6DBA40完整分配与无效映射后端另核'),
    ('MapView配置记录与预览消费/证据/functions_raw.json', 0x622D50, '既有完整契约复用', '01_对象布局与初值.txt', '复用signed前减计数的构造回调迭代，本次步长2496', '回调异常与分配器后端另核'),
)


def source_record(path, va):
    source = json.loads(path.read_bytes())
    found = [(index, row) for index, row in enumerate(source['functions'])
             if int(row.get('va', row.get('address')), 16) == va]
    assert len(found) == 1
    return found[0]


def record(path, va, status, document, conclusion, unknown, evidence):
    index, row = source_record(path, va)
    assembly = row.get('assembly', row.get('instructions'))
    return dict(va=hex(va), end_va=row.get('end_va', row.get('end_address')), status=status,
                conclusion=conclusion, unknown=unknown, document=document, evidence=[evidence],
                evidence_pointer=f'/functions/{index}',
                chunks=row.get('chunk_byte_ranges', row.get('chunks')),
                instructions=len(assembly),
                review_scope='完整新主体本地指令与尾块契约；外部后端限制见unknown' if status == '本地静态契约已审阅'
                else '复用旧原证，不增加唯一VA；本批语义范围由正文和status限定')


def main():
    rows = [record(HERE / file, va, '本地静态契约已审阅', document, conclusion, unknown, '证据/' + file)
            for file, va, document, conclusion, unknown in SPECS]
    rows.extend(record(TOPIC / file, va, status, document, conclusion, unknown, '../' + file)
                for file, va, status, document, conclusion, unknown in REUSED)
    result = dict(schema=1, pe_sha256='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2',
                  scope='第20批Avatar：十新主体本地契约与五旧函数分级复用；不宣称全部外部依赖闭环',
                  status_counts=dict(Counter(row['status'] for row in rows)), functions=rows)
    (HERE.parent / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result['status_counts'], ensure_ascii=True))


if __name__ == '__main__':
    main()
