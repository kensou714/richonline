"""作者无损适配；仅写本专题派生件，保留原证及历史文件。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
HELPER = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
SPECS = [
    ('专题/NewProps与CombCard配置/证据/reused_raw.json', [0x627c20, 0x7fea80, 0x8052e0]),
    ('专题/NewProps与CombCard配置/证据/supplement_raw.json', [0x7febf0]),
    ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', [0x6276a0, 0x646610]),
    ('专题/Avatar配置与角色图片/证据/supplement_raw.json', [0x646590]),
    ('专题/角色文本选择与控件消费/证据/bounded_raw.json', [0x6f4db0, 0x7014a0]),
]
REVIEWS = {
    0x7fe7d0: ('静态契约已审阅', '旧道具1128字节记录构造：+0C=-1、+14=NULL，八个12字节槽交回调；局部字段初值不等于整对象清零。'),
    0x7fe9e0: ('静态契约已审阅', 'P+14非空则delete[]后清指针；不清其它字段，无空this门。'),
    0x7ff1d0: ('静态契约已审阅', '31项part表顺序strcmp，首等返回表号，未等返回FFFFFFFF；2=LAND、7=SUIT。'),
    0x7ff240: ('局部路径已核', '限定Prop两遍容量/编号、part、ROLE数组分配和初始化及退出路径；缺ROLE默认1，精确true为1，数量快照无本地有效域门。'),
}
# 语义锚为手工选定的真实指令；仅参与本题的loader路径被明确认领。
ANCHORS = {
    0x7fe7d0: [0x7fe7de,0x7fe7e3,0x7fe7e5,0x7fe7ea,0x7fe7f0,0x7fe7f8,0x7fe801,0x7fe80b,
               0x7fe815,0x7fe81f,0x7fe826,0x7fe82d,0x7fe834,0x7fe83b,0x7fe841,0x7fe84d,0x7fe859,
               0x7fe865,0x7fe8d9,0x7fe999,0x7fe9a3,0x7fe9b0,0x7fe9ba,0x7fe9c1,0x7fe9d1],
    0x7fe9e0: [0x7fe9fa,0x7fe9fe,0x7fea03,0x7fea0d,0x7fea18,0x7fea2c],
    0x7ff1d0: [0x7ff1e7,0x7ff1f9,0x7ff1fd,0x7ff202,0x7ff20e,0x7ff216,0x7ff218,0x7ff21a,0x7ff221,0x7ff231],
    0x7ff240: [0x7ff295,0x7ff29a,0x7ff29c,0x7ff2ca,0x7ff2d1,0x7ff2d6,0x7ff304,0x7ff30c,
               0x7ff31e,0x7ff332,0x7ff339,0x7ff359,0x7ff36a,0x7ff36d,0x7ff375,0x7ff380,0x7ff393,
               0x7ff3aa,0x7ff3b0,0x7ff3b4,0x7ff3cd,0x7ff3db,0x7ff3dd,0x7ff3e2,0x7ff3ee,0x7ff3fd,
               0x7ff436,0x7ff45b,0x7ff462,0x7ff492,0x7ff4a0,0x7ff65d,0x7ff664,0x7ff678,0x7ff687,
               0x7ff69a,0x7ff6ed,0x7ff6ee,0x7ff710,0x7ff714,0x7ff729,0x7ff72c,0x7ff747,0x7ff75b,
               0x7ff770,0x7ff777,0x7ff79c,0x7ff7a4,0x7ff7a6,0x7ff7a8,0x7ff7be,0x800864,0x800869,
               0x800891,0x8008cc],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def main():
    adapt = runpy.run_path(str(HELPER))['adapt']
    raw_path = HERE / 'bounded_raw.json'
    raw_bytes = raw_path.read_bytes()
    data = json.loads(raw_bytes)
    rows = [adapt(row, raw_path.relative_to(DOCS).as_posix(), '/functions/'+str(i), sha(raw_bytes),
                  '四个新主体原字段完整保留；语义分级只见本题清单') for i,row in enumerate(data['functions'])]
    save(HERE/'formal_functions.json', dict(disk_sha256=SHA, adapter_helper_sha256=sha(HELPER.read_bytes()), functions=rows))
    reused = []
    for source, addresses in SPECS:
        content = (DOCS/source).read_bytes()
        document = json.loads(content)
        for address in addresses:
            matches = [(i,r) for i,r in enumerate(document['functions'])
                       if int(r.get('seed_va',r.get('va')),16) == address]
            assert len(matches) == 1, (source, hex(address))
            i,row = matches[0]
            reused.append(adapt(row,source,'/functions/'+str(i),sha(content),'旧原证有限契约复用；不新增完整语义认领'))
    save(HERE/'reused_functions.json', dict(disk_sha256=SHA, functions=reused))
    reviews = []
    for i,row in enumerate(rows):
        va = int(row['va'],16)
        asm = {int(r['site_va'],16):r['text'] for r in row['normalized_assembly']}
        status, conclusion = REVIEWS[va]
        reviews.append(dict(va=row['va'],status=status,conclusion=conclusion,
                            scope=('全声明块的限定本体静态契约' if va != 0x7ff240 else '仅编号/容量、part、ROLE与必要初始化/退出；其它属性和EH完整语义未审'),
                            unknown='未运行游戏；未恢复全部下游CRT或其它属性；局部静态门不证明输入合法性及动态同步',
                            evidence='证据/formal_functions.json',evidence_ref=dict(file='formal_functions.json',pointer='/functions/'+str(i)),
                            source_records=[dict(path='证据/bounded_raw.json',sha256=sha(raw_bytes),json_pointer='/functions/'+str(i))],
                            declared_chunks=row['declared_chunks'],
                            instruction_count=sum(r['is_code'] for r in row['normalized_assembly']),
                            semantic_anchors=[dict(site_va=hex(site),ida_text=asm[site]) for site in ANCHORS[va]]))
    save(HERE.parent/'函数审阅清单.json',dict(disk_sha256=SHA,raw_source_sha256=sha(raw_bytes),functions=reviews,
         summary=dict(new_bodies=4,complete_limited_contracts=3,partial_paths=1,historical_sources=9,
                      declared_chunks=5,declared_bytes=6509,instructions=1658,
                      warning='完整字节导出和旧原证复用不等同全部函数语义完成')))
    print('作者适配：4 新主体、9 旧原证；显式清单仅 4 项。')


if __name__ == '__main__':
    main()
