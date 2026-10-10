"""固定四新三旧及初始化参数旧记录；保留原字段并逐字段绑定来源。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE=Path(__file__).resolve().parent
DOCS=HERE.parents[2]
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
HELPER=DOCS/'专题/地图选择字段与列表消费/证据/adapt_sources.py'


def main():
    helper=runpy.run_path(str(HELPER));adapt=helper['adapt'];walk=helper['walk']
    raw=(HERE/'bounded_raw.json').read_bytes();data=json.loads(raw)
    rows=[adapt(row,'专题/地图视图初始化平移与夹取/证据/bounded_raw.json','/functions/'+str(i),
                hashlib.sha256(raw).hexdigest(),'本批新原证无损适配') for i,row in enumerate(data['functions'])]
    (HERE/'formal_functions.json').write_text(json.dumps(dict(disk_sha256=SHA,functions=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    raw=(HERE/'dimension_getters_raw.json').read_bytes();data=json.loads(raw)
    rows=[adapt(row,'专题/地图视图初始化平移与夹取/证据/dimension_getters_raw.json','/functions/'+str(i),
                hashlib.sha256(raw).hexdigest(),'本批尺寸短桥' if i<2 else '本批尺寸读取本体') for i,row in enumerate(data['functions'])]
    (HERE/'formal_dependencies.json').write_text(json.dumps(dict(disk_sha256=SHA,functions=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    specs=[('专题/断线与离席恢复/ida_disconnect_fields.json',['0x7b6d50','0x7e1600'],'历史本体本批深化审阅'),
           ('专题/断线与离席恢复/ida_disconnect_dependencies.json',['0x7b6f60'],'历史本体本批深化审阅'),
           ('专题/TeachMode序号生产与根对象/证据/load_source_raw.json',['0x64f2a0'],'初始化参数局部契约复用'),
           ('专题/TeachMode对象与消费者/证据/teachmode_raw.json',['0x63e0e0'],'历史局部契约复用'),
           ('专题/40C1状态事件/证据/animation_fields.json',['0x63e000','0x81bd10'],'历史局部契约复用')]
    rows=[]
    for path,addresses,scope in specs:
        raw=(DOCS/path).read_bytes();source=json.loads(raw)
        for va in addresses:
            found=[(ptr,row) for ptr,row in walk(source) if row.get('va',row.get('address'))==va and
                   any(key in row for key in ('assembly','instructions'))]
            assert len(found)==1,(path,va)
            ptr,row=found[0];rows.append(adapt(row,path,ptr,hashlib.sha256(raw).hexdigest(),scope))
    (HERE/'reused_functions.json').write_text(json.dumps(dict(disk_sha256=SHA,adapter_helper_sha256=hashlib.sha256(HELPER.read_bytes()).hexdigest(),functions=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    print('adapted: 4 seed new, 2 dimension bodies, 2 bridges, 3 reviewed reuse, 4 historical contracts')


if __name__=='__main__':
    main()
