"""无损适配本批与固定历史记录；所有原字段保留并绑定来源与JSON Pointer。"""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
DOCS=HERE.parents[2]
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def walk(value,path=''):
    if isinstance(value,dict):
        yield path,value
        for key,child in value.items():
            yield from walk(child,path+'/'+key.replace('~','~0').replace('/','~1'))
    elif isinstance(value,list):
        for index,child in enumerate(value):
            yield from walk(child,path+'/'+str(index))


def adapt(source,path,pointer,sha,scope):
    row=dict(source)
    va=source.get('seed_va',source.get('va',source.get('address')))
    chunks=source.get('chunk_byte_ranges',source.get('chunks',source.get('byte_ranges')))
    assert chunks
    assembly=source.get('assembly',source.get('instructions'))
    assert isinstance(assembly[0],dict)
    row.update(va=va,source_path=path,source_pointer=pointer,source_sha256=sha,
               source_field_pointers={key:pointer+'/'+key for key in source}, adaptation_scope=scope,
               normalized_chunks=[dict(start_va=chunk.get('start_va',chunk.get('va',chunk.get('address'))),
                                       **{key:value for key,value in chunk.items() if key not in ('start_va','va','address')}) for chunk in chunks],
               normalized_assembly=[dict(site_va=item.get('site_va',item.get('va',item.get('address'))),
                                         text=item['text'],is_code=item.get('is_code',True),
                                         original=item) for item in assembly])
    if 'declared_chunks' not in row:
        row['declared_chunks']=[dict(start_va=chunk['start_va'],end_va=hex(int(chunk['start_va'],16)+chunk['size']),
                                    is_main=chunk['start_va']==va) for chunk in row['normalized_chunks']]
    if 'byte_ranges' not in row:
        row['byte_ranges']=chunks
    return row


def main():
    raw=(HERE/'bounded_raw.json').read_bytes()
    data=json.loads(raw)
    rows=[adapt(row,'专题/地图选择字段与列表消费/证据/bounded_raw.json','/functions/'+str(i),
                hashlib.sha256(raw).hexdigest(),'本批新原证无损适配') for i,row in enumerate(data['functions'])]
    result=dict(disk_sha256=SHA,functions=rows)
    (HERE/'formal_functions.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    if (HERE/'dependency_raw.json').exists():
        raw=(HERE/'dependency_raw.json').read_bytes();data=json.loads(raw)
        dependencies=[adapt(row,'专题/地图选择字段与列表消费/证据/dependency_raw.json','/functions/'+str(i),
                            hashlib.sha256(raw).hexdigest(),'本批补充完整原证无损适配') for i,row in enumerate(data['functions'])]
        (HERE/'formal_dependencies.json').write_text(json.dumps(dict(disk_sha256=SHA,functions=dependencies),ensure_ascii=False,indent=2)+'\n','utf-8')
    specs=[('专题/MapView配置记录与预览消费/证据/closure_raw.json',['0x73f420'],'历史部分分析本体；本批分级审阅'),
           ('专题/随机地图候选与配置索引/证据/dependencies_raw.json',['0x64f200','0x7e9610'],'既有局部契约复用'),
           ('专题/随机地图候选与配置索引/证据/functions_raw.json',['0x6aaa80'],'既有局部契约复用'),
           ('专题/Pawn四档配置与业务消费/证据/reused_raw.json',['0x629dd0','0x629df0','0x63edd0','0x63e1a0','0x629e10'],'模式谓词复用'),
           ('专题/TeachMode对象与消费者/证据/teachmode_raw.json',['0x629e60'],'根对象字段地址复用'),
           ('专题/回合继续与落点调度/证据/stage1_dependencies.json',['0x922570'],'未初始化诊断局部契约复用'),
           ('专题/聊天发送与重复提示契约/证据/chat_contract_discovery.json',['0x9204c0','0x9204d0'],'既有CRT入口与共享复制块复用')]
    rows=[]
    for path,addresses,scope in specs:
        raw=(DOCS/path).read_bytes()
        source=json.loads(raw)
        for address in addresses:
            candidates=[(ptr,row) for ptr,row in walk(source) if row.get('va',row.get('address'))==address and
                        any(key in row for key in ('assembly','instructions'))]
            assert len(candidates)==1,(path,address,len(candidates))
            ptr,row=candidates[0]
            rows.append(adapt(row,path,ptr,hashlib.sha256(raw).hexdigest(),scope))
    (HERE/'reused_functions.json').write_text(json.dumps(dict(disk_sha256=SHA,functions=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    print('adapted: 6 new,',len(rows),'historical records')


if __name__=='__main__':
    main()
