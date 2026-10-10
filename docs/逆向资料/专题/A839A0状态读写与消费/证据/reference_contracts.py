"""固化本批沿用的历史局部契约；不提升历史整体语义覆盖。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def walk(value, pointer=''):
    if isinstance(value, dict):
        yield pointer, value
        for key, child in value.items():
            yield from walk(child, pointer + '/' + key.replace('~', '~0').replace('/', '~1'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, pointer + '/' + str(index))


def main():
    rows=[]
    specs=[('专题/TeachBoard记录与消费/证据/consumers_raw.json', ['0x798ce0','0x798d80']),
           ('专题/TeachBoard记录与消费/证据/reused_raw.json', ['0x6fa7f0']),
           ('专题/TeachMode状态与序号来源/证据/closure_raw.json', ['0x6ac390']),
           ('专题/TeachMode状态与序号来源/证据/state_source_raw.json', ['0x82a900','0x82ab80','0x8976e0']),
           ('专题/聊天发送与重复提示契约/证据/chat_contract_discovery.json', ['0x828f60'])]
    for filename, addresses in specs:
        raw=(DOCS/filename).read_bytes()
        data=json.loads(raw)
        for address in addresses:
            found=[(pointer,row) for pointer,row in walk(data) if row.get('va',row.get('address'))==address
                   and any(key in row for key in ('instructions','assembly'))]
            assert len(found)==1,(filename,address,len(found))
            pointer,row=found[0]
            chunks=row.get('chunk_byte_ranges',row.get('chunks',row.get('byte_ranges')))
            assert chunks
            windows=[dict(start_va='0x6ac48e',end_va='0x6ac4b4')] if address=='0x6ac390' else []
            if address=='0x828f60':
                windows=[dict(start_va='0x828f93',end_va='0x828fbd'),dict(start_va='0x82a1f2',end_va='0x82a212')]
            rows.append(dict(va=address,source_path=filename,source_sha256=hashlib.sha256(raw).hexdigest(),
                             source_pointer=pointer,source_record=row,
                             scope='仅生产窗口' if windows else '复用外围契约；非本批新增入口', windows=windows,
                             chunk_byte_ranges=[dict(start_va=chunk.get('start_va',chunk.get('va',chunk.get('address'))),
                                                     **{key:value for key,value in chunk.items() if key not in ('start_va','va','address')})
                                                for chunk in chunks]))
    (HERE/'historical_contracts.json').write_text(json.dumps(dict(disk_sha256=SHA,contracts=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    print('historical contract references:',len(rows))


if __name__=='__main__':
    main()
