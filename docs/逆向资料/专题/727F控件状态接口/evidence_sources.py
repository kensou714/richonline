"""显式列出新原证与复用来源；不把导航或独审输出误当函数数组。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NEW_FILES = ('seeds.json', 'local_interfaces.json', 'text_dependencies.json', 'representative_consumers.json')
REUSE = (
    ('../控件树与对象生命周期/证据/几何传播.json', (0x8E31B0, 0x8E3340)),
    ('../4023系列事件/证据/series_support.json', (0x715140,)),
    ('../提示文本生命周期/证据/initial.json', (0x8E0650,)),
    ('../列表控件行记录与布局/证据/list_functions.json', (0x8F4050, 0x8F41B0)),
    ('../全局大对象构造与所有权/证据/record_users.json', (0x736D10,)),
    ('../输入与快捷键/ida_input_raw.json', (0x81DCA0, 0x81DEC0)),
)


def records():
    result = []
    sources = [('证据/'+name, None, False) for name in NEW_FILES]
    sources.extend((path, wanted, True) for path, wanted in REUSE)
    for relative, wanted, reused in sources:
        document = json.loads((HERE / relative).read_text(encoding='utf-8'))
        collection = document['functions']
        entries = collection.items() if isinstance(collection,dict) else enumerate(collection)
        for key, original in entries:
            va = int(original.get('va', original.get('ea')),16)
            if wanted is not None and va not in wanted:
                continue
            record = dict(original)
            record['va'] = hex(va)
            if 'instructions' in original:
                record['assembly'] = [dict(va=i['ea'],text=i['text']) for i in original['instructions']]
                record['byte_ranges'] = [dict(va=r['start'], size=int(r['end'],16)-int(r['start'],16), idb_hex=r['idb_bytes_hex']) for r in original['ranges']]
            # 7113A0的旧卡片原证为按地址索引的字典，本次重采仍只能计复核。
            result.append(dict(function=record, source=relative, pointer=f'/functions/{key}', reused=reused or va==0x7113A0,
                               source_fingerprint=document.get('disk_sha256', document.get('idb_input_sha256'))))
    return result
