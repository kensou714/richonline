"""旧原证逐记录原样复制；保留逐指令字节，不补造声明块。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
SOURCES = {
    '游戏分派桥接/证据/property_and_6021_handlers.json': ['0x6b7ce0','0x6a6cd0','0x629ea0'],
    '随机地图候选与配置索引/证据/functions_raw.json': ['0x629dd0','0x629df0','0x629e10'],
    '角色1416字段来源/证据/functions.json': ['0x63e1a0','0x6a54f0'],
    '大厅玩家记录与装备字段/证据/record_access.json': ['0x64f090'],
}


def build():
    records = []
    for name, wanted in SOURCES.items():
        payload = (TOPICS/name).read_bytes()
        raw = json.loads(payload)
        for index, row in enumerate(raw['functions']):
            if row['va'] in wanted:
                records.append(dict(va=row['va'], original_record=row,
                               source=dict(path='../../'+name, sha256=hashlib.sha256(payload).hexdigest(), pointer='/functions/'+str(index)),
                               note='原schema原样保存；未声明块则仍未声明，不计新完成'))
        assert set(wanted) <= {r['va'] for r in records}
    result = dict(schema='richonline-exact-reused-records-1', records=records)
    (HERE/'reused_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(records=len(records))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
