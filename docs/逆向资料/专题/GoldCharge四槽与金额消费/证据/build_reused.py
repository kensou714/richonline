"""原样保留复用记录与来源指针；不替旧记录补造声明块。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
SOURCES = {
    '40C1状态事件/证据/followup.json': ['0x7fb150'],
    'TeachMode对象与消费者/证据/teachmode_raw.json': ['0x7fb0e0'],
    '商店与购买流程/证据/shop_helpers.json': ['0x727b10'],
    '神明附身与元数据/证据/predicates.json': ['0x727b40', '0x727b70'],
    'KoNpc记录与消费者/证据/npc_supplement_raw.json': ['0x727bd0'],
    '主界面角色通知/证据/notify_helpers.json': ['0x6fa210'],
    '4036系列事件/证据/followups.json': ['0x63e590', '0x63e440'],
    '主界面角色通知/证据/notify_contract.json': ['0x727850'],
    '文本与容器/证据/config_map_consumers.json': ['0x7b9ca0'],
}


def build():
    records = []
    for name, wanted in SOURCES.items():
        payload = (TOPICS / name).read_bytes()
        raw = json.loads(payload)
        rows = raw['functions']
        indexed = rows.items() if isinstance(rows, dict) else enumerate(rows)
        for index, row in indexed:
            va = row.get('va', row.get('address', str(index)))
            if va not in wanted:
                continue
            records.append(dict(va=va, source=dict(path='../../' + name,
                           sha256=hashlib.sha256(payload).hexdigest(),
                           pointer='/functions/' + str(index)), original_record=row,
                           note='原schema原样保存；无声明块则仍无声明块，新完成数0'))
        assert set(wanted) <= {r['va'] for r in records}, (name, wanted)
    result = dict(schema='richonline-exact-reused-records-1', records=records,
                  scope='已有原证复用；不创造IDA声明块，不计新增完成')
    (HERE / 'reused_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(records=len(records))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
