"""保留已有对象来源导航；不计新增函数审阅，不扩IDA采证。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = [
    ('../../TeachMode状态与序号来源/证据/closure_raw.json', ['0x6282a9', '0x6282c9', '0x6282ea']),
    ('../../TeachMode状态与序号来源/证据/producers_raw.json', ['0x69e48b']),
]


def build():
    records = []
    for path, sites in SOURCES:
        payload = (HERE/path).read_bytes()
        source = json.loads(payload)
        row = source['functions'][0]
        anchors = [dict(pointer='/functions/0/assembly/'+str(i), value=a)
                   for i, a in enumerate(row['assembly']) if a['va'] in sites]
        assert len(anchors) == len(sites)
        records.append(dict(va=row['va'], source=dict(path=path,
                            sha256=hashlib.sha256(payload).hexdigest(), pointer='/functions/0'),
                            anchors=anchors, original_byte_ranges=row['chunk_byte_ranges'],
                            status='已有原证来源导航；新增函数审阅数0'))
    result = dict(schema='richonline-source-navigation-1', records=records,
                  scope='对象取得与基址零写入；不证明数组生产、容量与释放')
    (HERE/'source_navigation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(navigation_records=len(records), fresh_functions=0)


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
