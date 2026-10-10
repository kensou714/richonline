"""从已核专题原证摘取 KoNews 读取/访问器，保存来源文件哈希。"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / '地图建筑等级配置/证据'


def main():
    functions, thunks, provenance = [], {}, []
    for name, requested in (('functions_raw.json', {'0x806670'}),
                            ('accessors_raw.json', {'0x8069a0'})):
        blob = (SOURCE / name).read_bytes()
        raw = json.loads(blob)
        selected = [item for item in raw['functions'] if item['va'] in requested]
        assert {item['va'] for item in selected} == requested
        functions.extend(selected)
        bridges = {bridge for item in selected for call in item['calls'] for bridge in call['thunks']}
        thunks.update({item['va']: item for item in raw['thunks'] if item['va'] in bridges})
        provenance.append(dict(source='../地图建筑等级配置/证据/' + name,
                               source_sha256=hashlib.sha256(blob).hexdigest(), functions=sorted(requested)))
    result = dict(disk_sha256=raw['disk_sha256'], scope='摘取既有原证，不重新反编译或改写内容',
                  provenance=provenance, functions=functions, thunks=list(thunks.values()))
    destination = HERE / '证据/reused_raw.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(dict(functions=len(functions), thunks=len(thunks)))


if __name__ == '__main__':
    main()
