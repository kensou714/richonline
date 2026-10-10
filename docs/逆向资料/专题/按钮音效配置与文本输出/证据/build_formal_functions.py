"""六新主体与一旧主体双来源机械适配，保留原文及当前声明块。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
LEGACY = '专题/界面系统/第二批/ida_ui_batch2_raw.json'


def build():
    source = (HERE / 'bounded_raw.json').read_bytes()
    raw = json.loads(source)
    digest = hashlib.sha256(source).hexdigest()
    functions = []
    for index, f in enumerate(raw['functions']):
        functions.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'],
            pseudocode=f['pseudocode'], decompile_error=f['decompile_error'],
            assembly=[dict(va=i['site_va'], text=i['text'], is_code=i['is_code']) for i in f['assembly']],
            source=dict(path='证据/bounded_raw.json', sha256=digest, json_pointer='/functions/'+str(index)),
            chunk_byte_ranges=[dict(va=b['start_va'], **{k:v for k,v in b.items() if k!='start_va'})
                               for b in f['chunk_byte_ranges']],
            coverage_origin='本批新增完整主体'))
    old_bytes = (DOCS / LEGACY).read_bytes()
    old = json.loads(old_bytes)['functions']['0x90b500']
    index, audit = next((i,f) for i,f in enumerate(raw['current_chunk_audits']) if f['seed_va']=='0x90b500')
    functions.append(dict(va=old['address'], end_va=old['end'], name=old['name'],
        pseudocode=old['pseudocode'], decompile_error=None,
        assembly=[dict(i) for i in old['instructions']],
        source=dict(path='../界面系统/第二批/ida_ui_batch2_raw.json',
                    sha256=hashlib.sha256(old_bytes).hexdigest(), json_pointer='/functions/0x90b500'),
        current_audit_source=dict(path='证据/bounded_raw.json', sha256=digest,
                                  json_pointer='/current_chunk_audits/'+str(index)),
        chunk_byte_ranges=[dict(va=b['start_va'], **{k:v for k,v in b.items() if k!='start_va'})
                           for b in audit['chunk_byte_ranges']],
        coverage_origin='旧局部记录指定本体完整复核晋升；不是无记录新函数'))
    for f in functions:
        f['declared_chunks'] = [dict(start_va=b['va'], end_va=hex(int(b['va'],16)+b['size']),
                                    is_main=b['va']==f['va']) for b in f['chunk_byte_ranges']]
        f['bytes_match_disk'] = all(b['matching'] is True for b in f['chunk_byte_ranges'])
        f['status'] = '原证机械适配；语义分级见函数审阅清单.json'
    result = dict(schema='richonline-formal-bounded-adaptation-2', disk_sha256=raw['disk_sha256'],
                  source_sha256=digest, functions=functions,
                  scope='六新原证逐字段保留；一旧原证原文加当前完整块审计，不以旧整文件hash冒充当前版本')
    (HERE / 'formal_functions.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'functions':len(functions),'new':6,'legacy_upgrade':1}))


if __name__ == '__main__':
    build()
