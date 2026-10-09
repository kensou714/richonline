"""在已附着的只读IDA-MCP中调用recheck(db)，核对全部函数块和指令集合。"""
import hashlib
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/4019系列事件')
FILES = ('handlers.json', 'helpers.json', 'consumers.json', 'ui_and_property.json',
         'wait_window.json', 'adjacent_wait_context.json', 'wait_phase_and_owner_effect.json',
         'resource_loader_scope.json', 'text_recording.json')


def recheck(db):
    result = {'disk_sha256': hashlib.sha256((HERE.parents[3] / 'RnClient.exe').read_bytes()).hexdigest(),
              'scope': '重新枚举全部主块/尾块、指令地址和长度，再核对当前IDA字节；磁盘由build_review另验',
              'files': []}
    for filename in FILES:
        data = json.loads((HERE / '证据' / filename).read_text(encoding='utf-8'))
        item = {'file': filename, 'functions': len(data['functions']), 'mismatches': [],
                'function_chunks': []}
        for saved in data['functions']:
            function = db.functions.get_at(int(saved['va'], 16))
            chunks = list(db.functions.get_chunks(function))
            declared = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main)
                        for c in chunks]
            actual = {hex(i.ea): i.size for c in chunks
                      for i in db.instructions.get_between(c.start_ea, c.end_ea)}
            expected = {i['va']: i['size'] for i in saved['assembly']}
            if (hex(function.start_ea) != saved['va'] or hex(function.end_ea) != saved['end_va']
                    or declared != saved['declared_chunks'] or actual != expected):
                item['mismatches'].append({'va': saved['va'], 'kind': '函数块或指令集合不符'})
            for span in saved['byte_ranges']:
                if db.bytes.get_bytes_at(int(span['va'], 16), span['size']).hex() != span['idb_hex']:
                    item['mismatches'].append({'va': saved['va'], 'kind': '当前IDA字节不符'})
            item['function_chunks'].append({'va': saved['va'], 'declared_chunks': declared,
                                            'instruction_count': len(actual),
                                            'instruction_bytes': sum(actual.values())})
        result['files'].append(item)
    (HERE / '证据/ida_recheck.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                             encoding='utf-8')
    failures = [m for item in result['files'] for m in item['mismatches']]
    if failures:
        raise ValueError(failures)
    return {'functions': sum(i['functions'] for i in result['files']), 'mismatches': failures}
