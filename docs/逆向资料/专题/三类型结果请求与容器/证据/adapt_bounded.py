"""只适配已有原证字段；不采新证、不增加函数或覆盖范围。"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent


def main():
    raw = (HERE / 'bounded_raw.json').read_bytes()
    data = json.loads(raw)
    functions = []
    for index, source in enumerate(data['functions']):
        function = dict(source)
        function['va'] = source['seed_va']
        function['status'] = '完整声明块机械适配；人工结论见函数审阅清单'
        function['source_file'] = 'bounded_raw.json'
        function['source_pointer'] = '/functions/' + str(index)
        function['source_field_pointers'] = {
            key: function['source_pointer'] + '/' + key for key in source}
        function['byte_ranges'] = source['chunk_byte_ranges']
        function['declared_chunks'] = [
            dict(start_va=chunk['start_va'],
                 end_va=hex(int(chunk['start_va'], 16) + chunk['size']),
                 is_main=chunk['start_va'] == source['seed_va'])
            for chunk in source['chunk_byte_ranges']]
        functions.append(function)
    result = dict(disk_sha256=data['disk_sha256'], source_file='bounded_raw.json',
                  source_sha256=hashlib.sha256(raw).hexdigest(),
                  scope='六个已采入口的无损机械适配；不是新增导出或新增覆盖',
                  functions=functions)
    (HERE / 'formal_functions.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print('adapted functions:', len(functions))


if __name__ == '__main__':
    main()
