"""统计已转录资源的词法事实；逐段保留键序，不将重复键归并为游戏语义。"""
import hashlib
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def summarize():
    source = (HERE / 'resources.json').read_bytes()
    resources = json.loads(source)
    files, list_sections = [], []
    for record in resources['files']:
        lexical = record['lexical']
        entries = lexical['entries']
        file = dict(path=record['path'], source_size=record['source_size'],
                    decoded_size=lexical['decoded_size'], lines=len(lexical['lines']),
                    sections=len(lexical['sections']), entries=len(entries),
                    duplicate_keys=lexical['duplicate_keys'])
        if record['path'] == 'Avatar/AvatList.kpd':
            for section in lexical['sections']:
                values = [dict(line=row['line'], key=row['key_ascii'],
                               value_ascii=bytes.fromhex(row['value_hex']).strip(b' \t').decode('ascii'),
                               value_hex=row['value_hex'])
                          for row in entries if row['section_index'] == section['index']]
                list_sections.append(dict(name=section['ascii'], index=section['index'],
                                          line=section['line'], entries=values))
        else:
            frame_values = [row['decimal_literal'] for row in entries
                            if row['key_ascii'] == 'frame' and 'decimal_literal' in row]
            file.update(frame_counts=dict(Counter(frame_values)),
                        keys=dict(Counter(row['key_ascii'] for row in entries)),
                        section_names=[row['ascii'] for row in lexical['sections']])
        files.append(file)
    result = dict(schema=1, source_sha256=hashlib.sha256(source).hexdigest(),
                  scope='静态词法快照，不模拟配置查找或重复键选择；原文见resources.json',
                  files=files, list_sections=list_sections,
                  total_files=len(files), avt_files=sum(row['path'].endswith('.avt') for row in files),
                  avt_files_with_duplicates=sum(bool(row['duplicate_keys']) for row in files if row['path'].endswith('.avt')))
    (HERE / 'resource_summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: value for key, value in result.items() if key not in ('files', 'list_sections')}


if __name__ == '__main__':
    print(json.dumps(summarize(), ensure_ascii=True))
