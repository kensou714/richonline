"""整理资源全样本词法统计与复用消费窗；不模拟游戏查找策略。"""
import json
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    resources = json.loads((HERE / 'resources.json').read_bytes())
    frames, duplicates, sparse, avatars, images, coords = Counter(), [], [], [], [], []
    variants, positive_props, image_keys, duplicate_sections = {}, [], Counter(), []
    section_domains, bad_coordinates, pos_domains, section_deviations = Counter(), [], Counter(), []
    for file in resources['files']:
        lexical = file['lexical']
        if file['path'].endswith('.avt'):
            name = Path(file['path']).stem
            family, number = name.rsplit('_', 1)
            variants.setdefault(family, []).append(int(number))
            section_domains.update((len(lexical['sections']),))
            for row in lexical['entries']:
                if row['key_ascii'] == 'frame':
                    frames.update((row.get('decimal_literal'),))
                elif row['key_ascii'].startswith('pos'):
                    value = bytes.fromhex(row['value_hex']).strip()
                    pos_domains.update((row['key_ascii'],))
                    if not re.fullmatch(rb'-?\d+\s*,\s*-?\d+', value):
                        bad_coordinates.append(dict(path=file['path'], line=row['line'], value_hex=row['value_hex']))
            if lexical['duplicate_keys']:
                duplicates.append(dict(path=file['path'], items=lexical['duplicate_keys']))
            expected = {f'DIR_{direction}_PIC_{picture}' for direction in range(4) for picture in range(26)}
            actual = {section['ascii'] for section in lexical['sections']}
            names = Counter(section['ascii'] for section in lexical['sections'])
            if any(count > 1 for count in names.values()):
                duplicate_sections.append(dict(path=file['path'], names={name: count for name, count in names.items() if count > 1}))
            if actual != expected:
                section_deviations.append(dict(path=file['path'], missing=sorted(expected - actual), extra=sorted(actual - expected)))
        else:
            for section in lexical['sections']:
                rows = [row for row in lexical['entries'] if row['section_index'] == section['index']]
                values = [(row['key_ascii'], bytes.fromhex(row['value_hex']).strip().decode('ascii')) for row in rows]
                if section['ascii'].startswith('AVATAR_'):
                    props = sorted(int(key[4:]) for key, value in values if re.fullmatch(r'prop\d+', key))
                    consumed = 0
                    while consumed in props:
                        consumed += 1
                    avatar = dict(section=section['ascii'], props=props, contiguous_count=consumed, values=values)
                    avatars.append(avatar)
                    positive_props.extend(int(value) for key, value in values if re.fullmatch(r'prop\d+', key) and int(value) > 0)
                    if props != list(range(len(props))):
                        sparse.append(avatar)
                    coords.extend(value for key, value in values if key == 'coord')
                elif section['ascii'].startswith('AVAT_'):
                    images.extend(value for key, value in values)
                    image_keys.update(key for key, value in values)
    result = dict(files=len(resources['files']), avt_files=sum(file['path'].endswith('.avt') for file in resources['files']),
                  avt_section_counts=dict(section_domains), frame_counts=dict(frames), pos_keys=dict(pos_domains),
                  bad_coordinates=bad_coordinates, section_deviations=section_deviations, duplicate_files=duplicates, avatar_count=len(avatars),
                  avatars=avatars, sparse_props=sparse, coordinate_names=dict(Counter(coords)),
                  image_values=dict(Counter(images)),
                  image_key_counts=dict(image_keys), image_prefixes=dict(Counter(value.split('_', 1)[0] for value in images)),
                  positive_prop_count=len(positive_props), unique_positive_props=len(set(positive_props)),
                  avt_variants=variants, duplicate_sections=duplicate_sections,
                  avatar_prop_key_counts=dict(Counter(len(avatar['props']) for avatar in avatars)),
                  avatar_consumed_prop_counts=dict(Counter(avatar['contiguous_count'] for avatar in avatars)))
    (HERE / 'resource_digest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    compact = {key: value for key, value in result.items() if key not in ('avatars', 'image_values', 'duplicate_files', 'coordinate_names')}
    compact['duplicate_file_count'] = len(duplicates)
    compact['duplicate_key_count'] = sum(len(row['items']) for row in duplicates)
    compact['image_value_count'] = len(result['image_values'])
    compact['coordinate_name_count'] = len(result['coordinate_names'])
    print(json.dumps(compact, ensure_ascii=True))
    reused = json.loads((HERE / 'reused_verified.json').read_bytes())
    for function in reused['functions']:
        if function['va'] == '0x642740':
            for window in function['windows']:
                print(window['site'])
                for instruction in window['context']:
                    print(instruction['va'], instruction['capstone'])


if __name__ == '__main__':
    build()
