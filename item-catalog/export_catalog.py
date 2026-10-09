"""Export read-only game reference tables and browser-playable audio."""
from __future__ import annotations

import ctypes
import hashlib
import json
import re
import struct
from collections import defaultdict
from pathlib import Path

from export_cards import Decoder, records, simplified, main as export_cards

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / 'public'


def number(value):
    return float(value) if '.' in value else int(value)


def clean(value):
    return simplified(value).replace('`n', '\n')


class Catalog:
    def __init__(self):
        self.decoder = Decoder(ROOT)
        self.sources = {}
        self.textures = {}
        self.images = {}
        self.issues = []

    def read(self, relative, encoding='cp950'):
        path = ROOT / relative
        self.sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        return self.decoder.unpack(path).decode(encoding)

    def table(self, relative, encoding='cp950'):
        return list(records(self.read(relative, encoding)))

    def texture(self, family, key):
        if family not in self.textures:
            self.textures[family] = {r['section']: r for r in self.table(f'Tex/{family}.dat', 'gbk')}
        value = self.textures[family].get(key, {}).get('npid')
        return self.image(int(value)) if value is not None else None

    def image(self, npid):
        if npid in self.images:
            return self.images[npid]
        path = ROOT / f'Tex/{npid // 500:02}/{npid:05}.np'
        result = None
        if path.exists():
            image = self.decoder.picture(path)
            result = f'images/{npid}.png'
            image.save(OUT / result, optimize=True)
        else:
            self.issues.append({'missingImage': path.relative_to(ROOT).as_posix()})
        self.images[npid] = result
        return result

    def other(self, key):
        match = re.fullmatch(r'other_(\d+)_(\d+)', key, re.I)
        return self.texture('other', f'O_{match[1]}_S_{match[2]}') if match else None

    def maps(self):
        previews = {r['map'].lower(): r for r in self.table('Data/MapView.kpd')}
        result = []
        for path in sorted((ROOT / 'Map').glob('*.emp')):
            raw = path.read_bytes()
            version = struct.unpack_from('<I', raw, 16)[0]
            if version not in (1, 2, 3):
                raise ValueError(f'Unsupported map: {path}')
            meta_count = 3 + 2 * (version >= 2) + (version >= 3)
            meta = struct.unpack_from('<' + 'i' * meta_count, raw, 23288)
            at = 23288 + meta_count * 4
            name = clean(raw[at:at + 20].split(b'\0')[0].decode('cp950'))
            description = clean(raw[at + 20:at + 120].split(b'\0')[0].decode('cp950'))
            preview = previews.get(path.name.lower(), {})
            result.append({'id': path.stem, 'name': name, 'description': description,
                           'size': f'{meta[-2]} × {meta[-1]}',
                           'image': self.other(preview.get('pic_enb', '')),
                           'source': path.relative_to(ROOT).as_posix()})
            self.sources[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return result

    def roles(self):
        result = []
        for r in self.table('Data/Role.kpd'):
            text = clean(r.get('tag', ''))
            if '?' in text:
                text = text.replace('?', '□') + '（原始文字缺字）'
            result.append({'id': int(r['indx']), 'name': clean(r['name']),
                           'sex': {'girl': '女', 'boy': '男'}.get(r.get('sex'), '未注明'),
                           'birthday': clean(r.get('birthday', '未注明')), 'description': text,
                           'image': self.texture('role', f"R_{r['suit0']}_D_0_F_0"),
                           'source': r})
        return result

    def npcs(self):
        result = []
        for r in self.table('Data/Npc.kpd'):
            modes = [label for key, label in [('bCm', '普通'), ('bPk', 'PK'), ('bHb', '拆屋')] if r.get(key) == 'true']
            result.append({'id': int(r['indx']), 'name': clean(r['name']),
                           'affix': f"{r['affix']} 天" if int(r['affix']) > 0 else '—',
                           'respawn': f"{r['anew']} 天" if int(r['anew']) > 0 else '—',
                           'modes': '、'.join(modes) or '未配置',
                           'image': self.texture('npc', f"N_{r['indx']}_S_0"), 'source': r})
        return result

    def events(self, maps, props):
        result = []
        for r in self.table('Tex/event.dat', 'gbk'):
            match = re.fullmatch(r'EVENT_(\d+)', r['section'])
            if match:
                result.append({'id': f'格-{match[1]}', 'name': clean(r['name']), 'kind': '地图事件格',
                               'map': '—', 'description': '—',
                               'image': self.texture('event', f'E_{match[1]}_S_0'), 'source': r})
        map_names = {r['source'].split('/')[-1].lower(): r['name'] for r in maps}
        for file, prefix, kind in [('Data/KoNews.kpd', '闯关', '闯关新闻'), ('Data/BwNews.kpd', '首领', '首领战新闻')]:
            for line_number, line in enumerate(self.read(file).splitlines(), 1):
                if not line.strip() or line.lstrip().startswith('//'):
                    continue
                cells = line.split('\t')
                if len(cells) != 10:
                    raise ValueError(f'Unexpected event row: {file}:{line_number}')
                low, high = int(cells[5]), int(cells[6])
                amount = str(low) if low == high else f'{low}～{high}'
                card_names = [clean(props[int(v)]['name']) for v in cells[7].split(',') if v.isdigit() and int(v) in props]
                description = clean(cells[9]).replace('%d', amount).replace('%%', '%').replace('%s', '、'.join(card_names) or '指定卡片')
                result.append({'id': f'{prefix}-{line_number}', 'name': kind, 'kind': kind,
                               'map': map_names.get(cells[0].lower(), cells[0]), 'description': description,
                               'image': self.other(cells[8]), 'source': {'file': file, 'line': line_number, 'values': cells}})
        return result

    def mall(self, props):
        offers = defaultdict(list)
        for offer in self.table('Data/SellProp.kpd'):
            offers[int(offer['prop'])].append(offer['section'])
        labels = {'CARD': '卡片', 'FUNC': '功能道具', 'AVATAR': '装饰道具'}
        result = []
        for item_id, groups in sorted(offers.items()):
            r = props[item_id]
            available = r.get('enable', '').split(',')[0] == 'true'
            prices = []
            for suffix, field, label in [('J', 'LJ', '代币'), ('R', 'LR', '金豆')]:
                if any(g.endswith('_' + suffix) for g in groups) and r.get('sale' + field) == 'true' and available:
                    value = r.get('price' + field)
                    prices.append(f'{number(value):,g} {label}' if value else f'{label}价格未配置')
            result.append({'id': item_id, 'name': clean(r['name']), 'kind': labels.get(r['type'], '其他'),
                           'description': clean(r.get('desc', '')) or '暂无描述',
                           'price': '\n'.join(prices) if prices else '未开放购买',
                           'image': self.texture('card', f"CARD_{r['icon']}") if r.get('icon') else None,
                           'source': {'offers': groups, 'fields': r}})
        return result

    def audio(self, music):
        folder, prefix = ('Music', 'mus') if music else ('Sound', 'snd')
        effective, history = {}, defaultdict(list)
        batch = None
        for index in range(10000):
            path = ROOT / folder / f'{prefix}{index:04}.dat'
            if not path.exists():
                break
            raw = path.read_bytes()
            signature, current_batch, count = struct.unpack_from('<4sII', raw)
            if signature != (b'mus%' if music else b'snd%') or count > 20000 or len(raw) < 12 + count * 16:
                raise ValueError(f'Invalid audio header: {path}')
            if batch is None:
                batch = current_batch
            if current_batch != batch:
                continue
            self.sources[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
            for i in range(count):
                item_id, offset, size, extra = struct.unpack_from('<IIII', raw, 12 + i * 16)
                packed_size = extra if extra and not music else size
                if offset < 12 + count * 16 or size > 64 * 1024 * 1024 or offset + packed_size > len(raw):
                    raise ValueError(f'Invalid audio range: {path}:{item_id}')
                entry = {'id': item_id, 'file': path.relative_to(ROOT).as_posix(), 'offset': offset, 'size': size, 'extra': extra}
                history[item_id].append(entry)
                effective[item_id] = entry
        result = []
        (OUT / 'audio' / prefix).mkdir(parents=True, exist_ok=True)
        for item_id, entry in sorted(effective.items()):
            with (ROOT / entry['file']).open('rb') as stream:
                stream.seek(entry['offset'])
                payload = stream.read(entry['extra'] if entry['extra'] and not music else entry['size'])
            if entry['extra'] and not music:
                out = ctypes.create_string_buffer(entry['size'])
                if self.decoder.lib.resource_decompress(payload, len(payload), out, entry['size']) != 0:
                    raise ValueError('Audio decompression failed')
                payload = out.raw
            extension = 'wav' if payload.startswith(b'RIFF') else 'mp3'
            target = f'audio/{prefix}/{item_id}.{extension}'
            (OUT / target).write_bytes(payload)
            result.append({'id': item_id, 'name': ('背景音乐' if music else '音效') + f' {item_id}',
                           'file': entry['file'].split('/')[-1], 'size': f'{len(payload) / 1024:.1f} KB',
                           'format': extension.upper(), 'audio': target, 'source': history[item_id]})
        return result


def main():
    export_cards()
    catalog = Catalog()
    props = {int(r['indx']): r for r in catalog.table('Data/Prop.kpd')}
    data = json.loads((OUT / 'cards.json').read_text(encoding='utf-8'))
    data['maps'] = catalog.maps()
    data['roles'] = catalog.roles()
    data['npcs'] = catalog.npcs()
    data['events'] = catalog.events(data['maps'], props)
    data['mall'] = catalog.mall(props)
    data['sounds'] = catalog.audio(False)
    data['music'] = catalog.audio(True)
    data['sourceFiles'].update(catalog.sources)
    data['exportIssues'] = catalog.issues
    serialized = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    (OUT / 'catalog.json').write_text(serialized, encoding='utf-8')
    (OUT / 'catalog.js').write_text('window.GAME_CATALOG=' + serialized.replace('<', '\\u003c') + ';\n', encoding='utf-8')
    print(json.dumps({key: len(data[key]) for key in ['cards', 'events', 'roles', 'npcs', 'maps', 'mall', 'sounds', 'music']}))


if __name__ == '__main__':
    main()
