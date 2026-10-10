"""复用既有 KPD 解包器，只读核 MapView 样本；保留重复 ITEM 顺序。"""
from pathlib import Path
import hashlib
import importlib.util
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = Path(__file__).resolve().parent


def main():
    helper = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/inspect_resources.py'
    spec = importlib.util.spec_from_file_location('mapview_existing_resource_reader', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    blob = (ROOT / 'Data/MapView.kpd').read_bytes()
    plain, key, packed = module.decode(blob)
    text = plain.decode('latin1')
    records = module.sections(text)
    for record in records:
        record['field_byte_lengths'] = {
            name: len(value.encode('latin1')) for name, value in record['fields'].items()
        }
        value = record['fields'].get('map')
        if value and value.isascii():
            relative = 'Map/' + value.replace('\\', '/')
            path = ROOT / relative
            record['file_disk'] = dict(path=relative, exists=path.is_file(),
                                      sha256=hashlib.sha256(path.read_bytes()).hexdigest()
                                      if path.is_file() else None)
    result = dict(source='Data/MapView.kpd', source_size=len(blob),
                  source_sha256=hashlib.sha256(blob).hexdigest(), key=key,
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  compressed_size=packed, tail_size=len(blob) - 9 - packed,
                  reused_decoder=str(helper.relative_to(ROOT)).replace('\\', '/'),
                  decoder_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
                  caveat='Latin-1 逐字节映射仅核 ASCII 键值；重复节顺序保留，非客户端失败模拟',
                  records=records)
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'MapView.kpd.decoded.bin').write_bytes(plain)
    (BASE / 'resource.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                       encoding='utf-8')
    reading = ['// MapView.kpd 只读转录；精确字节见证据/MapView.kpd.decoded.bin。',
               '// 非 ASCII 行只保留十六进制，避免将 Latin-1 映射误当中文字码。']
    for line in plain.rstrip(b'\0').splitlines():
        reading.append('// ' + (line.decode('ascii') if line.isascii() else '原始字节：' + line.hex()))
    (BASE.parent / '04_资源配置只读转录.txt').write_text('\n'.join(reading) + '\n', encoding='utf-8')
    return dict(records=len(records), item_records=sum(r['name'] == 'ITEM' for r in records),
                source_sha256=result['source_sha256'])


if __name__ == '__main__':
    print(json.dumps(main(), ensure_ascii=False))
