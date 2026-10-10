"""复用现有KPD解包器，只读记录ASTable样本与精确ASCII转录。"""
from pathlib import Path
import hashlib
import importlib.util
import json
from collections import Counter

ROOT = Path('F:/大富翁online/Richonline')
BASE = Path(__file__).resolve().parent


def main():
    helper = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/inspect_resources.py'
    spec = importlib.util.spec_from_file_location('astable_existing_kpd_reader', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    blob = (ROOT / 'Data/ASTable.kpd').read_bytes()
    plain, key, packed = module.decode(blob)
    groups = module.sections(plain.decode('latin1'))
    for group in groups:
        group['field_byte_lengths'] = {key: len(value.encode('latin1')) for key, value in group['fields'].items()}
    result = dict(source='Data/ASTable.kpd', source_sha256=hashlib.sha256(blob).hexdigest(), source_size=len(blob),
                  decoded_sha256=hashlib.sha256(plain).hexdigest(), decoded_size=len(plain), key=key,
                  packed_size=packed, tail_size=len(blob) - 9 - packed,
                  reused_decoder=str(helper.relative_to(ROOT)).replace('\\', '/'), decoder_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
                  section_counts=dict(Counter(group['name'] for group in groups)), sections=groups,
                  caveat='Latin-1只作逐字节映射；顺序保留，字典不证明重复键语义；精确行另有decoded.bin与转录')
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'ASTable.kpd.decoded.bin').write_bytes(plain)
    (BASE / 'resource.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// ASTable.kpd只读转录；精确字节见证据/ASTable.kpd.decoded.bin。',
             '// 非ASCII行仅列原字节；转录不替代客户端缺键、数量及图片ID失败验证。']
    for line in plain.rstrip(b'\0').splitlines():
        lines.append('// ' + (line.decode('ascii') if line.isascii() else '原始字节：' + line.hex()))
    (BASE.parent / '04_资源配置只读转录.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(sections=len(groups), section_counts=result['section_counts']), ensure_ascii=False))


if __name__ == '__main__':
    main()
