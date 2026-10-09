"""校验逆向档案的UTF-8、注释式排版和JSON可读性，保存可追溯时点快照。"""
import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / '全量分析/archive_validation.json'

def main():
    checked, errors = [], []
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or path == REPORT or path.suffix not in {'.txt', '.json', '.py'}:
            continue
        before = path.stat()
        raw = path.read_bytes()
        item = dict(path=path.relative_to(ROOT).as_posix(), bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(), errors=[])
        try:
            content = raw.decode('utf-8-sig', errors='strict')
            if path.suffix == '.json':
                json.loads(content)
            elif path.suffix == '.py':
                ast.parse(content, filename=str(path))
            else:
                in_block = False
                for number, line in enumerate(content.splitlines(), 1):
                    text = line.strip()
                    if not text:
                        continue
                    if text.startswith('```') or text.startswith('# '):
                        item['errors'].append(dict(line=number, reason='出现Markdown排版'))
                    if in_block:
                        if not text.startswith(('*', '//')):
                            item['errors'].append(dict(line=number, reason='块注释内未沿用星号排版'))
                        if '*/' in text:
                            in_block = False
                    elif text.startswith('/*'):
                        in_block = '*/' not in text[2:]
                    elif not text.startswith('//'):
                        item['errors'].append(dict(line=number, reason='非空行不属于注释式文档'))
                if in_block:
                    item['errors'].append(dict(reason='块注释未闭合'))
        except (UnicodeError, ValueError, SyntaxError) as exc:
            item['errors'].append(dict(reason=str(exc)))
        after = path.stat()
        if before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size:
            item['errors'].append(dict(reason='扫描时文件变化，需重跑'))
        if item['errors']:
            errors.append(item['path'])
        checked.append(item)
    counts = {extension: sum(Path(item['path']).suffix == extension for item in checked)
              for extension in ['.txt', '.json', '.py']}
    result = dict(checked_at=datetime.now(timezone.utc).isoformat(),
                  scope='本次读取字节的格式快照；不代表语义正确、客户端验证或之后新增文件已核对',
                  counts=counts, error_files=errors, files=checked)
    REPORT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(counts=counts, error_files=errors), ensure_ascii=False))
    if errors:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
