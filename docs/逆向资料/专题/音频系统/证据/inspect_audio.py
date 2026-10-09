"""只读核对当前音频容器；输出索引与载荷边界，不播放、不改资源。"""

import argparse
import hashlib
import json
import pathlib
import struct
from collections import Counter


def inspect(root: pathlib.Path) -> dict:
    result = {"files": [], "summary": {}}
    for folder, prefix in (("Sound", "snd"), ("Music", "mus")):
        ids = []
        group = []
        for path in sorted((root / folder).glob(prefix + "*.dat")):
            data = path.read_bytes()
            item = {"path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            if len(data) < 12:
                item["error"] = "文件不足 12 字节"
                group.append(item)
                continue
            header = struct.unpack_from("<III", data)
            item["header"] = header
            item["magic_bytes"] = data[:4].hex()
            if header[2] > (len(data) - 12) // 16:
                item["error"] = "声明的索引数超出文件"
                group.append(item)
                continue
            entries = [struct.unpack_from("<IIII", data, 12 + 16 * i)
                       for i in range(header[2])]
            item["entries"] = entries
            item["payload_prefixes"] = [data[e[1]:e[1] + 16].hex() for e in entries]
            item["out_of_bounds"] = [i for i, e in enumerate(entries)
                                     if e[1] + (e[3] or e[2]) > len(data)]
            item["overlaps_index"] = [i for i, e in enumerate(entries)
                                      if e[1] < 12 + 16 * len(entries)]
            item["riff_count"] = sum(data[e[1]:e[1] + 4] == b"RIFF" for e in entries)
            item["compressed_count"] = sum(e[3] != 0 for e in entries)
            ids.extend(e[0] for e in entries)
            group.append(item)
        counts = Counter(ids)
        result["files"].extend(group)
        result["summary"][folder] = {
            "files": len(group), "entries": len(ids),
            "min_id": min(ids) if ids else None, "max_id": max(ids) if ids else None,
            "duplicate_ids": {str(k): v for k, v in counts.items() if v > 1},
            "riff_count": sum(x.get("riff_count", 0) for x in group),
            "compressed_count": sum(x.get("compressed_count", 0) for x in group),
            "out_of_bounds": sum(len(x.get("out_of_bounds", [])) for x in group),
            "overlaps_index": sum(len(x.get("overlaps_index", [])) for x in group),
            "errors": [x["path"] for x in group if "error" in x],
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    report = inspect(args.root.resolve())
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
