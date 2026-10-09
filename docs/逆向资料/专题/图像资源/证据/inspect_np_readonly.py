"""只读审计当前 Tex 的 NP 容器和客户端已证消费布局，不修改资源。
依赖：Python 3，lzokay；仅把 JSON 结果写到 --out 指定位置。
"""
from pathlib import Path
from collections import Counter
import argparse, hashlib, importlib.metadata, json, struct
import lzokay

MAX_BYTES = 64 * 1024 * 1024
MAX_PIXELS = 16 * 1024 * 1024
MAX_FRAMES = 4096

def sha(data):
    return hashlib.sha256(data).hexdigest().upper()

def inspect(path, root):
    """每个读取区间以文件/输出长度限制；不使用索引长度猜测截取。"""
    result = {"path": path.relative_to(root).as_posix(), "size": path.stat().st_size}
    if result["size"] > MAX_BYTES:
        return dict(result, error="文件超过64MiB审计上限")
    raw = path.read_bytes()
    result["sha256"] = sha(raw)
    try:
        if len(raw) < 9:
            raise ValueError("外层头不足9字节")
        key = raw[0]
        decoded, packed = struct.unpack("<II", bytes((b-key)&255 for b in raw[1:9]))
        result.update(key=key, decoded_size=decoded, packed_size=packed,
                      container_tail=len(raw)-9-packed)
        if not 0 < decoded <= MAX_BYTES or not 0 < packed <= len(raw)-9:
            raise ValueError("外层长度无效或超过审计上限")
        payload = bytes((b-key)&255 for b in raw[9:9+packed])
        output = lzokay.decompress(payload, decoded)
        if len(output) != decoded or len(output) < 9:
            raise ValueError("解压大小不符或内层头不足")
        result["decoded_sha256"] = sha(output)
        mode, width, height = struct.unpack_from("<BII", output)
        pixels = width * height
        result.update(mode=mode, width=width, height=height)
        if not 0 < pixels <= MAX_PIXELS:
            raise ValueError("像素数为零或超过审计上限")
        if mode == 1:
            if len(output) < 14:
                raise ValueError("索引图头不足")
            frames, alpha = struct.unpack_from("<IB", output, 9)
            result.update(frames=frames, alpha=alpha)
            if not 0 < frames <= MAX_FRAMES:
                raise ValueError("帧数为零或超过审计上限")
            # 忠实模拟客户端游标：alpha只读取，不推进；不把拟议格式当作事实。
            cursor, furthest = 14, 14
            for _ in range(frames):
                cursor += 768 + pixels
                furthest = max(furthest, cursor + (pixels if alpha else 0))
            time_bytes = 4 * frames if frames > 1 else 0
            furthest = max(furthest, cursor + time_bytes)
            result.update(client_cursor=cursor, client_required=furthest,
                          client_read_within_output=furthest <= len(output),
                          alpha_multiframe=bool(alpha and frames > 1),
                          conventional_layout_size=14+frames*(768+pixels*(2 if alpha else 1))+time_bytes)
            # conventional_layout_size 是独立比较项，不参与接受/拒绝与解码。
            result["tail_after_client_reads"] = len(output)-furthest
            if 0 <= len(output)-furthest <= 16:
                result["tail_hex"] = output[furthest:].hex()
            if time_bytes and cursor+time_bytes <= len(output):
                times = struct.unpack_from("<"+"I"*frames, output, cursor)
                result["duration_min_max_ms"] = [min(times), max(times)]
                result["first_durations_ms"] = list(times[:8])
        elif mode == 2:
            needed = 9 + pixels * 4
            result.update(frames=1, alpha=None, client_required=needed,
                          client_read_within_output=needed <= len(output),
                          tail_after_client_reads=len(output)-needed)
            if needed <= len(output):
                alphas = output[12:needed:4]
                result["nonopaque_pixel_count"] = sum(a != 255 for a in alphas)
                result["zero_alpha_pixel_count"] = alphas.count(0)
        else:
            result["unknown_mode"] = True
        return result
    except Exception as ex:
        result["error"] = type(ex).__name__ + ": " + str(ex)
        return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args=parser.parse_args()
    root=args.root.resolve()
    output=args.out.resolve()
    if root == output or (root/"Tex").resolve() in output.parents:
        raise SystemExit("结果文件不能写入原始Tex资源目录")
    files=sorted((root/"Tex").rglob("*.np"))
    rows=[inspect(p,root) for p in files]
    packages=sorted([p.relative_to(root).as_posix() for p in root.rglob("*")
                     if p.is_file() and p.suffix.lower() in (".npp",".tb")])
    counts=Counter((str(x.get("mode")),str(x.get("alpha")),str(x.get("frames",0)>1))
                   for x in rows if "error" not in x)
    result={"source_root":str(root),"source_exe_sha256":sha((root/"RnClient.exe").read_bytes()),
            "method":"有界外层解码+独立lzokay解压+IDA客户端游标读取范围模拟；没有执行游戏",
            "lzokay_version":importlib.metadata.version("lzokay"),
            "limits":{"max_file_or_decoded_bytes":MAX_BYTES,"max_pixels":MAX_PIXELS,"max_frames":MAX_FRAMES},
            "script_sha256":sha(Path(__file__).read_bytes()),
            "summary":{"np_files":len(rows),"errors":sum("error" in x for x in rows),
                       "client_read_out_of_bounds":sum(x.get("client_read_within_output") is False for x in rows),
                       "alpha_multiframe":sum(x.get("alpha_multiframe",False) for x in rows),
                       "mode_alpha_multiframe_counts":dict(sorted(("/".join(k),v) for k,v in counts.items())),
                       "package_or_index_files_found":packages},
            "files":rows}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result["summary"],ensure_ascii=False))
if __name__ == "__main__":
    main()
