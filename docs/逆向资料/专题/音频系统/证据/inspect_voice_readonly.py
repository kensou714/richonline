"""只读记录 Voice.dat 和 VoiceFace.kpd；不生成可替换的游戏文件。"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import lzokay


def inspect(root: Path) -> dict:
    voice = (root / "Config/Voice.dat").read_bytes()
    if len(voice) % 32:
        raise ValueError("Voice.dat 不是完整的 8 个 DWORD 角色行")
    words = struct.unpack("<" + "i" * (len(voice) // 4), voice)
    packed_file = (root / "Data/VoiceFace.kpd").read_bytes()
    if len(packed_file) < 9:
        raise ValueError("VoiceFace.kpd 不足容器头长度")
    key = packed_file[0]
    raw_size, packed_size = struct.unpack(
        "<II", bytes((x - key) & 255 for x in packed_file[1:9]))
    if not (0 < raw_size <= 64 * 1024 * 1024 and 0 < packed_size <= len(packed_file) - 9):
        raise ValueError("VoiceFace.kpd 长度声明越界")
    plain = lzokay.decompress(
        bytes((x - key) & 255 for x in packed_file[9:9 + packed_size]), raw_size)
    if len(plain) != raw_size:
        raise ValueError("VoiceFace.kpd 解码后长度不符")
    decoded_text = plain.decode("gb18030")
    if decoded_text.encode("gb18030") != plain:
        raise ValueError("VoiceFace.kpd 中文文本不能无损往返")
    return {
        "Voice.dat": {
            "path": "Config/Voice.dat", "sha256": hashlib.sha256(voice).hexdigest(),
            "size": len(voice), "rows8": [words[i:i + 8] for i in range(0, len(words), 8)]},
        "VoiceFace.kpd": {
            "path": "Data/VoiceFace.kpd", "sha256": hashlib.sha256(packed_file).hexdigest(),
            "key": key, "declared_raw": raw_size, "declared_packed": packed_size,
            "decoded_sha256": hashlib.sha256(plain).hexdigest(), "decoded_text": decoded_text,
            "decoder": "lzokay；载荷逐字节减首字节后 LZO 解码",
            "text_encoding": "本样本 gb18030 解码与重新编码逐字节相同；不宣称原始编码唯一"}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = inspect(args.root.resolve())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Voice.dat rows:", len(result["Voice.dat"]["rows8"]))
    print("VoiceFace.kpd decoded bytes:", result["VoiceFace.kpd"]["declared_raw"])
