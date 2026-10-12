"""Create an isolated website URL overlay from the actual online KPD."""
import argparse
import configparser
import ctypes
import hashlib
import io
import json
from pathlib import Path
import struct
from urllib.parse import urlsplit
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-root", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    uri = urlsplit(args.origin)
    if uri.scheme != "https" or not uri.netloc or uri.path not in ("", "/") or uri.query or uri.fragment:
        raise ValueError("An HTTPS origin is required")
    if args.output.exists():
        raise ValueError("Choose a new output directory")
    library = ctypes.CDLL(str((args.client_root / "ResourceCodec.dll").resolve()))
    library.resource_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    library.resource_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    library.resource_decompress.restype = library.resource_compress.restype = ctypes.c_int

    def decode(packed):
        shifted = bytes((b - packed[0]) % 256 for b in packed[1:])
        length, size = struct.unpack("<II", shifted[:8])
        if not 0 < length <= 65536 or size != len(shifted) - 8:
            raise ValueError("Invalid KPD")
        output = ctypes.create_string_buffer(length)
        if library.resource_decompress(shifted[8:], size, output, length) != 0:
            raise ValueError("Decompression failed")
        return output.raw

    source = args.client_root / "online-client/online.kpd"
    original = source.read_bytes()
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(decode(original).decode("cp950"))
    old = dict(config["AREA0"])
    changes = {"reg": "/register", "cong": "/claim", "wang": "/", "news": "/"}
    for key, suffix in changes.items():
        config["AREA0"][key] = args.origin.rstrip("/") + suffix
    stream = io.StringIO()
    config.write(stream, space_around_delimiters=False)
    plain = stream.getvalue().replace("\n", "\r\n").encode("cp950")
    capacity = len(plain) + len(plain) // 16 + 67
    output = ctypes.create_string_buffer(capacity)
    actual = ctypes.c_size_t()
    if library.resource_compress(plain, len(plain), output, capacity, ctypes.byref(actual)) != 0:
        raise ValueError("Compression failed")
    payload = struct.pack("<II", len(plain), actual.value) + output.raw[:actual.value]
    packed = original[:1] + bytes((b + original[0]) % 256 for b in payload)
    if decode(packed) != plain or source.read_bytes() != original:
        raise ValueError("Round trip or source stability check failed")
    if any(config["AREA0"][key] != value for key, value in old.items() if key not in changes):
        raise ValueError("Unexpected connection configuration change")
    args.output.mkdir(parents=True)
    files = {"online-client/online.kpd": packed, "online-client/online.ini": plain}
    manifest = {"sourceSha256": hashlib.sha256(original).hexdigest(), "changedKeys": changes,
                "websiteOrigin": args.origin, "clientExeChanged": False,
                "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()]}
    files["网站入口补丁说明.txt"] = ("退出游戏后，将 online-client 文件夹覆盖到客户端目录。继续使用 Start-Online.cmd 启动。\n"
        "只修改 reg（注册）、cong（代币领取）、wang（官网）、news（官网）四个网页入口；游戏服务器地址不变。\n"
        "实际读取 online.kpd；online.ini 仅供查看。修改密码在官网导航中，没有修改 EXE。\n").encode("utf-8-sig")
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    for name, data in files.items():
        path = args.output / "overlay" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with zipfile.ZipFile(args.output / "RichOnline-Website-Client.zip", "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
