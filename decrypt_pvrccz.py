#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cocos2d *.pvr.ccz / *.ccz 解密解压 + PVR 转 PNG 脚本

用途：
    - 递归扫描输入目录
    - 处理 Cocos2d CCZ/CCZp 文件
    - 对 CCZp 使用 ZipUtils::setPvrEncryptionKey 对应的 4 个 uint 解密
    - zlib 解压后输出 .pvr
    - 可选调用 PVRTexToolCLI.exe 将 .pvr 转成 .png
    - 保留目录结构
    - 输出简洁 JSON 报告

PVR key：
    key1 = 0x72C159A2
    key2 = 0x4B3F9693
    key3 = 0x97BC2991
    key4 = 0x8A8EF15B

用法：
    只解密/解压为 PVR：
        python decrypt_pvrccz.py --input ./input --output ./output

    解密/解压后自动转 PNG：
        python decrypt_pvrccz.py --input ./input --output ./output --convert-png --pvrtcli "C:\\Path\\To\\PVRTexToolCLI.exe"

你需要搜索 PVRTexTool 下载安装后，在安装目录中拷贝适用于Windows的CLI exe版本。（其他系统请自行搜索）
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import zlib
from pathlib import Path


PVR_KEY_PARTS = (
    0x72C159A2,
    0x4B3F9693,
    0x97BC2991,
    0x8A8EF15B,
)

CCZ_HEADER_SIZE = 16
CCZ_COMPRESSION_ZLIB = 0
UINT32_MASK = 0xFFFFFFFF


def u32(x: int) -> int:
    return x & UINT32_MASK


def read_u16_be(buf: bytes, off: int) -> int:
    return struct.unpack_from(">H", buf, off)[0]


def read_u32_be(buf: bytes, off: int) -> int:
    return struct.unpack_from(">I", buf, off)[0]


def read_u32_le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def write_u32_le(buf: bytearray, off: int, value: int):
    struct.pack_into("<I", buf, off, u32(value))


def make_pvr_encryption_key(key_parts=PVR_KEY_PARTS):
    enc_len = 1024
    encryption_key = [0] * enc_len

    rounds = 6
    sum_ = 0
    z = encryption_key[enc_len - 1]
    delta = 0x9E3779B9

    while rounds > 0:
        sum_ = u32(sum_ + delta)
        e = (sum_ >> 2) & 3

        for p in range(enc_len - 1):
            y = encryption_key[p + 1]
            mx = (
                (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                ^ ((sum_ ^ y) + (key_parts[(p & 3) ^ e] ^ z))
            )
            encryption_key[p] = u32(encryption_key[p] + mx)
            z = encryption_key[p]

        p = enc_len - 1
        y = encryption_key[0]
        mx = (
            (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((sum_ ^ y) + (key_parts[(p & 3) ^ e] ^ z))
        )
        encryption_key[enc_len - 1] = u32(encryption_key[enc_len - 1] + mx)
        z = encryption_key[enc_len - 1]

        rounds -= 1

    return encryption_key


PVR_ENCRYPTION_KEY = make_pvr_encryption_key()


def decode_encoded_pvr_inplace(buf: bytearray, start: int = 12):
    enc_len = 1024
    secure_len = 512
    distance = 64

    word_count = (len(buf) - start) // 4
    key_index = 0
    i = 0

    while i < word_count and i < secure_len:
        off = start + i * 4
        value = read_u32_le(buf, off)
        write_u32_le(buf, off, value ^ PVR_ENCRYPTION_KEY[key_index])
        key_index += 1
        if key_index >= enc_len:
            key_index = 0
        i += 1

    while i < word_count:
        off = start + i * 4
        value = read_u32_le(buf, off)
        write_u32_le(buf, off, value ^ PVR_ENCRYPTION_KEY[key_index])
        key_index += 1
        if key_index >= enc_len:
            key_index = 0
        i += distance


def checksum_pvr_words(buf: bytes, start: int = 12) -> int:
    word_count = (len(buf) - start) // 4
    count = min(word_count, 128)
    cs = 0
    for i in range(count):
        cs ^= read_u32_le(buf, start + i * 4)
    return u32(cs)


def detect_output_type(buf: bytes):
    if buf.startswith(b"PVR"):
        return "pvr", ".pvr"
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", ".png"
    if buf.startswith(b"\xff\xd8\xff"):
        return "jpg", ".jpg"
    if buf.startswith(b"RIFF") and len(buf) >= 12 and buf[8:12] == b"WEBP":
        return "webp", ".webp"
    return "bin", ".bin"


def inflate_ccz(data: bytes, verify_checksum: bool = False):
    info = {
        "input_head": data[:16].hex(),
        "encrypted": False,
        "compression_type": None,
        "version": None,
        "reserved": None,
        "declared_uncompressed_len": None,
        "checksum_ok": None,
    }

    if len(data) < CCZ_HEADER_SIZE:
        info["reason"] = "too_short_for_ccz_header"
        return False, None, info

    sig = data[:4]
    if sig not in (b"CCZ!", b"CCZp"):
        info["reason"] = "not_ccz_or_cczp"
        return False, None, info

    compression_type = read_u16_be(data, 4)
    version = read_u16_be(data, 6)
    reserved = read_u32_be(data, 8)

    info["compression_type"] = compression_type
    info["version"] = version
    info["reserved"] = f"0x{reserved:08x}"

    if compression_type != CCZ_COMPRESSION_ZLIB:
        info["reason"] = f"unsupported_compression_type_{compression_type}"
        return False, None, info

    buf = bytearray(data)

    if sig == b"CCZ!":
        if version > 2:
            info["reason"] = f"unsupported_ccz_version_{version}"
            return False, None, info
    else:
        info["encrypted"] = True
        if version > 0:
            info["reason"] = f"unsupported_cczp_version_{version}"
            return False, None, info

        decode_encoded_pvr_inplace(buf, start=12)

        if verify_checksum:
            calculated = checksum_pvr_words(buf, start=12)
            info["checksum_ok"] = calculated == reserved
            info["checksum_calculated"] = f"0x{calculated:08x}"
            if calculated != reserved:
                info["reason"] = "checksum_mismatch_after_decrypt"
                return False, None, info

    declared_len = read_u32_be(buf, 12)
    info["declared_uncompressed_len"] = declared_len

    compressed = bytes(buf[CCZ_HEADER_SIZE:])

    try:
        out = zlib.decompress(compressed)
    except Exception as e:
        try:
            out = zlib.decompress(compressed, -zlib.MAX_WBITS)
            info["zlib_mode"] = "raw_deflate_fallback"
        except Exception:
            info["reason"] = f"zlib_decompress_failed: {e}"
            return False, None, info
    else:
        info["zlib_mode"] = "zlib"

    info["actual_uncompressed_len"] = len(out)
    info["declared_len_matches"] = (not declared_len) or (declared_len == len(out))

    out_type, out_ext = detect_output_type(out)
    info["output_type"] = out_type
    info["output_ext"] = out_ext
    info["output_head"] = out[:16].hex()

    return True, out, info


def make_output_path(in_path: Path, in_root: Path, out_root: Path, output_ext: str):
    rel = in_path.relative_to(in_root)
    out_path = out_root / rel

    name = out_path.name.lower()
    if name.endswith(".pvr.ccz"):
        return out_path.with_name(out_path.name[:-4])  # strip only .ccz -> .pvr
    if name.endswith(".ccz"):
        return out_path.with_suffix(output_ext)

    return out_path.with_suffix(out_path.suffix + output_ext)


def pvr_to_png_path(pvr_path: Path):
    if pvr_path.name.lower().endswith(".pvr"):
        return pvr_path.with_suffix(".png")
    return pvr_path.with_name(pvr_path.name + ".png")


def resolve_pvrtcli(user_path: str | None):
    if user_path:
        candidate = Path(user_path)
        if candidate.exists():
            return str(candidate)
        return None

    # 如果用户没有传路径，尝试从 PATH 找。
    found = shutil.which("PVRTexToolCLI.exe") or shutil.which("PVRTexToolCLI")
    if found:
        return found

    # 常见安装路径兜底；找不到也不报错，由调用处记录失败。
    common_candidates = [
        r"C:\\Program Files\\Imgtec\\PowerVR_Tools\\PVRTexTool\\CLI\\Windows_x86_64\\PVRTexToolCLI.exe\",
    ]
    for p in common_candidates:
        if Path(p).exists():
            return p

    return None


def convert_pvr_to_png(pvr_path: Path, png_path: Path, pvrtcli: str, timeout_seconds: int = 120):
    """
    调用 PVRTexToolCLI 将 PVR 转 PNG。

    不同版本 PVRTexToolCLI 参数可能略有差异。这里优先使用常见形式：
        PVRTexToolCLI.exe -i input.pvr -d output.png

    如果你的版本不支持，可在这里把 cmd 改成你的版本要求。
    """
    png_path.parent.mkdir(parents=True, exist_ok=True)

    commands_to_try = [
        [pvrtcli, "-i", str(pvr_path), "-d", str(png_path)],
        [pvrtcli, "-i", str(pvr_path), "-o", str(png_path)],
    ]

    last_result = None
    for cmd in commands_to_try:
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except Exception as e:
            last_result = {
                "ok": False,
                "cmd": cmd,
                "reason": f"exception: {e}",
                "stdout": "",
                "stderr": "",
            }
            continue

        ok = completed.returncode == 0 and png_path.exists() and png_path.stat().st_size > 0
        result = {
            "ok": ok,
            "cmd": cmd,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-2000:],
            "stderr": completed.stderr[-2000:],
            "output": str(png_path),
        }
        if ok:
            return result
        last_result = result

    return last_result or {
        "ok": False,
        "reason": "no_command_attempted",
        "output": str(png_path),
    }


def should_process(path: Path, all_files: bool):
    if all_files:
        return True
    name = path.name.lower()
    return name.endswith(".ccz") or name.endswith(".pvr.ccz") or name.endswith(".pvr")


def main():
    parser = argparse.ArgumentParser(description="Decrypt/inflate Cocos2d PVR CCZ/CCZp files, optionally convert PVR to PNG.")
    parser.add_argument("--input", "-i", required=True, help="输入目录")
    parser.add_argument("--output", "-o", required=True, help="输出目录")
    parser.add_argument("--all-files", action="store_true", help="扫描所有文件；默认只处理 *.ccz / *.pvr.ccz / *.pvr")
    parser.add_argument("--verify-checksum", action="store_true", help="校验 CCZp reserved checksum；默认不强制校验")
    parser.add_argument("--copy-pvr", action="store_true", help="如果遇到已是明文 PVR 的文件，也复制到输出目录")
    parser.add_argument("--convert-png", action="store_true", help="输出 .pvr 后调用 PVRTexToolCLI.exe 转 PNG")
    parser.add_argument("--pvrtcli", default=None, help=r'PVRTexToolCLI.exe 路径，例如 "C:\...\PVRTexToolCLI.exe"')
    parser.add_argument("--png-only", action="store_true", help="转 PNG 成功后删除中间 .pvr")
    parser.add_argument("--convert-timeout", type=int, default=120, help="单个 PVR 转 PNG 超时时间，默认 120 秒")
    args = parser.parse_args()

    in_root = Path(args.input)
    out_root = Path(args.output)

    if not in_root.exists():
        raise FileNotFoundError(f"input directory does not exist: {in_root}")

    resolved_pvrtcli = resolve_pvrtcli(args.pvrtcli) if args.convert_png else None
    if args.convert_png and not resolved_pvrtcli:
        print("[warn] --convert-png enabled, but PVRTexToolCLI.exe was not found.")
        print("[warn] pass it explicitly with: --pvrtcli \"C:\\Path\\To\\PVRTexToolCLI.exe\"")

    stats = {
        "total_seen": 0,
        "processed_candidates": 0,
        "decrypted_or_inflated": 0,
        "plain_pvr_copied": 0,
        "png_converted": 0,
        "png_convert_failed": 0,
        "failed": 0,
        "skipped": 0,
    }
    success = []
    failed = []
    convert_failed = []

    print(f"[input]  {in_root}")
    print(f"[output] {out_root}")
    print("[pvr key] " + ", ".join(f"0x{x:08X}" for x in PVR_KEY_PARTS))
    if args.convert_png:
        print(f"[pvrtcli] {resolved_pvrtcli or 'NOT FOUND'}")
    print("-" * 80)

    for root, _, files in os.walk(in_root):
        for filename in files:
            stats["total_seen"] += 1
            in_path = Path(root) / filename

            if not should_process(in_path, args.all_files):
                stats["skipped"] += 1
                continue

            rel_path = in_path.relative_to(in_root)
            stats["processed_candidates"] += 1

            try:
                data = in_path.read_bytes()
            except Exception as e:
                stats["failed"] += 1
                failed.append({"file": str(rel_path), "reason": f"read_error: {e}"})
                print(f"[read failed] {rel_path}: {e}")
                continue

            out_path = None
            info = {}

            # 已是明文 PVR
            if data.startswith(b"PVR"):
                if not args.copy_pvr and not args.convert_png:
                    stats["skipped"] += 1
                    continue

                out_path = out_root / rel_path
                out_path.parent.mkdir(parents=True, exist_ok=True)
                if args.copy_pvr or args.convert_png:
                    out_path.write_bytes(data)
                    stats["plain_pvr_copied"] += 1
                    print(f"[plain pvr] {rel_path}")
                    info = {"output_type": "pvr", "mode": "plain_pvr"}
            else:
                ok, out, info = inflate_ccz(data, verify_checksum=args.verify_checksum)
                if not ok:
                    stats["failed"] += 1
                    failed.append({
                        "file": str(rel_path),
                        "reason": info.get("reason"),
                        "info": info,
                        "size": len(data),
                    })
                    print(f"[failed] {rel_path}: {info.get('reason')}")
                    continue

                out_ext = info.get("output_ext") or ".pvr"
                out_path = make_output_path(in_path, in_root, out_root, out_ext)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(out)

                stats["decrypted_or_inflated"] += 1
                print(f"[ok] {rel_path} -> {info.get('output_type')} | {out_path.relative_to(out_root)}")

            success_item = {
                "file": str(rel_path),
                "mode": info.get("mode") or ("cczp_decrypt_inflate" if info.get("encrypted") else "ccz_inflate"),
                "output_type": info.get("output_type"),
                "output": str(out_path),
                "declared_uncompressed_len": info.get("declared_uncompressed_len"),
                "actual_uncompressed_len": info.get("actual_uncompressed_len"),
            }

            # 可选转 PNG
            if args.convert_png and out_path and out_path.exists() and out_path.suffix.lower() == ".pvr":
                if not resolved_pvrtcli:
                    stats["png_convert_failed"] += 1
                    cf = {
                        "file": str(rel_path),
                        "pvr": str(out_path),
                        "reason": "PVRTexToolCLI.exe not found",
                    }
                    convert_failed.append(cf)
                    success_item["png_convert"] = cf
                else:
                    png_path = pvr_to_png_path(out_path)
                    result = convert_pvr_to_png(
                        out_path,
                        png_path,
                        resolved_pvrtcli,
                        timeout_seconds=args.convert_timeout,
                    )
                    success_item["png_convert"] = result

                    if result.get("ok"):
                        stats["png_converted"] += 1
                        print(f"[png] {out_path.relative_to(out_root)} -> {png_path.relative_to(out_root)}")
                        if args.png_only:
                            try:
                                out_path.unlink()
                                success_item["pvr_deleted"] = True
                            except Exception as e:
                                success_item["pvr_delete_error"] = str(e)
                    else:
                        stats["png_convert_failed"] += 1
                        convert_failed.append({
                            "file": str(rel_path),
                            "pvr": str(out_path),
                            "reason": result.get("reason") or f"returncode={result.get('returncode')}",
                            "result": result,
                        })
                        print(f"[png failed] {out_path.relative_to(out_root)}")

            success.append(success_item)

    report = {
        "config": {
            "key_parts": [f"0x{x:08X}" for x in PVR_KEY_PARTS],
            "input": str(in_root),
            "output": str(out_root),
            "verify_checksum": args.verify_checksum,
            "convert_png": args.convert_png,
            "pvrtcli": resolved_pvrtcli,
            "png_only": args.png_only,
        },
        "stats": stats,
        "success": success,
        "failed": failed,
        "png_convert_failed": convert_failed,
    }

    report_path = out_root / "_pvr_ccz_decrypt_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 80)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"[report] {report_path}")


if __name__ == "__main__":
    main()
