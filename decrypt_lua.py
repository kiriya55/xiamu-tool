#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cocos2d-Lua XXTEA 解密脚本

已验证参数：
    sign = b"doboyu"
    key  = b"807a9e9a"

用法：
    python decrypt_lua.py --input ./input --output ./output

依赖：
    Py3ComUtils.Decrypt.xxtea
    Py3ComUtils.FileHandler.rbin / sbin
"""

import argparse
import json
import os
from pathlib import Path

from Py3ComUtils.Decrypt import xxtea
from Py3ComUtils.FileHandler import rbin, sbin


LUA_SIGN = b"doboyu"
LUA_KEY = b"807a9e9a"


def detect_file_type(buf: bytes):
    """简单识别明文/解密后文件类型。"""
    if not buf:
        return None, None

    if buf.startswith(b"\x1bLua"):
        return "lua_bytecode", ".luac"

    head = buf[:512].lstrip()

    if head.startswith((b"--", b"local ", b"return ", b"function ", b"module(")):
        return "lua_text", ".lua"

    if head.startswith(b"{") or head.startswith(b"["):
        return "json_or_text", ".json"

    if head.startswith(b"<?xml") or head.startswith(b"<plist") or b"<plist" in head[:256]:
        return "plist_or_xml", ".plist"

    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", ".png"

    if buf.startswith(b"\xff\xd8\xff"):
        return "jpg", ".jpg"

    if buf.startswith(b"PK\x03\x04"):
        return "zip", ".zip"

    # 宽松文本检测
    sample = buf[:1024]
    if sample:
        printable = sum(
            1 for c in sample
            if c in b"\r\n\t" or 32 <= c <= 126 or c >= 0x80
        )
        if printable / len(sample) > 0.92:
            return "text", ".txt"

    return None, None


def safe_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    sbin(str(path), data)


def output_path_with_ext(out_path: Path, detected_ext: str):
    known = {
        ".lua", ".luac", ".txt", ".json", ".plist", ".xml",
        ".png", ".jpg", ".jpeg", ".zip",
    }
    if out_path.suffix.lower() in known:
        return out_path
    return out_path.with_suffix(detected_ext)


def decrypt_one(data: bytes):
    """
    返回:
        (ok, decrypted_bytes, mode, detected_type, detected_ext, reason)
    """
    plain_type, plain_ext = detect_file_type(data)
    if plain_type:
        return True, data, "plain", plain_type, plain_ext, None

    if not data.startswith(LUA_SIGN):
        return False, None, "skip", None, None, "missing_lua_sign"

    try:
        dec = xxtea(data, LUA_SIGN, LUA_KEY)
    except Exception as e:
        return False, None, "xxtea", None, None, f"decrypt_exception: {e}"

    if not dec:
        return False, None, "xxtea", None, None, "empty_decrypt_result"

    ftype, ext = detect_file_type(dec)
    if not ftype:
        return False, dec, "xxtea", None, None, "unknown_magic_after_decrypt"

    return True, dec, "xxtea", ftype, ext, None


def main():
    parser = argparse.ArgumentParser(description="Decrypt Cocos2d-Lua publish directory.")
    parser.add_argument("--input", "-i", required=True, help="输入目录")
    parser.add_argument("--output", "-o", required=True, help="输出目录")
    parser.add_argument("--copy-plain", action="store_true", default=True, help="复制明文文件，默认开启")
    parser.add_argument("--no-copy-plain", dest="copy_plain", action="store_false", help="不复制明文文件")
    args = parser.parse_args()

    in_root = Path(args.input)
    out_root = Path(args.output)

    if not in_root.exists():
        raise FileNotFoundError(f"input directory does not exist: {in_root}")

    stats = {
        "total": 0,
        "plain": 0,
        "decrypted": 0,
        "failed": 0,
        "skipped_plain_not_copied": 0,
    }
    success = []
    failed = []

    print(f"[input]  {in_root}")
    print(f"[output] {out_root}")
    print(f"[lua] sign={LUA_SIGN!r}, key={LUA_KEY!r}")
    print("-" * 80)

    for root, _, files in os.walk(in_root):
        for filename in files:
            stats["total"] += 1
            in_path = Path(root) / filename
            rel_path = in_path.relative_to(in_root)
            out_path = out_root / rel_path

            try:
                data = rbin(str(in_path))
            except Exception as e:
                stats["failed"] += 1
                failed.append({"file": str(rel_path), "reason": f"read_error: {e}"})
                print(f"[read failed] {rel_path}: {e}")
                continue

            ok, dec, mode, ftype, ext, reason = decrypt_one(data)

            if ok and mode == "plain":
                stats["plain"] += 1
                if args.copy_plain:
                    final_path = output_path_with_ext(out_path, ext)
                    safe_write(final_path, dec)
                    success.append({"file": str(rel_path), "mode": "plain", "type": ftype, "output": str(final_path)})
                    print(f"[plain] {rel_path} -> {ftype}")
                else:
                    stats["skipped_plain_not_copied"] += 1
                continue

            if ok and mode == "xxtea":
                stats["decrypted"] += 1
                final_path = output_path_with_ext(out_path, ext)
                safe_write(final_path, dec)
                success.append({"file": str(rel_path), "mode": "xxtea", "type": ftype, "output": str(final_path)})
                print(f"[ok] {rel_path} -> {ftype}")
                continue

            stats["failed"] += 1
            failed.append({
                "file": str(rel_path),
                "reason": reason,
                "head_hex": data[:32].hex(),
                "size": len(data),
            })
            print(f"[failed] {rel_path}: {reason}")

    report = {
        "config": {
            "sign": LUA_SIGN.decode("ascii"),
            "key": LUA_KEY.decode("ascii"),
            "input": str(in_root),
            "output": str(out_root),
        },
        "stats": stats,
        "success": success,
        "failed": failed,
    }

    report_path = out_root / "_lua_decrypt_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 80)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"[report] {report_path}")


if __name__ == "__main__":
    main()
