#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CG 图片资源 XXTEA 解密脚本

已验证参数：
    sign = b"doboyugame"
    key  = b"23a95f71"

用法：
    python decrypt_images.py --input ./input --output ./output

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


CG_SIGN = b"doboyugame"
CG_KEY = b"23a95f71"


def detect_file_type(buf: bytes):
    """识别常见图片/纹理/压缩/文本类型。"""
    if not buf:
        return None, None

    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", ".png"

    if buf.startswith(b"\xff\xd8\xff"):
        return "jpg", ".jpg"

    if buf.startswith(b"RIFF") and len(buf) >= 12 and buf[8:12] == b"WEBP":
        return "webp", ".webp"

    if buf.startswith(b"PVR"):
        return "pvr", ".pvr"

    if buf.startswith(b"CCZ!"):
        return "ccz", ".ccz"

    if buf.startswith(b"\xabKTX 11\xbb\r\n\x1a\n"):
        return "ktx", ".ktx"

    if buf.startswith(b"\x13\xab\xa1\x5c"):
        return "astc", ".astc"

    if buf.startswith(b"PKM "):
        return "pkm", ".pkm"

    if buf.startswith(b"PK\x03\x04"):
        return "zip", ".zip"

    if buf.startswith(b"\x1f\x8b"):
        return "gzip", ".gz"

    head = buf[:256].lstrip()
    if head.startswith(b"{") or head.startswith(b"["):
        return "json_or_text", ".json"

    if head.startswith(b"<?xml") or head.startswith(b"<plist") or b"<plist" in head[:128]:
        return "plist_or_xml", ".plist"

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
        ".png", ".jpg", ".jpeg", ".webp", ".pvr", ".ccz",
        ".ktx", ".astc", ".pkm", ".zip", ".gz",
        ".plist", ".json", ".txt",
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

    if not data.startswith(CG_SIGN):
        return False, None, "skip", None, None, "missing_cg_sign"

    try:
        dec = xxtea(data, CG_SIGN, CG_KEY)
    except Exception as e:
        return False, None, "xxtea", None, None, f"decrypt_exception: {e}"

    if not dec:
        return False, None, "xxtea", None, None, "empty_decrypt_result"

    ftype, ext = detect_file_type(dec)
    if not ftype:
        return False, dec, "xxtea", None, None, "unknown_magic_after_decrypt"

    return True, dec, "xxtea", ftype, ext, None


def main():
    parser = argparse.ArgumentParser(description="Decrypt images/resources.")
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
    print(f"[cg] sign={CG_SIGN!r}, key={CG_KEY!r}")
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
                "head_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:32]),
                "head_hex": data[:32].hex(),
                "size": len(data),
            })
            print(f"[failed] {rel_path}: {reason}")

    report = {
        "config": {
            "sign": CG_SIGN.decode("ascii"),
            "key": CG_KEY.decode("ascii"),
            "key_note": "ASCII bytes, not hex bytes, no zero padding",
            "input": str(in_root),
            "output": str(out_root),
        },
        "stats": stats,
        "success": success,
        "failed": failed,
    }

    report_path = out_root / "_cg_decrypt_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 80)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"[report] {report_path}")


if __name__ == "__main__":
    main()
