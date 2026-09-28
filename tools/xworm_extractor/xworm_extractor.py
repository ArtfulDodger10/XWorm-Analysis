#!/usr/bin/env python3
"""
Static config extractor for XWorm .NET payloads. The sample is parsed, never executed.

XWorm encrypts each setting with AES-256-ECB. The key is derived from the mutex:

    digest     = MD5(mutex)
    key[0:16]  = digest
    key[15:31] = digest     # key[15] becomes digest[0], key[31] stays 0

Field names are usually obfuscated, so the mutex is found by trying every string
in the #US heap as the key and keeping the one that decrypts the most settings.

Nader Ayman (Artful Dodger) - https://artfuldodger10.github.io - MIT License
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import struct
import sys
from typing import Iterable, Optional

import pefile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__version__ = "1.1.0"

log = logging.getLogger("xworm_extractor")

MAX_FILE_SIZE = 50 * 1024 * 1024
CLR_DIRECTORY = 14
METADATA_MAGIC = 0x424A5342  # "BSJB"
MIN_DECRYPTED = 2            # host and port at least

B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^https?://\S+$", re.I)
TELEGRAM_TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")
TELEGRAM_CHAT_RE = re.compile(r"^-?\d{5,15}$")
VERSION_RE = re.compile(r"XWorm\s*V?(\d+(?:\.\d+)+)", re.I)

BASE58 = "[1-9A-HJ-NP-Za-km-z]"
WALLET_RES = {
    "btc": re.compile(rf"^(?:bc1[a-z0-9]{{25,62}}|[13]{BASE58}{{25,34}})$"),
    "eth": re.compile(r"^0x[a-fA-F0-9]{40}$"),
    "trx": re.compile(rf"^T{BASE58}{{33}}$"),
    "ltc": re.compile(rf"^(?:ltc1[a-z0-9]{{25,62}}|[LM]{BASE58}{{26,33}})$"),
}


class NotDotNetError(Exception):
    pass


class NoUserStringsError(Exception):
    pass


def _compressed_length(data: bytes, pos: int) -> tuple[int, int]:
    """ECMA-335 II.23.2 compressed integer. Returns (value, bytes used)."""
    b0 = data[pos]
    if b0 & 0x80 == 0:
        return b0, 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | data[pos + 1], 2
    if b0 & 0xE0 == 0xC0:
        return ((b0 & 0x1F) << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3], 4
    raise ValueError(f"bad compressed length 0x{b0:02x} at {pos}")


def parse_us_heap(heap: bytes) -> list[str]:
    strings: list[str] = []
    pos = 1
    while pos < len(heap):
        try:
            length, used = _compressed_length(heap, pos)
        except (ValueError, IndexError):
            break
        pos += used
        if length == 0:
            continue
        blob = heap[pos:pos + length]
        pos += length
        # UTF-16LE text followed by a one-byte flag
        text = blob[:length - 1] if length % 2 else blob
        strings.append(text.decode("utf-16-le", errors="replace"))
    return strings


def get_metadata_streams(pe: pefile.PE) -> dict[str, bytes]:
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= CLR_DIRECTORY:
        raise NotDotNetError("no CLR data directory")
    clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[CLR_DIRECTORY]
    if clr_dir.VirtualAddress == 0 or clr_dir.Size == 0:
        raise NotDotNetError("no CLR header (not a .NET assembly)")

    md_rva, md_size = struct.unpack_from("<II", pe.get_data(clr_dir.VirtualAddress, 16), 8)
    md = pe.get_data(md_rva, md_size)
    if struct.unpack_from("<I", md, 0)[0] != METADATA_MAGIC:
        raise NotDotNetError("bad metadata signature")

    pos = 16 + struct.unpack_from("<I", md, 12)[0]
    count = struct.unpack_from("<H", md, pos + 2)[0]
    pos += 4

    streams: dict[str, bytes] = {}
    for _ in range(count):
        offset, size = struct.unpack_from("<II", md, pos)
        pos += 8
        end = md.index(b"\x00", pos)
        name = md[pos:end].decode("ascii", errors="replace")
        pos = (end + 4) & ~3
        streams[name] = md[offset:offset + size]
    return streams


def read_user_strings(path: str) -> list[str]:
    pe = pefile.PE(path, fast_load=True)
    try:
        streams = get_metadata_streams(pe)
    finally:
        pe.close()
    names = ", ".join(streams)
    if "#US" not in streams:
        raise NoUserStringsError(f"no #US heap (streams: {names}), metadata modified by an obfuscator")
    strings = parse_us_heap(streams["#US"])
    if not any(s.strip() for s in strings):
        raise NoUserStringsError(f"empty #US heap (streams: {names}), strings are stored elsewhere")
    return strings


def derive_key(mutex: str) -> bytes:
    digest = hashlib.md5(mutex.encode("utf-8")).digest()
    key = bytearray(32)
    key[0:16] = digest
    key[15:31] = digest
    return bytes(key)


def _pkcs7_unpad(data: bytes) -> Optional[bytes]:
    if not data:
        return None
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        return None
    return data[:-pad]


def decode_ciphertext(value: str) -> Optional[bytes]:
    if len(value) < 24 or len(value) % 4 or not B64_RE.match(value):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        return None
    return raw if len(raw) % 16 == 0 else None


def decrypt(raw: bytes, key: bytes) -> Optional[str]:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plain = _pkcs7_unpad(dec.update(raw) + dec.finalize())
    if plain is None:
        return None
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or not all(c.isprintable() or c in "\r\n\t" for c in text):
        return None
    return text


def find_key(strings: list[str]) -> Optional[tuple[str, bytes, dict[int, str]]]:
    """Returns (mutex, key, {heap index: plaintext}) for the best candidate, or None."""
    ciphertexts = {i: raw for i, s in enumerate(strings) if (raw := decode_ciphertext(s)) is not None}
    if len(ciphertexts) < MIN_DECRYPTED:
        return None

    best = None
    tried: set[str] = set()
    for candidate in strings:
        if candidate in tried or not 1 <= len(candidate) <= 128:
            continue
        tried.add(candidate)
        key = derive_key(candidate)
        plain = {i: p for i, raw in ciphertexts.items() if (p := decrypt(raw, key)) is not None}
        if len(plain) >= MIN_DECRYPTED and (best is None or len(plain) > len(best[2])):
            best = (candidate, key, plain)
    return best


def _is_host(value: str) -> bool:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return bool(parts) and all(IPV4_RE.match(p) or DOMAIN_RE.match(p) or URL_RE.match(p) for p in parts)


def _is_port(value: str) -> bool:
    return value.isdigit() and 0 < int(value) < 65536


def label_config(values: list[str]) -> tuple[dict, list[str]]:
    """Map decrypted values to settings by their format.

    Ties are broken by XWorm's field order: Hosts, Port, KEY, SPL, Group, USBNM,
    InstallDir, InstallStr.
    """
    config: dict = {}
    unlabeled: list[str] = []
    brackets: list[str] = []
    exes: list[str] = []

    for raw in values:
        v = raw.strip()
        if not v:
            continue
        wallet = next((coin for coin, rx in WALLET_RES.items() if rx.match(v)), None)
        if wallet:
            config.setdefault("clipper_wallets", {}).setdefault(wallet, []).append(v)
        elif "hosts" not in config and _is_host(v):
            config["hosts"] = [p.strip() for p in v.split(",") if p.strip()]
        elif "port" not in config and _is_port(v):
            config["port"] = int(v)
        elif TELEGRAM_TOKEN_RE.match(v):
            config["telegram_token"] = v
        elif "telegram_chat_id" not in config and TELEGRAM_CHAT_RE.match(v):
            config["telegram_chat_id"] = v
        elif v.startswith("<") and v.endswith(">"):
            brackets.append(v)
        elif "install_dir" not in config and v.startswith("%"):
            config["install_dir"] = v
        elif v.lower().endswith(".exe") and "\\" not in v and "/" not in v:
            exes.append(v)
        elif "group" not in config and VERSION_RE.search(v):
            config["group"] = v
        else:
            unlabeled.append(v)

    if brackets:
        config["aes_key"] = brackets[0]
    if len(brackets) > 1:
        config["splitter"] = brackets[1]
    unlabeled.extend(brackets[2:])

    usb = [e for e in exes if "usb" in e.lower()]
    rest = [e for e in exes if e not in usb]
    if usb:
        config["usb_name"] = usb[0]
    elif rest:
        config["usb_name"] = rest.pop(0)
    if rest:
        config["install_name"] = rest.pop(0)
    unlabeled.extend(usb[1:] + rest)

    # a renamed group has no fixed format, so take the first value left over
    if "group" not in config and unlabeled:
        config["group"] = unlabeled.pop(0)

    return config, unlabeled


def detect_version(strings: Iterable[str]) -> Optional[str]:
    for s in strings:
        m = VERSION_RE.search(s)
        if m:
            return m.group(1)
    return None


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract(path: str) -> dict:
    result: dict = {
        "file": os.path.basename(path),
        "sha256": None,
        "status": "error",
        "family": "XWorm",
        "extractor_version": __version__,
    }
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            result["error"] = f"larger than {MAX_FILE_SIZE} bytes, skipped"
            return result
        result["sha256"] = sha256_file(path)
        strings = read_user_strings(path)
    except NotDotNetError as e:
        result.update(status="not_dotnet", error=str(e))
        return result
    except NoUserStringsError as e:
        result.update(status="dotnet_no_strings", error=str(e))
        return result
    except pefile.PEFormatError as e:
        result.update(status="not_pe", error=str(e))
        return result
    except (OSError, ValueError, struct.error) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    found = find_key(strings)
    if found is None:
        result.update(status="no_config", error="no string decrypts the settings (packed, obfuscated or not XWorm)")
        return result

    mutex, key, decrypted = found
    values = [decrypted[i] for i in sorted(decrypted)]
    config, unlabeled = label_config(values)
    config["mutex"] = mutex
    if "aes_key" in config:
        # C2 traffic uses AES-ECB keyed with MD5(KEY)
        config["c2_traffic_key_md5"] = hashlib.md5(config["aes_key"].encode("utf-8")).hexdigest()

    hosts = config.get("hosts", [])
    result.update({
        "status": "ok",
        "version": detect_version(strings + values),
        "c2": [f"{h}:{config['port']}" for h in hosts] if "port" in config else hosts,
        "config": config,
        "config_aes_key_hex": key.hex(),
        "decrypted_values": values,
        "unlabeled_values": unlabeled,
    })
    return result


def iter_files(paths: list[str], recursive: bool) -> Iterable[str]:
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p) and recursive:
            for root, _, files in os.walk(p):
                for name in sorted(files):
                    yield os.path.join(root, name)
        elif os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full):
                    yield full
        else:
            log.warning("not found: %s", p)


def dump_strings(paths: list[str], recursive: bool) -> None:
    for path in iter_files(paths, recursive):
        try:
            strings = read_user_strings(path)
        except (NotDotNetError, NoUserStringsError, pefile.PEFormatError, OSError, ValueError,
                struct.error) as e:
            print(f"# {path}: {type(e).__name__}: {e}")
            continue
        print(f"# {path}: {len(strings)} strings")
        for i, s in enumerate(strings):
            print(f"{i}\t{s!r}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static XWorm config extractor. Never executes the sample.")
    parser.add_argument("paths", nargs="+", help="files and/or directories")
    parser.add_argument("-r", "--recursive", action="store_true", help="walk directories recursively")
    parser.add_argument("-o", "--output", help="write results as JSON Lines")
    parser.add_argument("--only-ok", action="store_true", help="only print successful extractions")
    parser.add_argument("--dump-strings", action="store_true", help="print the #US strings and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")

    if args.dump_strings:
        dump_strings(args.paths, args.recursive)
        return 0

    out = open(args.output, "w", encoding="utf-8") if args.output else None
    summary: dict[str, int] = {}
    try:
        for path in iter_files(args.paths, args.recursive):
            res = extract(path)
            summary[res["status"]] = summary.get(res["status"], 0) + 1
            if args.only_ok and res["status"] != "ok":
                log.info("%s: %s", path, res["status"])
            elif out:
                out.write(json.dumps(res) + "\n")
            else:
                print(json.dumps(res, indent=2))
    finally:
        if out:
            out.close()

    if sum(summary.values()) > 1:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(summary.items()))
        print(f"\n{sum(summary.values())} files: {counts}", file=sys.stderr)
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
