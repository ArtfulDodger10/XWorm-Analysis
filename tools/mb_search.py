#!/usr/bin/env python3
"""
Find likely-unpacked XWorm payloads on MalwareBazaar and optionally download them.

Most files tagged XWorm are loaders. The payload is a small .NET file, so this keeps
exe files under a size limit whose imphash is the standard .NET one
(f34d5f2d4577ed6d9ceec516c1f5a744, mscoree!_CorExeMain only).

The abuse.ch key is read from the ABUSE_CH_KEY environment variable.

    python mb_search.py -o candidates.csv
    python mb_search.py --spread --count 10 --skip-dir C:\\samples --download C:\\samples\\new

Downloads are MalwareBazaar's encrypted ZIPs (password: infected). Run them in a VM.

Nader Ayman (Artful Dodger) - MIT License
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

API = "https://mb-api.abuse.ch/api/v1/"
DOTNET_IMPHASH = "f34d5f2d4577ed6d9ceec516c1f5a744"
SHA256_RE = re.compile(r"[0-9a-f]{64}", re.I)


def api_call(key: str, params: dict, timeout: int = 60, retries: int = 3) -> bytes:
    req = urllib.request.Request(
        API,
        data=urllib.parse.urlencode(params).encode(),
        headers={"Auth-Key": key, "User-Agent": "xworm-analysis/mb_search"},
    )
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            client_error = isinstance(e, urllib.error.HTTPError) and e.code < 500
            if client_error or attempt == retries:
                raise
            print(f"  {params.get('query')}: {e}, retrying in {5 * attempt}s", file=sys.stderr)
            time.sleep(5 * attempt)
    raise RuntimeError("unreachable")


def query(key: str, params: dict) -> list[dict]:
    reply = json.loads(api_call(key, params))
    status = reply.get("query_status")
    if status == "ok":
        return reply["data"]
    if status in ("no_results", "tag_not_found", "signature_not_found"):
        return []
    raise RuntimeError(f"{params.get('query')} returned {status!r}")


def collect(key: str, signature: str, tag: Optional[str], limit: int) -> list[dict]:
    pool = query(key, {"query": "get_siginfo", "signature": signature, "limit": limit})
    if tag:
        try:
            pool += query(key, {"query": "get_taginfo", "tag": tag, "limit": limit})
        except Exception as e:
            print(f"warning: tag search failed ({e}), using signature results only", file=sys.stderr)
    unique: dict[str, dict] = {}
    for s in pool:
        unique.setdefault(s["sha256_hash"].lower(), s)
    return list(unique.values())


def known_hashes(dirs: list[str]) -> set[str]:
    found: set[str] = set()
    for d in dirs:
        if not os.path.isdir(d):
            print(f"warning: {d} not found", file=sys.stderr)
            continue
        for _, _, files in os.walk(d):
            for name in files:
                found.update(h.lower() for h in SHA256_RE.findall(name))
    return found


def filter_candidates(samples: list[dict], max_size: int, dotnet_only: bool, skip: set[str]) -> list[dict]:
    hits = [
        s for s in samples
        if s.get("file_type") == "exe"
        and int(s.get("file_size") or 0) <= max_size
        and (not dotnet_only or (s.get("imphash") or "").lower() == DOTNET_IMPHASH)
        and s["sha256_hash"].lower() not in skip
    ]
    hits.sort(key=lambda s: s.get("first_seen") or "", reverse=True)
    return hits


def pick(hits: list[dict], count: int, spread: bool) -> list[dict]:
    """The newest `count`, or `count` spaced evenly over the date range."""
    if not spread or len(hits) <= count:
        return hits[:count]
    step = (len(hits) - 1) / (count - 1) if count > 1 else 0
    return [hits[round(i * step)] for i in range(count)]


def download(key: str, sha256: str, out_dir: str) -> str:
    data = api_call(key, {"query": "get_file", "sha256_hash": sha256}, timeout=120)
    if data[:2] != b"PK":
        raise RuntimeError(data[:200].decode(errors="replace"))
    path = os.path.join(out_dir, f"{sha256}.zip")
    with open(path, "wb") as f:
        f.write(data)
    return path


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Find likely-unpacked XWorm payloads on MalwareBazaar")
    p.add_argument("--signature", default="XWorm")
    p.add_argument("--tag", default="xworm", help="also search this tag, '' to disable")
    p.add_argument("--max-size", type=int, default=120_000, help="bytes (default 120000)")
    p.add_argument("--limit", type=int, default=1000, help="results per query, max 1000")
    p.add_argument("--any-type", action="store_true", help="don't filter on the .NET imphash")
    p.add_argument("--skip-dir", action="append", default=[], help="skip hashes already in this folder")
    p.add_argument("-o", "--output", help="save all candidates to CSV")
    p.add_argument("--download", metavar="DIR", help="download the picked samples here")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--spread", action="store_true", help="pick across the date range, not just the newest")
    args = p.parse_args(argv)

    key = os.environ.get("ABUSE_CH_KEY")
    if not key:
        print('set your key first: $env:ABUSE_CH_KEY="..." (PowerShell) or set ABUSE_CH_KEY=... (cmd)',
              file=sys.stderr)
        return 2

    try:
        samples = collect(key, args.signature, args.tag or None, min(args.limit, 1000))
    except Exception as e:
        print(f"search failed: {e}", file=sys.stderr)
        return 1

    skip = known_hashes(args.skip_dir)
    hits = filter_candidates(samples, args.max_size, not args.any_type, skip)
    chosen = pick(hits, args.count, args.spread)

    print(f"{len(samples)} samples checked, {len(skip)} already on disk, "
          f"{len(hits)} candidates <= {args.max_size} bytes, showing {len(chosen)}\n")
    for s in chosen:
        print(f"{s['sha256_hash']}  {int(s['file_size']):>8}  {s.get('first_seen')}  "
              f"{','.join(s.get('tags') or [])}")

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["sha256", "file_size", "first_seen", "imphash", "file_name", "tags"])
            for s in hits:
                w.writerow([s["sha256_hash"], s["file_size"], s.get("first_seen"), s.get("imphash"),
                            s.get("file_name"), ";".join(s.get("tags") or [])])
        print(f"\n{len(hits)} candidates saved to {args.output}")

    if args.download:
        os.makedirs(args.download, exist_ok=True)
        for s in chosen:
            try:
                print(f"downloaded {download(key, s['sha256_hash'], args.download)}")
            except Exception as e:
                print(f"failed {s['sha256_hash']}: {e}", file=sys.stderr)
            time.sleep(1)
        print("\nZIP password: infected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
