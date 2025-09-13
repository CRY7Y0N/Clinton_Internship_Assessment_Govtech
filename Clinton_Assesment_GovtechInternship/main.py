#!/usr/bin/env python3
"""
Nginx Log Parser & User-Agent Enricher
--------------------------------------
Reads Nginx 'combined' access logs, turns each line into JSON, and enriches
with browser / OS / device info from the User-Agent. Optional summary and
error handling are built in.

Key flags:
  --pretty    Pretty-print JSON
  --summary   Print a small stats report
  --wrap      Wrap output array with {"metadata": ..., "entries": [...]}
  --errors    Write a simple error log (line number + reason)
  --strict    Exit with code 2 if any lines failed to parse

Examples:
  python main.py -i sample_access.log -o output.json --pretty
  python main.py -i sample_access.log -o output.json --pretty --summary --wrap
  type sample_access.log | python main.py -i - -o - --pretty  # stdin -> stdout

Tip:
  For better UA detection, install:
    pip install user-agents
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, Optional, List, Tuple
from collections import Counter

# Optional dependency: richer UA parsing if available
try:
    from user_agents import parse as ua_parse  # type: ignore
except Exception:
    ua_parse = None  # fallback to heuristics if not installed


# --- Nginx "combined" log regex ---
# Format:
#   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
#   "$http_referer" "$http_user_agent"
COMBINED_REGEX = re.compile(
    r'(?P<remote_addr>\S+)\s+'           # e.g. 203.0.113.10
    r'(?P<identd>-)\s+'                  # usually "-"
    r'(?P<remote_user>\S+)\s+'           # user or "-"
    r'\[(?P<time_local>[^\]]+)\]\s+'     # [12/Sep/2025:09:12:03 +0800]
    r'"(?P<request>[^"]*)"\s+'           # "GET /path HTTP/1.1"
    r'(?P<status>\d{3})\s+'              # 200
    r'(?P<body_bytes_sent>\S+)\s+'       # 1450
    r'"(?P<http_referer>[^"]*)"\s+'      # "https://example.com"
    r'"(?P<http_user_agent>[^"]*)"'      # "Mozilla/5.0 ..."
)

NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"  # e.g. 12/Sep/2025:09:12:03 +0800


# --- Small, tidy structure for UA output ---
@dataclass
class UAInfo:
    browser: Dict[str, Optional[str]]
    os: Dict[str, Optional[str]]
    device: Dict[str, Optional[str] | Optional[bool]]

    @staticmethod
    def empty() -> "UAInfo":
        """Default shape when UA is missing or unknown."""
        return UAInfo(
            browser={"family": None, "version": None},
            os={"family": None, "version": None},
            device={
                "family": None,   # e.g. "iPad", "iPhone" (when known)
                "type": None,     # "Mobile" | "Tablet" | "PC" | "Bot" | "Other"
                "is_mobile": None,
                "is_tablet": None,
                "is_pc": None,
                "is_bot": None,
            },
        )


# --- Helpers: time & request parsing ---
def parse_time_local(s: str) -> str:
    """Convert Nginx time_local to ISO8601 (UTC). If parsing fails, return original."""
    try:
        dt = datetime.strptime(s, NGINX_TIME_FMT)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return s


def parse_request(req: str) -> Dict[str, Optional[str]]:
    """Split 'METHOD path ... HTTP/x.y' robustly. Protocol = last token that starts with HTTP/."""
    method = path = protocol = None
    if req:
        parts = req.split()
        if parts:
            method = parts[0]
        if len(parts) >= 2:
            path = parts[1]  # keep it simple; we ignore middle tokens in 'request' field
        # protocol: prefer last token that looks like HTTP/??
        for tok in reversed(parts):
            if tok.upper().startswith("HTTP/"):
                protocol = tok
                break
    return {"method": method, "path": path, "protocol": protocol}


# --- UA enrichment (library first, then safe fallbacks) ---
def _guess_windows_version_from_ua(ua_lc: str) -> Optional[str]:
    # Many Win11 UAs still say "Windows NT 10.0". If it literally says "Windows 11", call it 11.
    if "windows nt 6.1" in ua_lc:
        return "7"
    if "windows nt 6.2" in ua_lc:
        return "8"
    if "windows nt 6.3" in ua_lc:
        return "8.1"
    if "windows nt 10.0" in ua_lc:
        return "11" if "windows 11" in ua_lc else "10"
    return None


def enrich_user_agent(ua_string: str) -> UAInfo:
    """Turn a UA string into {browser, os, device} details."""
    info = UAInfo.empty()
    if not ua_string:
        return info

    # Preferred: use user-agents if present
    if ua_parse is not None:
        ua = ua_parse(ua_string)

        info.browser["family"] = ua.browser.family or None
        info.browser["version"] = ua.browser.version_string or None

        info.os["family"] = ua.os.family or None
        info.os["version"] = ua.os.version_string or None

        info.device["family"] = ua.device.family or None
        info.device["is_mobile"] = bool(ua.is_mobile)
        info.device["is_tablet"] = bool(ua.is_tablet)
        info.device["is_pc"] = bool(ua.is_pc)
        info.device["is_bot"] = bool(ua.is_bot)


        # Decide type from library
        if ua.is_mobile:
            dtype = "Mobile"
        elif ua.is_tablet:
            dtype = "Tablet"
        elif ua.is_pc:
            dtype = "PC"
        elif ua.is_bot:
            dtype = "Bot"
        else:
            dtype = "Other"

        # --- OVERRIDE: if UA string clearly indicates a tablet, force Tablet ---
        ua_lc = ua_string.lower()
        looks_like_tablet = (
            ("tablet" in ua_lc) or
            ("ipad" in ua_lc) or
            (" sm-t" in ua_lc) or ("sm-t" in ua_lc)
        )
        if looks_like_tablet:
            dtype = "Tablet"
            info.device["is_tablet"] = True
            info.device["is_mobile"] = False
            if "ipad" in ua_lc:
                info.device["family"] = "iPad"

        info.device["type"] = dtype
        return info

    # Fallback heuristics (works without extra installs)
    ua_lc = ua_string.lower()

    # Browser family (basic)
    if "edg/" in ua_lc or " edge/" in ua_lc or " edg " in ua_lc:
        info.browser["family"] = "Edge"
    elif "opr/" in ua_lc or " opera" in ua_lc:
        info.browser["family"] = "Opera"
    elif "chrome/" in ua_lc and "edg" not in ua_lc and "opr" not in ua_lc:
        info.browser["family"] = "Chrome"
    elif "firefox/" in ua_lc:
        info.browser["family"] = "Firefox"
    elif "safari/" in ua_lc and "chrome" not in ua_lc:
        info.browser["family"] = "Safari"

    # OS family + version (best effort)
    if "windows" in ua_lc:
        info.os["family"] = "Windows"
        info.os["version"] = _guess_windows_version_from_ua(ua_lc)
    elif "mac os x" in ua_lc or "macintosh" in ua_lc:
        info.os["family"] = "macOS"
        m = re.search(r"mac os x ([0-9_\.]+)", ua_lc)
        if m:
            info.os["version"] = m.group(1).replace("_", ".")
    elif "android" in ua_lc:
        info.os["family"] = "Android"
        m = re.search(r"android ([0-9\.]+)", ua_lc)
        if m:
            info.os["version"] = m.group(1)
    elif "iphone" in ua_lc or "ipad" in ua_lc or "cpu iphone os" in ua_lc or "cpu os" in ua_lc:
        info.os["family"] = "iOS"
        m = re.search(r"iphone os ([0-9_]+)", ua_lc) or re.search(r"cpu (?:iphone )?os ([0-9_]+)", ua_lc)
        if m:
            info.os["version"] = m.group(1).replace("_", ".")
    elif "linux" in ua_lc:
        info.os["family"] = "Linux"

    # Device type (tablet before mobile to avoid mislabeling Android tablets)
    if any(k in ua_lc for k in ["bot", "spider", "crawler"]):
        info.device["type"] = "Bot"
        info.device["is_bot"] = True
        info.device["is_mobile"] = False
        info.device["is_tablet"] = False
        info.device["is_pc"] = False

    elif "ipad" in ua_lc or "tablet" in ua_lc or ("android" in ua_lc and "tablet" in ua_lc):
        info.device["type"] = "Tablet"
        info.device["is_tablet"] = True
        info.device["is_mobile"] = False
        info.device["is_pc"] = False
        info.device["is_bot"] = False
        info.device["family"] = "iPad" if "ipad" in ua_lc else None

    elif "mobile" in ua_lc or "iphone" in ua_lc or ("android" in ua_lc and "mobile" in ua_lc):
        info.device["type"] = "Mobile"
        info.device["is_mobile"] = True
        info.device["is_tablet"] = False
        info.device["is_pc"] = False
        info.device["is_bot"] = False
        info.device["family"] = "iPhone" if "iphone" in ua_lc else None

    elif "windows" in ua_lc or "mac os x" in ua_lc or "linux" in ua_lc:
        info.device["type"] = "PC"
        info.device["is_pc"] = True
        info.device["is_mobile"] = False
        info.device["is_tablet"] = False
        info.device["is_bot"] = False

    else:
        info.device["type"] = "Other"
        info.device["is_mobile"] = False
        info.device["is_tablet"] = False
        info.device["is_pc"] = False
        info.device["is_bot"] = False

    return info


# --- One-line parser ---
def parse_line(line: str, line_number: int) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Parse a single log line.
    Returns (record_dict, error_reason or None).
    """
    raw = line.rstrip("\r\n")
    if not raw:
        return ({"line_number": line_number, "parse_ok": False, "raw": ""}, "empty line")

    m = COMBINED_REGEX.match(raw)
    if not m:
        return (
            {
                "line_number": line_number,
                "raw": raw,
                "parse_ok": False,
                "error": "Line does not match Nginx combined format",
            },
            "regex_mismatch",
        )

    gd = m.groupdict()

    # Safe conversions
    try:
        status = int(gd.get("status", "0"))
    except Exception:
        status = 0

    bbs = gd.get("body_bytes_sent")
    try:
        body_bytes = int(bbs) if bbs and bbs.isdigit() else 0
    except Exception:
        body_bytes = 0

    req = parse_request(gd.get("request", "") or "")
    ua_info = enrich_user_agent(gd.get("http_user_agent", "") or "")

    record: Dict[str, Any] = {
        "line_number": line_number,
        "parse_ok": True,

        "remote_addr": gd.get("remote_addr"),
        "remote_user": None if gd.get("remote_user") == "-" else gd.get("remote_user"),

        "time_local": gd.get("time_local"),
        "time_iso_utc": parse_time_local(gd.get("time_local", "")),

        "request": gd.get("request"),
        "method": req["method"],
        "path": req["path"],
        "protocol": req["protocol"] ,

        "status": status,
        "body_bytes_sent": body_bytes,

        "http_referer": None if gd.get("http_referer") in (None, "-", "") else gd["http_referer"],
        "http_user_agent": gd.get("http_user_agent") or None,

        "ua": asdict(ua_info),
    }
    return (record, None)


def process_stream(lines: Iterable[str]) -> Tuple[List[Dict[str, Any]], List[Tuple[int, str]]]:
    """Parse many lines; collect records and (line, error_reason) for any failures."""
    records: List[Dict[str, Any]] = []
    errors: List[Tuple[int, str]] = []
    for i, line in enumerate(lines, start=1):
        rec, err = parse_line(line, i)
        records.append(rec)
        if err is not None or rec.get("parse_ok") is False:
            errors.append((i, err or rec.get("error", "unknown error")))
    return records, errors


# --- Small summary printout (handy for quick checks) ---
def _top(counter: Counter, k: int = 5) -> List[str]:
    return [f"{name} ({count})" for name, count in counter.most_common(k)]


def print_summary(records: List[Dict[str, Any]]) -> None:
    total = len(records)
    if total == 0:
        print("Summary:\n---------\nNo records parsed.")
        return

    unique_ips = {r.get("remote_addr") for r in records if r.get("remote_addr")}
    by_browser = Counter((r.get("ua") or {}).get("browser", {}).get("family") for r in records)
    by_os = Counter(((r.get("ua") or {}).get("os", {}).get("family"),
                     (r.get("ua") or {}).get("os", {}).get("version")) for r in records)
    by_device = Counter((r.get("ua") or {}).get("device", {}).get("type") for r in records)
    by_status = Counter(r.get("status") for r in records)

    def fmt_os(k: Tuple[Optional[str], Optional[str]]) -> str:
        fam, ver = k
        if fam is None and ver is None:
            return "Unknown"
        return f"{fam} {ver}" if ver else str(fam)

    print("Summary:")
    print("---------")
    print(f"Total requests: {total}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"Top Browsers: {', '.join(_top(by_browser))}")
    print(f"Top OS: {', '.join([f'{fmt_os(k)} ({c})' for k, c in by_os.most_common(5)])}")
    print(f"Devices: {', '.join(_top(by_device))}")
    print(f"HTTP Statuses: {', '.join([f'{k} ({v})' for k, v in by_status.most_common()])}")


# --- CLI entrypoint ---
def main() -> None:
    parser = argparse.ArgumentParser(description="Parse & enrich Nginx combined access logs.")
    parser.add_argument("-i", "--input", default="-", help="Input path or '-' for stdin")
    parser.add_argument("-o", "--output", default="-", help="Output path or '-' for stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--summary", action="store_true", help="Print a summary report")
    parser.add_argument("--wrap", action="store_true", help="Wrap array in an object with metadata + entries")
    parser.add_argument("--strict", action="store_true", help="Exit with code 2 if any parse errors occurred")
    parser.add_argument("--errors", help="Optional path to write error lines (lineno + reason)")
    args = parser.parse_args()

    start_ts = time.time()

    # Input source (file or stdin)
    if args.input == "-" or args.input.lower() == "stdin":
        in_fp = sys.stdin
        close_in = False
    else:
        try:
            in_fp = open(args.input, "r", encoding="utf-8", errors="replace")
            close_in = True
        except FileNotFoundError:
            print(f"Error: input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error opening input: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        records, errs = process_stream(in_fp)
    finally:
        if 'close_in' in locals() and close_in:
            in_fp.close()

    # Optional separate error log
    if args.errors and errs:
        try:
            with open(args.errors, "w", encoding="utf-8") as ef:
                for ln, reason in errs:
                    ef.write(f"{ln}\t{reason}\n")
        except Exception as e:
            print(f"Warning: failed to write errors file '{args.errors}': {e}", file=sys.stderr)

    # Build output (array by default; wrap when asked)
    duration_ms = int((time.time() - start_ts) * 1000)
    if args.wrap:
        payload: Any = {
            "metadata": {
                "source": args.input,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": duration_ms,
                "total_lines": len(records),
                "parse_errors": len(errs),
                "user_agent_parser": "user-agents" if ua_parse is not None else "heuristics",
            },
            "entries": records,
        }
    else:
        payload = records  # matches assessment: array of JSON objects

    out_text = json.dumps(payload, indent=2 if args.pretty else None, ensure_ascii=False)

    # Output destination (file or stdout)
    if args.output == "-" or args.output.lower() == "stdout":
        sys.stdout.write(out_text + ("\n" if not out_text.endswith("\n") else ""))
    else:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_text)
                if not out_text.endswith("\n"):
                    f.write("\n")
            print(f"Output written to {args.output}")
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            sys.exit(1)

    # Optional summary
    if args.summary:
        print_summary(records)

    # Optional strict mode
    if args.strict and errs:
        sys.exit(2)


if __name__ == "__main__":
    main()
