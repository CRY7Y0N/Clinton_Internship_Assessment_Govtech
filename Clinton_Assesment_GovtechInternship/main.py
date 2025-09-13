#!/usr/bin/env python3
"""
Nginx Log Parser & User-Agent Enricher (+ Summary)
--------------------------------------------------
Reads Nginx access logs (default 'combined' format), parses each line into JSON,
enriches with browser/OS/device from the User-Agent, and writes a JSON array.
Optionally prints a summary report with --summary.

Usage:
    python3 main.py --input sample_access.log --output output.json --pretty --summary

Optional dependency (recommended):
    pip install user-agents
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, Optional, List
from collections import Counter

# Try to import user-agents (optional)
try:
    from user_agents import parse as ua_parse  # type: ignore
except Exception:
    ua_parse = None

# Nginx default 'combined' log format pattern:
# '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
# '"$http_referer" "$http_user_agent"'
COMBINED_REGEX = re.compile(
    r'(?P<remote_addr>\S+)\s+'
    r'(?P<identd>-)\s+'
    r'(?P<remote_user>\S+)\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes_sent>\S+)\s+'
    r'"(?P<http_referer>[^"]*)"\s+'
    r'"(?P<http_user_agent>[^"]*)"'
)

# Example: 10/Oct/2000:13:55:36 -0700
NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class UAInfo:
    browser: Dict[str, Optional[str]]
    os: Dict[str, Optional[str]]
    device: Dict[str, Optional[str] | Optional[bool]]

    @staticmethod
    def empty() -> "UAInfo":
        return UAInfo(
            browser={"family": None, "version": None},
            os={"family": None, "version": None},
            device={
                "family": None,
                "type": None,         # "Mobile" | "Tablet" | "PC" | "Bot" | "Other"
                "is_mobile": None,
                "is_tablet": None,
                "is_pc": None,
                "is_bot": None,
            },
        )


def parse_time_local(s: str) -> str:
    """Convert Nginx time_local string to ISO8601 (UTC). Return original on failure."""
    try:
        dt = datetime.strptime(s, NGINX_TIME_FMT)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return s


def parse_request(req: str) -> Dict[str, Optional[str]]:
    """Split 'METHOD path HTTP/x.y' into components (robust to missing parts)."""
    method, path, protocol = None, None, None
    if req:
        parts = req.split()
        if len(parts) >= 1:
            method = parts[0]
        if len(parts) >= 2:
            path = parts[1]
        if len(parts) >= 3:
            protocol = parts[2]
    return {"method": method, "path": path, "protocol": protocol}


def _guess_windows_version_from_ua_str(ua_lc: str) -> Optional[str]:
    """
    Best-effort mapping for Windows version from raw UA string when library is absent/outdated.
    Note: Windows 11 often still reports 'Windows NT 10.0' (ambiguous).
    """
    if "windows nt 6.1" in ua_lc:
        return "7"
    if "windows nt 6.2" in ua_lc:
        return "8"
    if "windows nt 6.3" in ua_lc:
        return "8.1"
    if "windows nt 10.0" in ua_lc:
        if "windows 11" in ua_lc:
            return "11"
        return "10"
    return None


def enrich_user_agent(ua_string: str) -> UAInfo:
    """Return browser/os/device info from UA string using user-agents if available."""
    info = UAInfo.empty()
    if not ua_string:
        return info

    # Preferred: user-agents
    if ua_parse is not None:
        ua = ua_parse(ua_string)

        info.browser["family"] = ua.browser.family or None
        info.browser["version"] = ua.browser.version_string or None

        info.os["family"] = ua.os.family or None
        info.os["version"] = ua.os.version_string or None  # "11", "10", "17.2", "14"

        info.device["family"] = ua.device.family or None
        info.device["is_mobile"] = bool(ua.is_mobile)
        info.device["is_tablet"] = bool(ua.is_tablet)
        info.device["is_pc"] = bool(ua.is_pc)
        info.device["is_bot"] = bool(ua.is_bot)

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
        info.device["type"] = dtype

        return info

    # Fallback heuristics (no dependency)
    ua_lc = ua_string.lower()

    # Browser family
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

    # OS family + version
    if "windows" in ua_lc:
        info.os["family"] = "Windows"
        info.os["version"] = _guess_windows_version_from_ua_str(ua_lc)
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

    # Device type
    if "bot" in ua_lc or "spider" in ua_lc or "crawler" in ua_lc:
        info.device["type"] = "Bot"
        info.device["is_bot"] = True
        info.device["is_mobile"] = False
        info.device["is_tablet"] = False
        info.device["is_pc"] = False
    elif "mobile" in ua_lc or "iphone" in ua_lc or ("android" in ua_lc and "mobile" in ua_lc):
        info.device["type"] = "Mobile"
        info.device["is_mobile"] = True
        info.device["is_tablet"] = False
        info.device["is_pc"] = False
        info.device["is_bot"] = False
        info.device["family"] = "iPhone" if "iphone" in ua_lc else None
    elif "ipad" in ua_lc or ("android" in ua_lc and "tablet" in ua_lc):
        info.device["type"] = "Tablet"
        info.device["is_tablet"] = True
        info.device["is_mobile"] = False
        info.device["is_pc"] = False
        info.device["is_bot"] = False
        info.device["family"] = "iPad" if "ipad" in ua_lc else None
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


def parse_line(line: str, line_number: int) -> Dict[str, Any]:
    """Parse one Nginx combined log line. Return a JSON-serializable dict."""
    m = COMBINED_REGEX.match(line.rstrip("\n"))
    if not m:
        return {
            "line_number": line_number,
            "raw": line.rstrip("\n"),
            "parse_ok": False,
            "error": "Line does not match Nginx combined format regex"
        }

    gd = m.groupdict()

    time_iso = parse_time_local(gd.get("time_local", ""))
    req_parts = parse_request(gd.get("request", ""))

    ua_info = enrich_user_agent(gd.get("http_user_agent", "") or "")

    result: Dict[str, Any] = {
        "line_number": line_number,
        "parse_ok": True,

        "remote_addr": gd.get("remote_addr"),
        "remote_user": None if gd.get("remote_user") == "-" else gd.get("remote_user"),
        "time_local": gd.get("time_local"),
        "time_iso_utc": time_iso,

        "request": gd.get("request"),
        "method": req_parts["method"],
        "path": req_parts["path"],
        "protocol": req_parts["protocol"],

        "status": int(gd.get("status", "0")),
        "body_bytes_sent": None if gd.get("body_bytes_sent") in (None, "-", "") else int(gd["body_bytes_sent"]),

        "http_referer": None if gd.get("http_referer") in (None, "-", "") else gd["http_referer"],
        "http_user_agent": gd.get("http_user_agent") or None,

        "ua": asdict(ua_info),
    }

    return result


def process_stream(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    for i, line in enumerate(lines, start=1):
        line = line.strip("\r\n")
        if not line:
            continue
        yield parse_line(line, i)


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

    # pretty OS key
    def fmt_os(k):
        fam, ver = k
        if fam is None and ver is None:
            return "Unknown"
        if ver:
            return f"{fam} {ver}"
        return str(fam)

    print("Summary:")
    print("---------")
    print(f"Total requests: {total}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"Top Browsers: {', '.join(_top(by_browser))}")
    print(f"Top OS: {', '.join([f'{fmt_os(k)} ({c})' for k, c in by_os.most_common(5)])}")
    print(f"Devices: {', '.join(_top(by_device))}")
    print(f"HTTP Statuses: {', '.join([f'{k} ({v})' for k, v in by_status.most_common()])}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse & enrich Nginx combined access logs.")
    ap.add_argument("--input", "-i", default="-", help="Input file path (default: '-' for stdin)")
    ap.add_argument("--output", "-o", default="-", help="Output file path (default: '-' for stdout)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--summary", action="store_true", help="Print a summary report after parsing")
    args = ap.parse_args()

    # Input
    if args.input == "-" or args.input.lower() == "stdin":
        in_fp = sys.stdin
        close_in = False
    else:
        in_fp = open(args.input, "r", encoding="utf-8", errors="replace")
        close_in = True

    try:
        records = list(process_stream(in_fp))
    finally:
        if close_in:
            in_fp.close()

    # Output JSON (if requested or default)
    out_text = json.dumps(records, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.output == "-" or args.output.lower() == "stdout":
        sys.stdout.write(out_text + ("\n" if not out_text.endswith("\n") else ""))
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_text)
            if not out_text.endswith("\n"):
                f.write("\n")

    # Summary report
    if args.summary:
        print_summary(records)


if __name__ == "__main__":
    main()
