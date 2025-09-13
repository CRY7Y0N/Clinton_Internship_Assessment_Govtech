#!/usr/bin/env python3
"""
Nginx Log Parser & User-Agent Enricher
--------------------------------------
Reads Nginx access logs (default 'combined' format), parses each line into JSON,
enriches with browser/OS/device from the User-Agent, and writes a JSON array.

Usage:
    python3 main.py --input sample_access.log --output output.json
    # or read from stdin / write to stdout
    cat sample_access.log | python3 main.py > output.json

Optional dependency (recommended):
    pip install user-agents

Notes:
- If 'user-agents' is installed, enrichment will be detailed and accurate.
- Without it, a lightweight heuristic fallback is used.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, Optional

# Try to import user-agents (optional)
try:
    from user_agents import parse as ua_parse  # type: ignore
except Exception:
    ua_parse = None

# Nginx default 'combined' log format pattern:
# '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
# '"$http_referer" "$http_user_agent"'
COMBINED_REGEX = re.compile(
    r'(?P<remote_addr>\S+)\s+'           # remote_addr
    r'(?P<identd>-)\s+'                  # identd (usually '-')
    r'(?P<remote_user>\S+)\s+'           # remote_user or '-'
    r'\[(?P<time_local>[^\]]+)\]\s+'     # [time_local]
    r'"(?P<request>[^"]*)"\s+'           # "METHOD path HTTP/x.y"
    r'(?P<status>\d{3})\s+'              # status
    r'(?P<body_bytes_sent>\S+)\s+'       # bytes
    r'"(?P<http_referer>[^"]*)"\s+'      # "referer"
    r'"(?P<http_user_agent>[^"]*)"'      # "user-agent"
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
                "type": None,         # "Mobile" | "Tablet" | "PC" | "Other"
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


def enrich_user_agent(ua_string: str) -> UAInfo:
    """Return browser/os/device info from UA string using user-agents if available."""
    info = UAInfo.empty()
    if not ua_string:
        return info

    # Heuristic fallback (when user-agents isn't installed)
    if ua_parse is None:
        ua = ua_string.lower()

        # Browser family
        if "chrome" in ua and "edg" not in ua:
            info.browser["family"] = "Chrome"
        elif "safari" in ua and "chrome" not in ua:
            info.browser["family"] = "Safari"
        elif "firefox" in ua:
            info.browser["family"] = "Firefox"
        elif "edg" in ua:
            info.browser["family"] = "Edge"
        elif "opera" in ua or "opr" in ua:
            info.browser["family"] = "Opera"

        # OS family
        if "windows" in ua:
            info.os["family"] = "Windows"
        elif "mac os x" in ua or "macintosh" in ua:
            info.os["family"] = "macOS"
        elif "android" in ua:
            info.os["family"] = "Android"
        elif "linux" in ua:
            info.os["family"] = "Linux"
        elif "iphone" in ua or "ipad" in ua or "ios" in ua:
            info.os["family"] = "iOS"

        # Device (very rough)
        if "mobile" in ua or "iphone" in ua or ("android" in ua and "mobile" in ua):
            info.device["type"] = "Mobile"
        elif "ipad" in ua or ("android" in ua and "tablet" in ua):
            info.device["type"] = "Tablet"
        elif "windows" in ua or "mac os x" in ua or "linux" in ua:
            info.device["type"] = "PC"
        else:
            info.device["type"] = "Other"

        # Flags unknown in fallback
        return info

    # Full enrichment with user-agents
    ua = ua_parse(ua_string)

    # Browser
    info.browser["family"] = ua.browser.family or None
    info.browser["version"] = ua.browser.version_string or None

    # OS
    info.os["family"] = ua.os.family or None
    info.os["version"] = ua.os.version_string or None

    # Device
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

    # Normalized fields
    time_iso = parse_time_local(gd.get("time_local", ""))
    req_parts = parse_request(gd.get("request", ""))

    # UA enrichment
    ua_info = enrich_user_agent(gd.get("http_user_agent", "") or "")

    # Build result
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


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse & enrich Nginx combined access logs.")
    ap.add_argument("--input", "-i", default="-",
                    help="Input file path (default: '-' for stdin)")
    ap.add_argument("--output", "-o", default="-",
                    help="Output file path (default: '-' for stdout)")
    ap.add_argument("--pretty", action="store_true",
                    help="Pretty-print JSON")
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

    # Output
    out_text = json.dumps(records, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.output == "-" or args.output.lower() == "stdout":
        sys.stdout.write(out_text + ("\n" if not out_text.endswith("\n") else ""))
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_text)
            if not out_text.endswith("\n"):
                f.write("\n")


if __name__ == "__main__":
    main()
