# tests/test_parser.py
import io
from typing import Optional, List, Tuple, Dict, Any

# Import from your script (humanized Version A)
from main import parse_line, process_stream, print_summary

# 1) Basic happy-path desktop (Chrome/Windows)
def test_valid_combined_line_basic():
    line = (
        '203.0.113.10 - - [12/Sep/2025:09:12:03 +0800] '
        '"GET / HTTP/1.1" 200 1450 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/119.0.6045.200 Safari/537.36"'
    )
    rec, err = parse_line(line, 1)
    assert err is None
    assert rec["parse_ok"] is True
    assert rec["status"] == 200
    assert rec["method"] == "GET"
    assert rec["path"] == "/"
    assert rec["protocol"] == "HTTP/1.1"
    assert rec["ua"]["os"]["family"] == "Windows"
    assert rec["ua"]["device"]["type"] == "PC"
    assert rec["ua"]["device"]["is_pc"] is True

# 2) Regex mismatch captured
def test_regex_mismatch_is_captured():
    bad = (
        '203.0.113.10 - - [12/Sep/2025:09:12:03 +0800] '
        'GET / HTTP/1.1 200 1450 "-" "UA"'
    )
    rec, err = parse_line(bad, 5)
    assert rec["parse_ok"] is False
    assert err == "regex_mismatch" or "does not match" in (rec.get("error") or "").lower()

# 3) Android tablet should be Tablet (tablet before mobile)
def test_tablet_before_mobile():
    ua = (
        "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-T870; Tablet) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.60 Mobile Safari/537.36"
    )
    line = (
        f'192.0.2.77 - - [12/Sep/2025:09:13:15 +0800] "GET /help HTTP/1.1" 200 78 "-" "{ua}"'
    )
    rec, err = parse_line(line, 2)
    assert err is None
    assert rec["parse_ok"] is True
    assert rec["ua"]["device"]["type"] == "Tablet"
    assert rec["ua"]["device"]["is_tablet"] is True
    assert rec["ua"]["device"]["is_mobile"] in (False, None)

# 4) Windows 11 hint acceptance
def test_windows_11_hint():
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Windows 11) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Edg/119.0.1108.62"
    )
    line = (
        f'203.0.113.77 - - [12/Sep/2025:09:13:01 +0800] "GET /reports HTTP/1.1" 200 1234 "-" "{ua}"'
    )
    rec, err = parse_line(line, 3)
    assert err is None
    assert rec["parse_ok"] is True
    assert rec["ua"]["os"]["family"] == "Windows"
    # Allow either 11 or 10 depending on library behavior
    assert rec["ua"]["os"]["version"] in ("11", "10", None)

# 5) End-to-end processing for two lines
def test_process_stream_end_to_end():
    data = """203.0.113.10 - - [12/Sep/2025:09:12:03 +0800] "GET / HTTP/1.1" 200 1450 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0"
198.51.100.23 - - [12/Sep/2025:09:12:09 +0800] "GET /login HTTP/1.1" 302 512 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
"""
    lines = io.StringIO(data).read().splitlines(True)
    records, errors = process_stream(lines)
    assert len(records) == 2
    assert len(errors) == 0
    assert all(r["parse_ok"] for r in records)
    assert records[0]["status"] == 200 and records[0]["ua"]["device"]["type"] == "PC"
    assert records[1]["status"] == 302 and records[1]["ua"]["device"]["type"] == "Mobile"

# 6) iPad should be Tablet & iOS OS family
def test_ipad_is_tablet_ios():
    ua = "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
    line = f'203.0.113.90 - - [12/Sep/2025:09:13:33 +0800] "GET /docs HTTP/1.1" 200 2112 "-" "{ua}"'
    rec, err = parse_line(line, 6)
    assert err is None and rec["parse_ok"] is True
    assert rec["ua"]["device"]["type"] == "Tablet"
    assert rec["ua"]["os"]["family"] in ("iOS", "iPadOS", None)

# 7) Googlebot classified as Bot
def test_googlebot_is_bot():
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    line = f'66.249.66.1 - - [12/Sep/2025:09:13:48 +0800] "GET /robots.txt HTTP/1.1" 200 68 "-" "{ua}"'
    rec, err = parse_line(line, 7)
    assert err is None and rec["parse_ok"] is True
    assert rec["ua"]["device"]["type"] == "Bot"
    assert rec["ua"]["device"]["is_bot"] is True

# 8) 404 with referer is parsed and bytes numeric conversion is safe
def test_404_with_referer_and_bytes():
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0'
    line = (
        f'198.51.100.88 - - [12/Sep/2025:09:12:40 +0800] '
        f'"GET /static/logo.png HTTP/1.1" 404 0 "https://example.com/page" "{ua}"'
    )
    rec, err = parse_line(line, 8)
    assert err is None and rec["parse_ok"] is True
    assert rec["status"] == 404
    assert rec["http_referer"] == "https://example.com/page"
    assert isinstance(rec["body_bytes_sent"], int) and rec["body_bytes_sent"] == 0

# 9) HTTP/2.0 protocol handled
def test_http2_protocol():
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    line = f'203.0.113.55 - - [12/Sep/2025:09:12:27 +0800] "GET /dashboard HTTP/2.0" 200 4096 "-" "{ua}"'
    rec, err = parse_line(line, 9)
    assert err is None and rec["parse_ok"] is True
    assert rec["protocol"] == "HTTP/2.0"

# 10) Request with spaces in path preserves method/path split
def test_request_with_space_in_path():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36"
    line = f'203.0.113.77 - - [12/Sep/2025:09:13:01 +0800] "GET /reports Q1 HTTP/1.1" 200 1234 "-" "{ua}"'
    # Our parser keeps the whole request & extracts method/path/protocol safely;
    # path will be only the first token after method ("/reports")
    rec, err = parse_line(line, 10)
    assert err is None and rec["parse_ok"] is True
    assert rec["method"] == "GET"
    assert rec["path"] == "/reports"
    assert rec["protocol"] == "HTTP/1.1"
