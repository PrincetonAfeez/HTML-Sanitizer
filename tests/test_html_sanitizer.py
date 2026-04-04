"""Tests for html_sanitizer core behavior and CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from html_sanitizer import main, run, sanitize_html, validate_url

ROOT = Path(__file__).resolve().parent.parent


def test_comment_removed_in_safe_mode() -> None:
    out, findings, _ = sanitize_html("<p>a</p><!-- evil -->", mode="safe")
    assert "<!--" not in out
    assert "evil" not in out
    assert "<p>a</p>" == out
    assert any(f.get("category") == "comment" for f in findings)


def test_ie_conditional_comment_removed() -> None:
    html_in = '<!--[if IE]><img src=x onerror=alert(1)><![endif]--><p>ok</p>'
    out, _, _ = sanitize_html(html_in, mode="safe")
    assert "alert" not in out
    assert "<p>ok</p>" == out


def test_script_stripped_and_finding() -> None:
    out, findings, _ = sanitize_html('<p>x</p><script>alert(1)</script>', mode="safe")
    assert "script" not in out.lower()
    assert any(f.get("category") == "script_tag" for f in findings)


def test_javascript_href_replaced() -> None:
    out, findings, _ = sanitize_html('<a href="javascript:alert(1)">x</a>', mode="safe")
    assert 'href="#removed"' in out or "#removed" in out
    assert any(f.get("category") == "dangerous_url" for f in findings)


def test_protocol_relative_href_blocked() -> None:
    safe, ok = validate_url("//evil.example/phish", "href")
    assert ok is False
    assert safe == "#removed"


def test_data_uri_blocked() -> None:
    safe, ok = validate_url("data:text/html,<b>x</b>", "href")
    assert ok is False


def test_event_handlers_logged_in_pass() -> None:
    out, findings, _ = sanitize_html('<p onclick="alert(1)">x</p>', mode="safe")
    assert "onclick" not in out
    ev = [f for f in findings if f.get("category") == "event_handler"]
    assert len(ev) >= 1


def test_plain_mode_strips_tags() -> None:
    out, _, _ = sanitize_html("<p>hello <b>w</b></p>", mode="plain")
    assert "<" not in out
    assert "hello" in out and "w" in out


def test_custom_allow_list() -> None:
    out, _, _ = sanitize_html("<div>a</div><p>b</p>", mode="safe", allowed_tags=["div"])
    assert "<div" in out
    assert "<p>" not in out


def test_run_report_shape() -> None:
    r = run("<script>x</script>", {"mode": "plain"})
    assert set(r) >= {"output", "findings", "stats", "summary", "warnings", "errors"}
    assert r["errors"] == []
    assert r["stats"]["mode"] == "plain"


def test_main_cli_plain_input(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--input", "<em>z</em>", "--mode", "plain"])
    assert code == 0
    captured = capsys.readouterr()
    assert "z" in captured.out
    assert "<em>" not in captured.out


def test_main_cli_report_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--input", '<img src="//x">', "--mode", "safe", "--report"])
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert "findings" in payload
    assert "stats" in payload


def test_cli_subprocess_show_diff() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "html_sanitizer.py"), "--input", "<p>hi</p>", "--show-diff"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "hi" in proc.stdout
    assert "Characters:" in proc.stderr


def test_cli_missing_file_exit_code() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "html_sanitizer.py"), "--file", str(ROOT / "nonexistent_file_12345.txt")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "Cannot read" in proc.stderr


def test_temp_file_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "in.html"
    dst = tmp_path / "out.txt"
    src.write_text("<b>x</b>", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "html_sanitizer.py"), "--file", str(src), "--output", str(dst), "--mode", "plain"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert dst.read_text(encoding="utf-8").strip() == "x"
