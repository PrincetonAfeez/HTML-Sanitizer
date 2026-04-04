# Build an HTML Sanitizer in Python

This tutorial walks Python students through building a small HTML sanitizer like the one in the `HTML-Sanitizer` project.

## What you are building

You will build a command-line Python app that can:

- remove dangerous HTML like `<script>` and `<style>`
- remove inline event handlers like `onclick`
- validate `href` and `src` values
- offer two output modes:
  - `plain`: return text only
  - `safe`: keep a small allowlist of safe tags
- generate a structured report of what was removed
- include automated tests with `pytest`

## Important warning

This project is excellent for learning about Python strings, regular expressions, command-line tools, and test-driven development.

It is **not** a production-grade HTML sanitizer. Browsers parse HTML with real parsers, not regex. For hostile input in real web apps, use a parser-backed sanitizer and add other defenses like output encoding and CSP.

---

## Step 1: Set up the project folder

Create a new folder and open it in your editor.

```bash
mkdir HTML-Sanitizer
cd HTML-Sanitizer
mkdir tests
```

Create these files:

```text
HTML-Sanitizer/
├── html_sanitizer.py
├── errors.py
├── requirements.txt
└── tests/
    └── test_html_sanitizer.py
```

---

## Step 2: Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

### macOS / Linux

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

Install test dependencies:

```bash
pip install -r requirements.txt
```

---

## Step 3: Add a tiny error module

Create `errors.py`:

```python
"""Shared DataGuard exceptions."""


class DataGuardError(Exception):
    """Base exception for friendly CLI failures."""


class InputError(DataGuardError):
    """Raised when input cannot be read or decoded."""


class ParseError(DataGuardError):
    """Raised when data cannot be parsed."""


class ValidationError(DataGuardError):
    """Raised when validation fails in a non-fatal way."""
```

### Why this file matters

It keeps your program cleaner. Instead of raising generic exceptions everywhere, you define errors that match your app.

---

## Step 4: Start the main sanitizer file

At the top of `html_sanitizer.py`, import the tools you need:

```python
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

from errors import InputError
```

### Why these imports?

- `argparse`: builds the CLI
- `html`: decodes and escapes HTML entities
- `json`: prints structured reports
- `re`: powers regex matching
- `sys`: writes to stdout and stderr
- `Path`: reads and writes files cleanly

---

## Step 5: Define your regex patterns

Add the core patterns:

```python
COMMENT_PATTERN = re.compile(
    r"(?:<!--\[if[\s\S]*?<!\[endif\]-->|<!--[\s\S]*?-->)",
    re.IGNORECASE | re.DOTALL,
)

SCRIPT_PATTERN = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL)
STYLE_PATTERN = re.compile(r"<style\b[^>]*>.*?</style\s*>", re.IGNORECASE | re.DOTALL)

BLOCKED_TAGS_PATTERN = re.compile(
    r"<(?:iframe|object|embed|applet|form|base)\b[^>]*>.*?</(?:iframe|object|embed|applet|form|base)\s*>|<(?:iframe|object|embed|applet|form|base)\b[^>]*/?>",
    re.IGNORECASE | re.DOTALL,
)

META_REFRESH_PATTERN = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>",
    re.IGNORECASE,
)

EVENT_HANDLER_PATTERN = re.compile(
    r"\s+on[a-z0-9_-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`|[^\s>]+)",
    re.IGNORECASE,
)

STYLE_DANGER_PATTERN = re.compile(
    r"expression\s*\(|url\s*\(\s*javascript:|url\s*\(\s*['\"]?data:|-moz-binding|behavior\s*:",
    re.IGNORECASE,
)

TAG_PATTERN = re.compile(
    r"<(?P<closing>/)?(?P<tag>[A-Za-z0-9]+)(?P<attrs>[^>]*)>",
    re.IGNORECASE | re.DOTALL,
)

ATTRIBUTE_PATTERN = re.compile(
    r"([^\s=<>'\"`/]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`|([^\s>]+)))?",
    re.DOTALL,
)
```

### What students should learn here

Each regex is solving one narrow problem. This is easier to debug than trying to build one giant pattern.

---

## Step 6: Create the allowlist

Add a small set of allowed tags and attributes:

```python
DEFAULT_SAFE_TAGS = {
    "p": [],
    "b": [],
    "i": [],
    "u": [],
    "strong": [],
    "em": [],
    "br": [],
    "hr": [],
    "ul": [],
    "ol": [],
    "li": [],
    "h1": [],
    "h2": [],
    "h3": [],
    "h4": [],
    "h5": [],
    "h6": [],
    "blockquote": [],
    "pre": [],
    "code": [],
    "a": ["href"],
    "img": ["src", "alt"],
}

SELF_CLOSING_TAGS = {"br", "hr", "img"}
```

### Why an allowlist is useful

A blocklist says “remove known bad things.”
An allowlist says “keep only these approved things.”

For security work, allowlists are usually safer.

---

## Step 7: Build helper functions for findings

You want your app to explain what it removed.

```python
def line_number_for_position(text: str, position: int) -> int:
    return text.count("\n", 0, max(position, 0)) + 1


def add_finding(findings: list[dict], text: str, position: int, category: str, severity: str, message: str) -> None:
    findings.append(
        {
            "severity": severity,
            "category": category,
            "line": line_number_for_position(text, position),
            "message": message,
        }
    )
```

### Why this matters

Students often stop at “it works.” A better tool also explains what happened.

---

## Step 8: Write a reusable replacement helper

Instead of repeating the same substitution logic over and over, create one reusable function:

```python
def replace_pattern(
    text: str,
    pattern: re.Pattern,
    replacement: str,
    findings: list[dict],
    category: str,
    severity: str,
    message_template: str,
) -> str:
    def replacement_function(match: re.Match) -> str:
        add_finding(
            findings,
            text,
            match.start(),
            category,
            severity,
            message_template.format(content=match.group(0)[:80]),
        )
        return replacement

    return pattern.sub(replacement_function, text)
```

### Why this is good design

It reduces duplication and makes later maintenance easier.

---

## Step 9: Validate URLs carefully

A sanitizer should not keep dangerous links.

```python
def validate_url(raw_value: str, attribute_name: str) -> tuple[str, bool]:
    decoded = html.unescape(raw_value).replace("\x00", "").strip()
    compact = re.sub(r"\s+", "", decoded).lower()
    allowed = ("http:", "https:", "mailto:")

    if compact.startswith(("javascript:", "data:", "vbscript:")):
        return "#removed", False

    if compact.startswith("//"):
        return "#removed", False

    if ":" in compact and not compact.startswith(allowed):
        return "#removed", False

    if attribute_name == "src" and compact.startswith("mailto:"):
        return "#removed", False

    return decoded, True
```

### What this protects against

- `javascript:alert(1)`
- `data:text/html,...`
- `vbscript:`
- protocol-relative URLs like `//evil.example`

---

## Step 10: Sanitize allowed attributes

Now write a function that filters attributes on safe tags.

```python
def sanitize_allowed_attributes(
    tag_name: str,
    raw_attrs: str,
    findings: list[dict],
    source_text: str,
    start_position: int,
    safe_tags: dict,
) -> str:
    kept = []
    allowed_attributes = safe_tags.get(tag_name, [])

    for match in ATTRIBUTE_PATTERN.finditer(raw_attrs):
        attribute_name = match.group(1).lower()
        raw_value = next((group for group in match.groups()[1:] if group is not None), "")

        if attribute_name.startswith("on"):
            add_finding(findings, source_text, start_position, "event_handler", "high", f"Removed event handler {attribute_name}.")
            continue

        if attribute_name == "style":
            continue

        if attribute_name not in allowed_attributes:
            if attribute_name not in {"", "/"}:
                add_finding(findings, source_text, start_position, "attribute_strip", "low", f"Removed attribute {attribute_name} from <{tag_name}>.")
            continue

        if attribute_name in {"href", "src"}:
            safe_value, is_safe = validate_url(raw_value, attribute_name)
            if not is_safe:
                add_finding(findings, source_text, start_position, "dangerous_url", "critical", f"Replaced dangerous {attribute_name} value on <{tag_name}>.")
            kept.append(f'{attribute_name}="{html.escape(safe_value, quote=True)}"')
            continue

        kept.append(f'{attribute_name}="{html.escape(raw_value, quote=True)}"')

    return (" " + " ".join(kept)) if kept else ""
```

### Key lesson

A safe tag is not enough. Safe attributes matter too.

`<a>` is often okay. `<a href="javascript:...">` is not.

---

## Step 11: Rebuild safe HTML

In safe mode, you do not want to keep everything. You want to rebuild only what passed the rules.

```python
def rebuild_safe_html(text: str, safe_tags: dict, findings: list[dict]) -> str:
    def replacement_function(match: re.Match) -> str:
        tag_name = match.group("tag").lower()
        closing = bool(match.group("closing"))
        raw_attrs = match.group("attrs") or ""

        if tag_name not in safe_tags:
            add_finding(findings, text, match.start(), "tag_strip", "low", f"Removed disallowed tag <{tag_name}>.")
            return ""

        if closing:
            return f"</{tag_name}>"

        safe_attrs = sanitize_allowed_attributes(tag_name, raw_attrs, findings, text, match.start(), safe_tags)

        if tag_name in SELF_CLOSING_TAGS:
            return f"<{tag_name}{safe_attrs}>"
        return f"<{tag_name}{safe_attrs}>"

    return TAG_PATTERN.sub(replacement_function, text)
```

### Why rebuild instead of editing in place?

Rebuilding is safer. You only keep content that passed the checks.

---

## Step 12: Add plain mode

Plain mode is simpler. Remove all tags and return only text.

```python
def strip_all_tags(text: str) -> str:
    without_tags = re.sub(r"<[^>]+>", "", text)
    return html.unescape(without_tags)
```

### What plain mode is good for

- logs
- summaries
- exporting text only
- pipelines that should not keep HTML formatting

---

## Step 13: Add a danger score

This gives users a quick sense of how risky the input looked.

```python
def danger_score(findings: list[dict]) -> int:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 2, "info": 1}
    return min(sum(weights.get(item.get("severity", "info"), 1) for item in findings), 100)
```

### Why this is useful

It turns many individual findings into one easy summary number.

---

## Step 14: Build the main pipeline

Now connect all the pieces.

```python
def sanitize_html(input_text: str, mode: str = "plain", allowed_tags: list[str] | None = None) -> tuple[str, list[dict], dict]:
    findings = []
    safe_tags = DEFAULT_SAFE_TAGS.copy()
    if allowed_tags is not None:
        safe_tags = {tag: DEFAULT_SAFE_TAGS.get(tag, []) for tag in allowed_tags if tag}

    text = input_text
    decoded = html.unescape(text)
    if decoded != text:
        findings.append({"severity": "low", "category": "entity_decode", "line": 1, "message": "Decoded HTML entities before scanning."})
        text = decoded

    if "\x00" in text:
        findings.append({"severity": "medium", "category": "null_byte", "line": 1, "message": "Removed null bytes used for obfuscation."})
        text = text.replace("\x00", "")

    previous = None
    loop_count = 0
    while text != previous and loop_count < 5:
        previous = text
        loop_count += 1

        text = replace_pattern(text, COMMENT_PATTERN, "", findings, "comment", "low", "Removed HTML comment.")
        text = replace_pattern(text, SCRIPT_PATTERN, "", findings, "script_tag", "critical", "Removed script tag and contents.")
        text = replace_pattern(text, STYLE_PATTERN, "", findings, "style_block", "medium", "Removed style block.")
        text = replace_pattern(text, BLOCKED_TAGS_PATTERN, "", findings, "blocked_tag", "critical", "Removed blocked tag container.")
        text = replace_pattern(text, META_REFRESH_PATTERN, "", findings, "meta_refresh", "critical", "Removed meta refresh tag.")
        text = replace_pattern(text, EVENT_HANDLER_PATTERN, "", findings, "event_handler", "high", "Removed inline event handler: {content}")

    if mode == "safe":
        output = rebuild_safe_html(text, safe_tags, findings)
    else:
        output = strip_all_tags(text)

    stats = {
        "mode": mode,
        "before_characters": len(input_text),
        "after_characters": len(output),
        "characters_removed": max(len(input_text) - len(output), 0),
        "danger_score": danger_score(findings),
        "passes": loop_count,
    }
    return output, findings, stats
```

### What students should notice

This function is the pipeline:

1. normalize input
2. remove dangerous patterns
3. choose output mode
4. return both cleaned output and structured metadata

---

## Step 15: Add a friendly wrapper API

```python
def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    mode = config.get("mode", "plain")
    allowed_tags = config.get("allowed_tags")
    output, findings, stats = sanitize_html(input_text, mode=mode, allowed_tags=allowed_tags)

    summary = (
        f"Sanitized HTML in {mode} mode. Removed {stats['characters_removed']} characters "
        f"with danger score {stats['danger_score']}."
    )

    return {
        "module_name": "html",
        "title": "DataGuard HTML Sanitizer Report",
        "output": output,
        "findings": findings,
        "warnings": [] if not findings else [f"Removed or modified {len(findings)} HTML threat indicators."],
        "errors": [],
        "stats": stats,
        "metadata": {"source": config.get("source_name", "<input>"), "mode": mode},
        "summary": summary,
    }
```

### Why this function exists

It provides a stable API for other programs to call.

---

## Step 16: Build the CLI

Add these helper functions and a `main()` entry point.

```python
def _parse_allowed_tags(raw: str | None) -> list[str] | None:
    if raw is None or not raw.strip():
        return None
    return [t.strip().lower() for t in raw.split(",") if t.strip()]
```

Then create the CLI:

```python
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strip dangerous HTML; optional allowlisted safe HTML mode.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", "-i", help="HTML string to sanitize")
    src.add_argument("--file", "-f", type=Path, help="Path to a .html or .txt file (UTF-8)")
    parser.add_argument("--mode", choices=("plain", "safe"), default="plain")
    parser.add_argument("--allow", help="Comma-separated tag names for safe mode")
    parser.add_argument("--output", "-o", type=Path, help="Write cleaned output to this file")
    parser.add_argument("--report", action="store_true", help="Print JSON findings and stats to stderr")
    parser.add_argument("--show-diff", action="store_true", help="Print before/after character counts to stderr")
    args = parser.parse_args(argv)

    if args.input is not None:
        input_text = args.input
    else:
        try:
            input_text = args.file.read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"Cannot read file: {args.file}") from exc

    allowed_tags = _parse_allowed_tags(args.allow)
    result = run(
        input_text,
        {
            "mode": args.mode,
            "allowed_tags": allowed_tags,
            "source_name": str(args.file) if args.file else "<--input>",
        },
    )

    out = result["output"]
    if args.output is not None:
        try:
            args.output.write_text(out, encoding="utf-8")
        except OSError as exc:
            raise InputError(f"Cannot write file: {args.output}") from exc
    else:
        sys.stdout.write(out)
        if out and not out.endswith("\n"):
            sys.stdout.write("\n")

    if args.show_diff:
        st = result["stats"]
        print(
            f"Characters: {st['before_characters']} -> {st['after_characters']} "
            f"(removed {st['characters_removed']}, danger_score={st['danger_score']}, passes={st['passes']})",
            file=sys.stderr,
        )

    if args.report:
        payload = {"findings": result["findings"], "stats": result["stats"], "summary": result["summary"]}
        print(json.dumps(payload, indent=2), file=sys.stderr)

    return 0
```

Finish the file with:

```python
if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InputError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
```

---

## Step 17: Add the test dependency

Create `requirements.txt`:

```text
pytest>=8.0.0
```

---

## Step 18: Write tests first for the important behaviors

Create `tests/test_html_sanitizer.py`.

Start with these core tests:

```python
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


def test_script_stripped_and_finding() -> None:
    out, findings, _ = sanitize_html('<p>x</p><script>alert(1)</script>', mode="safe")
    assert "script" not in out.lower()
    assert any(f.get("category") == "script_tag" for f in findings)


def test_javascript_href_replaced() -> None:
    out, findings, _ = sanitize_html('<a href="javascript:alert(1)">x</a>', mode="safe")
    assert 'href="#removed"' in out or "#removed" in out
    assert any(f.get("category") == "dangerous_url" for f in findings)


def test_plain_mode_strips_tags() -> None:
    out, _, _ = sanitize_html("<p>hello <b>w</b></p>", mode="plain")
    assert "<" not in out
    assert "hello" in out and "w" in out
```

Then add CLI tests:

```python
def test_main_cli_plain_input(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--input", "<em>z</em>", "--mode", "plain"])
    assert code == 0
    captured = capsys.readouterr()
    assert "z" in captured.out
    assert "<em>" not in captured.out


def test_cli_missing_file_exit_code() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "html_sanitizer.py"), "--file", str(ROOT / "missing.txt")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "Cannot read" in proc.stderr
```

### What to test next

Add more tests for:

- protocol-relative URLs
- `data:` URLs
- event handlers
- custom allowlists
- file round-trips
- JSON reports
- null bytes
- encoded payloads like `&lt;script&gt;`

---

## Step 19: Run the tests

```bash
python -m pytest
```

A passing test suite means your core behaviors are working as expected.

---

## Step 20: Try the CLI manually

### Plain mode

```bash
python html_sanitizer.py --input "<p>Hello</p><script>alert(1)</script>" --mode plain
```

Expected output:

```text
Hello
```

### Safe mode

```bash
python html_sanitizer.py --input "<p>Hello</p><script>alert(1)</script>" --mode safe
```

Expected output:

```html
<p>Hello</p>
```

### Show report

```bash
python html_sanitizer.py --input "<a href='javascript:alert(1)'>x</a>" --mode safe --report
```

### Write to a file

```bash
python html_sanitizer.py --file sample.html --mode safe --output clean.html
```

---

## Step 21: Explain the design to students

This app is a good beginner-to-intermediate Python project because it teaches:

- regex pattern design
- string normalization
- allowlist thinking
- CLI design with `argparse`
- returning structured data
- test writing with `pytest`
- error handling with custom exceptions

It is also small enough that one student can understand the whole codebase.

---

## Step 22: Discuss the limitations honestly

Students should understand what this app does **well** and what it does **not** do well.

### Good at

- learning core Python
- quick cleanup in a pipeline
- removing obvious dangerous markup
- creating security reports

### Not good at

- production-grade browser-safe sanitization
- handling every malformed HTML edge case
- matching browser parsing behavior
- protecting a real web app by itself

---

## Step 23: Suggested improvement roadmap

After students finish the base version, they can improve it.

### Beginner improvements

1. Add more tests.
2. Handle Unicode decode errors more gracefully.
3. Add a `--json` flag to print the whole report to stdout.
4. Add docstrings to every function.

### Intermediate improvements

1. Add packaging with `pyproject.toml`.
2. Add GitHub Actions for tests.
3. Split regex patterns into a separate config file.
4. Track counts per category in the report.

### Advanced improvements

1. Replace regex sanitization with a parser-backed approach.
2. Add configurable attribute allowlists.
3. Add fuzz tests for malformed HTML.
4. Add benchmarks for large inputs.

---

## Step 24: Reflection questions for students

Ask yourself:

1. Why is an allowlist safer than a blocklist?
2. Why is `javascript:` dangerous in `href`?
3. Why should reports go to `stderr` and cleaned output go to `stdout`?
4. Why is regex useful for learning but risky for full HTML parsing?
5. What new tests would make this app more trustworthy?

---

## Final takeaway

This project is a strong **learning app** because it is small, readable, testable, and realistic enough to teach useful software engineering habits.

If your goal is to learn Python app design, this is a very good project to build.
If your goal is to secure a real browser-facing production app, treat this as a teaching prototype and move to a parser-backed sanitizer.
