# Architecture Decision Record
## App 02 — HTML Sanitizer
**DataGuard Group | Document 1 of 5**
**Status: Accepted**

---

## Context

DataGuard processes raw text that may arrive as HTML — scraped pages, pasted rich-text, form submissions, email bodies. This content frequently contains script tags, event handlers, dangerous URLs, and obfuscation techniques designed to survive naive string cleaning. The HTML Sanitizer is the second module in the DataGuard group, responsible for cleaning markup before downstream apps (Contact Extractor, CSV Converter) extract structured data from it.

Two distinct use cases drove the design: some callers need plain text only (strip all tags, return content), while others need to preserve safe formatting (retain `<p>`, `<b>`, `<a>` etc. but nothing dangerous). A single module with a mode switch handles both.

---

## Decisions

### Decision 1 — Two modes: `plain` and `safe`

**Chosen:** `sanitize_html(text, mode="plain" | "safe")`. In `plain` mode all tags are stripped and entities decoded. In `safe` mode an allowlist-based rebuilder preserves whitelisted tags with sanitized attributes.

**Rejected:** A single mode that always attempts to preserve safe HTML.

**Reason:** Plain mode is simpler, faster, and produces output appropriate for downstream text processing (frequency counting, contact extraction). Safe mode is appropriate when the output will be re-rendered in a browser context. Callers should explicitly choose — defaulting to the more aggressive stripping is the safer default.

---

### Decision 2 — Multi-pass cleaning loop (up to 5 iterations)

**Chosen:** The core cleaning stage runs in a `while text != previous and loop_count < 5` loop, re-applying all regex patterns until the text stabilizes or 5 passes are exhausted.

**Rejected:** A single-pass cleaning with no re-scanning.

**Reason:** Obfuscated payloads nest transformations. After the first pass removes one layer, the result may expose another dangerous construct. Example: `<<script>script>alert(1)<</script>/script>` — after removing the inner `<script>`, the outer shell forms a valid `<script>` tag. The multi-pass loop catches this. The cap of 5 prevents pathological inputs from running indefinitely.

---

### Decision 3 — Regex-based approach with explicit allowlist

**Chosen:** Eight pre-compiled module-level regex patterns for specific threat categories, plus a `DEFAULT_SAFE_TAGS` allowlist mapping tag names to permitted attributes.

**Rejected:** A full HTML parser (e.g. `html.parser`, `BeautifulSoup`).

**Reason:** The module docstring is explicit — this is a triage helper, not a replacement for a hardened parser-based sanitizer. The regex approach is readable, testable, and appropriate for DataGuard's scope. The module acknowledges this limitation rather than hiding it. A parser-based approach would be the right choice for a security-critical production context.

---

### Decision 4 — `validate_url()` as a standalone pure function

**Chosen:** URL validation extracted into its own function that returns `(safe_value, is_ok)`.

**Rejected:** Inline URL checking inside `sanitize_allowed_attributes()`.

**Reason:** URL validation is complex enough (entity decoding, null byte removal, protocol detection, protocol-relative blocking) that it deserves its own function and its own tests. `test_protocol_relative_href_blocked` and `test_data_uri_blocked` test `validate_url` directly — this would not be possible if the logic were inlined.

---

### Decision 5 — `danger_score()` weighted severity sum

**Chosen:** A numeric score from 0–100 computed as the weighted sum of finding severities (`critical=25`, `high=15`, `medium=8`, `low=2`), capped at 100.

**Rejected:** A categorical risk level (low/medium/high/critical) for the overall document.

**Reason:** A single categorical label loses nuance — 50 low findings and 1 critical finding should not produce the same label. A numeric score lets callers set their own thresholds. The cap at 100 prevents the score from being meaninglessly large for heavily-contaminated inputs.

---

### Decision 6 — `errors.py` as shared DataGuard exception module

**Chosen:** `InputError` imported from `errors.py` — a file shared across DataGuard apps.

**Rejected:** Defining `InputError` inside `html_sanitizer.py`.

**Reason:** Consistent exception types across the DataGuard group allows the bootstrapper to catch `DataGuardError` (the base class) uniformly. This is the first app in the group to introduce `errors.py` — subsequent apps import from the same file.

---

### Decision 7 — Void elements rendered without self-closing slash

**Chosen:** `<br>`, `<hr>`, `<img ...>` — HTML5 void element syntax, no trailing `/>`.

**Rejected:** XML-style self-closing `<br />`.

**Reason:** This was the bug fixed during the evaluation. The original code rendered `<br/>` in some branches, which is valid XHTML but inconsistent with HTML5. The fix ensures void elements always render in standard HTML5 form regardless of how the input was written.

---

## Consequences

**Positive:**
- Multi-pass loop handles realistic obfuscation attempts without requiring a full parser.
- Two modes serve both plain-text extraction and safe HTML preservation callers.
- `validate_url()` is independently testable and catches the five most common URL-based XSS vectors.
- `danger_score` gives callers a single numeric signal without requiring them to iterate findings.
- `errors.py` establishes the shared exception contract for the entire DataGuard group.

**Negative / Trade-offs:**
- Regex-based sanitization is not adversarially hardened. Novel obfuscation techniques not covered by the current patterns will pass through. This is acknowledged in the module docstring.
- The multi-pass loop scans the entire text up to five times. For very large HTML documents, a parser-based single-pass approach would be more efficient.
- `DEFAULT_SAFE_TAGS` contains 20 tag entries with a fixed attribute allowlist. Tags with legitimate but varied attribute needs (e.g. `<table>`, `<td>`) are not included — callers needing those must pass a custom `allowed_tags`.

---

*Constitution reference: Article 1 (Python fundamentals), Article 3 (24-hour scope). Bug fixed before documentation: void element self-closing slash.*


---


# Technical Design Document
## App 02 — HTML Sanitizer
**DataGuard Group | Document 2 of 5**

---

## Overview

HTML Sanitizer is a single-file Python module that takes raw HTML and produces either clean plain text or allowlist-filtered safe HTML. It uses pre-compiled regex patterns, a multi-pass cleaning loop, URL validation, and a danger scoring system. It is the second component in the DataGuard shared sanitization layer.

**Files:** `html_sanitizer.py` (355 lines), `errors.py` (shared)
**Entry points:** `run()` (public API), `main()` (argparse CLI), `sanitize_html()` (direct engine)
**Dependencies:** `re`, `html`, `json`, `argparse`, `sys`, `pathlib` (stdlib); `errors.InputError` (DataGuard shared)

---

## Data Flow

```
Input HTML string
       │
       ▼
sanitize_html(text, mode, allowed_tags)
       │
       ├─ html.unescape() — decode entities first
       ├─ remove null bytes
       │
       └─ MULTI-PASS LOOP (up to 5 iterations)
              ├─ COMMENT_PATTERN       → remove <!-- ... -->
              ├─ SCRIPT_PATTERN        → remove <script>...</script>
              ├─ STYLE_PATTERN         → remove <style>...</style>
              ├─ BLOCKED_TAGS_PATTERN  → remove iframe, object, embed, form, base
              ├─ META_REFRESH_PATTERN  → remove <meta http-equiv=refresh>
              └─ EVENT_HANDLER_PATTERN → remove on* attributes inline
       │
       ├─ mode == "plain" → strip_all_tags() → html.unescape()
       └─ mode == "safe"  → rebuild_safe_html()
                                 └─ TAG_PATTERN.sub()
                                       └─ sanitize_allowed_attributes()
                                             └─ validate_url() (for href, src)
       │
       ▼
   (output: str, findings: list[dict], stats: dict)
       │
       ▼
   build_result() via run()  →  standard DataGuard result dict
```

---

## Module-Level Constants

### Compiled Regex Patterns

| Name | Purpose |
|---|---|
| `COMMENT_PATTERN` | HTML comments and IE conditional comments (`<!--[if IE]...`) |
| `SCRIPT_PATTERN` | `<script>` blocks with any attributes, case-insensitive, dotall |
| `STYLE_PATTERN` | `<style>` blocks |
| `BLOCKED_TAGS_PATTERN` | iframe, object, embed, applet, form, base — both paired and self-closing forms |
| `META_REFRESH_PATTERN` | `<meta http-equiv=refresh>` — phishing/redirect vector |
| `EVENT_HANDLER_PATTERN` | Inline `on*` attributes with any quoting style (double, single, backtick, unquoted) |
| `STYLE_DANGER_PATTERN` | CSS expression(), javascript: urls, -moz-binding, behavior: |
| `TAG_PATTERN` | Any HTML tag — captures closing flag, tag name, and attribute string |
| `ATTRIBUTE_PATTERN` | Individual attributes within a tag string, all quoting styles |

### `DEFAULT_SAFE_TAGS`
`dict[str, list[str]]` — 20 tag names mapped to their permitted attribute lists.

Notable entries:
- `"a": ["href"]` — links permitted, only `href` allowed
- `"img": ["src", "alt"]` — images permitted, `src` validated via `validate_url()`
- All structural/formatting tags (`p`, `b`, `i`, `strong`, `em`, `h1`–`h6`, etc.): empty attribute list

---

## Function Reference

### `line_number_for_position(text, position) → int`
1-based line number for a character position. Identical implementation to App 01's string sanitizer — consistent across DataGuard.

---

### `add_finding(findings, text, position, category, severity, message)`
Appends a structured finding:
```python
{"severity": str, "category": str, "line": int, "message": str}
```
Categories used: `comment`, `script_tag`, `style_block`, `blocked_tag`, `meta_refresh`, `event_handler`, `css_attack`, `dangerous_url`, `tag_strip`, `attribute_strip`, `entity_decode`, `null_byte`.

---

### `replace_pattern(text, pattern, replacement, findings, category, severity, message_template) → str`
Wraps `pattern.sub()` to intercept every match, log a finding, and then apply the replacement. `message_template` accepts `{content}` which is replaced with the first 80 characters of the matched text.

---

### `validate_url(raw_value, attribute_name) → tuple[str, bool]`
Pure function. Decodes entities, removes null bytes, strips whitespace, lowercases for comparison.

Blocked:
- `javascript:` prefix
- `data:` prefix
- `vbscript:` prefix
- Protocol-relative `//`
- Any unknown protocol containing `:` not in `("http:", "https:", "mailto:")`
- `mailto:` in `src` attributes

Returns `("#removed", False)` for any blocked URL. Returns `(decoded_value, True)` for safe URLs.

---

### `sanitize_allowed_attributes(tag_name, raw_attrs, findings, source_text, start_position, safe_tags) → str`
Iterates attributes via `ATTRIBUTE_PATTERN`. For each attribute:
1. Removes any `on*` handler — logs `event_handler` finding (high severity)
2. Removes `style` if it contains dangerous CSS patterns — logs `css_attack` finding
3. Removes any attribute not in the tag's allowed list — logs `attribute_strip` finding (low)
4. For `href`/`src`: passes through `validate_url()` — logs `dangerous_url` finding if blocked
5. Escapes remaining values with `html.escape(quote=True)`

Returns a string like `' href="https://example.com" alt="text"'` (leading space if non-empty).

---

### `rebuild_safe_html(text, safe_tags, findings) → str`
Uses `TAG_PATTERN.sub()`. For each matched tag:
- Tag not in allowlist → remove, log `tag_strip` (low)
- Closing tag for allowed element → `</tagname>`
- Opening tag for allowed element → reconstruct with `sanitize_allowed_attributes()`
- Void elements (`br`, `hr`, `img`) → rendered as `<tagname attrs>` (no slash)

---

### `strip_all_tags(text) → str`
Plain mode only. Strips all `<...>` patterns with `re.sub(r"<[^>]+>", "", text)`, then decodes remaining HTML entities with `html.unescape()`.

---

### `danger_score(findings) → int`
```python
weights = {"critical": 25, "high": 15, "medium": 8, "low": 2, "info": 1}
return min(sum(weights.get(f["severity"], 1) for f in findings), 100)
```

---

### `sanitize_html(input_text, mode, allowed_tags) → tuple[str, list[dict], dict]`
Main engine. Runs entity decode, null byte removal, then the multi-pass loop, then mode dispatch.

Stats dict:
```python
{
    "mode": str,
    "before_characters": int,
    "after_characters": int,
    "characters_removed": int,    # max(before - after, 0)
    "danger_score": int,          # 0–100
    "passes": int,                # actual loop iterations used
}
```

---

### `run(input_text, config) → dict`
Public API. Config keys: `mode`, `allowed_tags`, `source_name`.

Returns standard DataGuard envelope with `module_name: "html"`.

`warnings` field: empty if no findings; otherwise `["Removed or modified N HTML threat indicators."]`.

---

### `main(argv) → int`
CLI entry point. Returns 0 on success, 1 on `InputError` (file not found or unwritable).

Flags: `--input`/`--file` (mutually exclusive), `--mode`, `--allow`, `--output`, `--report`, `--show-diff`.

`--report` prints JSON findings+stats to stderr. `--show-diff` prints character count delta to stderr. Both leave stdout containing only the cleaned output.

---

## Multi-Pass Loop Detail

```python
previous = None
loop_count = 0
while text != previous and loop_count < 5:
    previous = text
    loop_count += 1
    # all six replace_pattern calls
```

The loop terminates when the text is unchanged after a full pass (no more patterns matched) or after 5 passes. The `passes` value in stats reflects the actual count used. Most clean inputs terminate after 1 pass. Heavily obfuscated inputs may use 2–3 passes.

---

## Shared Module: `errors.py`

```python
class DataGuardError(Exception): ...
class InputError(DataGuardError): ...
class ParseError(DataGuardError): ...
class ValidationError(DataGuardError): ...
```

`InputError` is raised by `main()` for file I/O failures. The CLI catches it, prints to stderr, and exits with code 1. The DataGuard bootstrapper catches `DataGuardError` to handle all module failures uniformly.


---


# Interface Design Specification
## App 02 — HTML Sanitizer
**DataGuard Group | Document 3 of 5**

---

## Public API

### Primary Entry Point

```python
run(input_text: str, config: dict | None = None) -> dict
```

**Config keys:**

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | `str` | `"plain"` | `"plain"` strips all tags; `"safe"` preserves allowlisted tags |
| `allowed_tags` | `list[str] \| None` | `None` | Custom tag allowlist for safe mode; replaces default |
| `source_name` | `str` | `"<input>"` | Label for result metadata |

---

### Direct Engine Access

```python
sanitize_html(
    input_text: str,
    mode: str = "plain",
    allowed_tags: list[str] | None = None,
) -> tuple[str, list[dict], dict]
```

Returns `(output, findings, stats)`.

---

### URL Validator

```python
validate_url(raw_value: str, attribute_name: str) -> tuple[str, bool]
```

Returns `(safe_value, is_ok)`. Can be called independently for URL validation tasks.

---

### CLI

```bash
# Plain text extraction from string
python html_sanitizer.py --input "<b>hello</b>" --mode plain

# Safe HTML from file, write to output
python html_sanitizer.py --file page.html --mode safe --output clean.html

# Custom allowlist
python html_sanitizer.py --input "<div><p>ok</p></div>" --mode safe --allow "div,p"

# With JSON report to stderr
python html_sanitizer.py --input "<script>x</script>" --mode plain --report

# Character count diff to stderr
python html_sanitizer.py --file page.html --show-diff

# Pipe usage
cat page.html | python html_sanitizer.py --input -
```

Exit codes: `0` success, `1` file I/O error.

---

## Result Envelope

```python
{
    "module_name": "html",
    "title": "DataGuard HTML Sanitizer Report",
    "output": str,
    "findings": list[dict],
    "warnings": list[str],      # empty or single-entry list
    "errors": [],               # always empty
    "stats": dict,
    "metadata": {"source": str, "mode": str},
    "summary": str,
}
```

---

## Finding Schema

```python
{"severity": str, "category": str, "line": int, "message": str}
```

**Severity levels:** `critical`, `high`, `medium`, `low`

**Categories and default severities:**

| Category | Severity | Description |
|---|---|---|
| `script_tag` | critical | `<script>` block removed |
| `blocked_tag` | critical | iframe/object/embed/form/base removed |
| `meta_refresh` | critical | `<meta http-equiv=refresh>` removed |
| `dangerous_url` | critical | href/src replaced with `#removed` |
| `event_handler` | high | `on*` inline handler removed |
| `css_attack` | medium | Dangerous inline style content removed |
| `null_byte` | medium | Null bytes removed |
| `style_block` | medium | `<style>` block removed |
| `comment` | low | HTML comment removed |
| `entity_decode` | low | Entities decoded before scanning |
| `tag_strip` | low | Tag not in allowlist removed |
| `attribute_strip` | low | Attribute not in allowlist removed |

---

## Stats Schema

```python
{
    "mode": str,                 # "plain" or "safe"
    "before_characters": int,
    "after_characters": int,
    "characters_removed": int,
    "danger_score": int,         # 0–100
    "passes": int,               # loop iterations used
}
```

---

## Input/Output Examples

### Plain mode — all tags stripped
```python
run("<p>hello <b>world</b></p>")
# output: "hello world"
# findings: []
# stats["danger_score"]: 0
```

### Script tag removal
```python
run("<p>ok</p><script>alert(1)</script>", {"mode": "plain"})
# output: "ok"
# findings: [{"severity": "critical", "category": "script_tag", ...}]
# stats["danger_score"]: 25
```

### Safe mode — allowlist filtering
```python
run('<p>text</p><div>block</div>', {"mode": "safe"})
# output: "<p>text</p>"   (<div> not in default allowlist)
# findings: [{"severity": "low", "category": "tag_strip", ...}]
```

### Dangerous href blocked
```python
run('<a href="javascript:alert(1)">click</a>', {"mode": "safe"})
# output: '<a href="#removed">click</a>'
# findings: [{"severity": "critical", "category": "dangerous_url", ...}]
```

### Event handler removed
```python
run('<p onclick="evil()">text</p>', {"mode": "safe"})
# output: "<p>text</p>"
# findings: [{"severity": "high", "category": "event_handler", ...}]
```

### IE conditional comment
```python
run('<!--[if IE]><img src=x onerror=alert(1)><![endif]--><p>ok</p>', {"mode": "safe"})
# output: "<p>ok</p>"
# findings: [{"category": "comment", ...}]
```

### Custom allowlist
```python
run("<div>a</div><p>b</p>", {"mode": "safe", "allowed_tags": ["div"]})
# output: "<div>a</div>"   (<p> stripped — not in custom list)
```

### Danger score example
```python
# 1 critical (25) + 1 high (15) + 1 medium (8) = 48
run('<script>x</script><p onclick="y">z</p>&lt;style&gt;...&lt;/style&gt;', {"mode": "plain"})
# stats["danger_score"]: 48
```

---

## Default Safe Tag Allowlist

| Tag | Allowed Attributes |
|---|---|
| p, b, i, u, strong, em, br, hr | (none) |
| ul, ol, li | (none) |
| h1–h6, blockquote, pre, code | (none) |
| a | href |
| img | src, alt |

All `href` and `src` values pass through `validate_url()`. Dangerous values are replaced with `#removed`.


---


# Runbook
## App 02 — HTML Sanitizer
**DataGuard Group | Document 4 of 5**

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — stdlib only
- `errors.py` must be in the same directory or on `PYTHONPATH`

---

## Installation

```bash
git clone https://github.com/PrincetonAfeez/HTML-Sanitizer
cd HTML-Sanitizer
```

Confirm `errors.py` is present alongside `html_sanitizer.py`. No `pip install` required.

---

## Running the CLI

### Strip all tags (plain mode, default)
```bash
python html_sanitizer.py --input "<p>hello <b>world</b></p>"
# output: hello world
```

### Safe mode — preserve allowlisted tags
```bash
python html_sanitizer.py --input "<p>text</p><script>evil()</script>" --mode safe
# output: <p>text</p>
```

### From a file, write to output
```bash
python html_sanitizer.py --file page.html --mode plain --output clean.txt
```

### Custom allowlist (comma-separated tag names)
```bash
python html_sanitizer.py --input "<div><p>ok</p></div>" --mode safe --allow "div,p"
```

### JSON report to stderr
```bash
python html_sanitizer.py --input "<script>x</script>" --mode plain --report 2>report.json
```

### Character diff to stderr
```bash
python html_sanitizer.py --file page.html --show-diff
# stderr: Characters: 4520 -> 3102 (removed 1418, danger_score=48, passes=2)
```

### Module invocation
```bash
python -m html_sanitizer --input "<b>hi</b>"
```

---

## Using as a Library

### Basic plain text extraction
```python
from html_sanitizer import run

result = run("<p>hello</p>", {"mode": "plain", "source_name": "email.html"})
print(result["output"])          # hello
print(result["stats"]["danger_score"])  # 0
```

### Safe mode with findings inspection
```python
from html_sanitizer import run

result = run(raw_html, {"mode": "safe"})
critical = [f for f in result["findings"] if f["severity"] == "critical"]
if critical:
    print(f"WARNING: {len(critical)} critical threats removed")
print(result["output"])
```

### Direct engine access
```python
from html_sanitizer import sanitize_html

output, findings, stats = sanitize_html(raw_html, mode="safe")
print(f"Passes used: {stats['passes']}")
print(f"Danger score: {stats['danger_score']}")
```

### URL validation only
```python
from html_sanitizer import validate_url

safe, ok = validate_url("javascript:alert(1)", "href")
print(ok)     # False
print(safe)   # #removed

safe, ok = validate_url("https://example.com", "href")
print(ok)     # True
```

### Check if input was clean
```python
output, findings, stats = sanitize_html(raw_html, mode="safe")
is_clean = stats["danger_score"] == 0 and len(findings) == 0
```

---

## Running Tests

```bash
pip install pytest
pytest test_html_sanitizer.py -v
```

Expected: all tests pass. The test suite includes subprocess tests that invoke the CLI directly — these require `html_sanitizer.py` to be executable from the project root.

```bash
# Run only unit tests (skip subprocess tests)
pytest test_html_sanitizer.py -v -k "not subprocess and not cli_subprocess"

# Run with coverage
pip install pytest-cov
pytest test_html_sanitizer.py --cov=html_sanitizer --cov-report=term-missing
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'errors'`
`errors.py` must be in the same directory as `html_sanitizer.py`. Either copy it there or set `PYTHONPATH` to the directory containing both files.

### File not found exits with code 1
The `--file` argument must point to an existing, UTF-8 readable file. The error message is printed to stderr.

### Output file not written
Check directory write permissions. The `--output` parent directory must exist — the module does not create intermediate directories.

### Danger score is 0 but output changed
Entity decoding (`entity_decode` category) has severity `"low"` which contributes 2 points per occurrence. If only entity decoding occurred, the score may still be low but above 0. Check `stats["passes"]` — if it is greater than 1, the multi-pass loop found nested constructs.

### Safe mode is not preserving expected tags
Check whether the tag is in `DEFAULT_SAFE_TAGS`. If using `--allow`, the custom list replaces the default entirely — include all tags you want to keep. For programmatic use, pass `allowed_tags=["div", "p", "a", ...]` to `run()` or `sanitize_html()`.


---


# Lessons Learned
## App 02 — HTML Sanitizer
**DataGuard Group | Document 5 of 5**

---

## Why This Design Was Chosen

The two-mode design came directly from thinking about who would call this module. The first draft only had plain mode. Adding safe mode was a decision made after thinking through DataGuard's pipeline — the Contact Extractor needs plain text, but a future module that re-renders HTML for display would need allowlist-filtered markup. Building both into one module now meant no duplication later.

The multi-pass loop was not in the first version. The first version was single-pass. The problem became apparent when writing the IE conditional comment test — a single pass removed the comment wrapper but left the inner tag structure intact in some edge cases. The loop was the simplest fix that handled real-world obfuscation patterns without requiring a full parser.

---

## What Was Intentionally Omitted

**Full HTML parser integration:** Using `html.parser` or a library like `bleach` would produce a more robust sanitizer. This was intentionally omitted because the learning goal was to practice regex, multi-pass logic, and allowlist design — not to wrap a library. The docstring explicitly acknowledges the limitation.

**CSS property allowlisting:** The `STYLE_DANGER_PATTERN` blocks known dangerous CSS patterns but does not whitelist safe ones. A complete implementation would parse the CSS value and allow only properties from an explicit safe list. Omitted as out of scope for DataGuard's text extraction use case.

**`<table>` and related tags:** Table elements (`table`, `thead`, `tbody`, `tr`, `td`, `th`) are not in `DEFAULT_SAFE_TAGS`. They are legitimate HTML but were excluded to keep the default allowlist simple. Callers needing table support must pass a custom `allowed_tags`.

**Encoding detection:** Assumes UTF-8 input. Files in other encodings require the caller to decode first.

---

## Biggest Weakness

The regex approach has a fundamental limitation: regex cannot fully parse HTML. Deeply nested or deliberately malformed markup may produce unexpected outputs. The specific case that prompted the multi-pass loop — `<<script>script>` style double-wrapping — is handled. But truly adversarial inputs from a security context require a parser-based approach (`html.parser` → DOM traversal → rebuild) rather than regex substitution.

The module docstring states this clearly. For DataGuard's actual use case (cleaning scraped text and user-pasted HTML before data extraction), this trade-off is acceptable. It would not be acceptable for a web application sanitizing untrusted input before rendering in a browser.

---

## The Bug Fixed Before Documentation

During the evaluation session, the self-closing tag rendering in `rebuild_safe_html()` was identified as producing `<br/>` in some branches. The fix ensures void elements always render as `<br>`, `<hr>`, `<img ...>` — standard HTML5 void element syntax without the XML-style trailing slash. The fix was:

```python
# Before (incorrect in some branches):
return f"<{tag_name}{safe_attrs}/>"

# After (correct):
return f"<{tag_name}{safe_attrs}>"
```

The lesson: void elements in HTML5 do not use `/>`. Testing against the HTML5 spec behavior, not just "it looks right," is the correct verification standard.

---

## Scaling Considerations

**If input volume increases:** The `replace_pattern()` function applies each regex to the entire string on each pass. For multi-megabyte HTML documents processed in bulk, a streaming line-by-line approach or chunked processing would reduce peak memory. The multi-pass architecture would need to be redesigned for streaming since it depends on whole-document state.

**If security requirements increase:** Replace the regex approach with a proper parser: parse to a DOM tree, walk nodes, apply allowlists at the node level, serialize back to HTML. This eliminates the class of obfuscation attacks that regex cannot handle.

**If more tag types need support:** `DEFAULT_SAFE_TAGS` is a module-level dict — adding entries requires only a one-line addition. The attribute allowlist per tag can include any attribute name. The `validate_url()` function is already generic and would apply automatically to any new `href` or `src` attributes.

---

## What the Next Refactor Would Be

1. **Parser-based safe mode:** Replace `rebuild_safe_html()` with `html.parser`-based DOM traversal for adversarially robust sanitization.

2. **Configurable `STYLE_DANGER_PATTERN`:** The CSS danger pattern is hardcoded. A `config["blocked_css_patterns"]` option would let callers customize it.

3. **`<table>` support in default allowlist:** `table`, `tr`, `td`, `th` are common legitimate tags that should probably be in the default safe list with a reasonable attribute subset.

4. **Encoding support:** Accept `bytes` input with a detected or specified encoding, rather than requiring the caller to pre-decode.

---

## What This Project Taught

**Multi-pass processing is a real design pattern, not a workaround.** The insight that a cleaned string may expose new dangerous content in the next scan comes from understanding how obfuscation works. Writing the IE conditional comment test first, observing the failure, and then designing the loop to fix it was the most direct route to understanding why defensive text processing often requires iteration.

**Documenting limitations is part of the design.** The module docstring explicitly says this is not a replacement for hardened sanitization. Writing that sentence forced clarity about what the module actually guarantees — it removes known patterns from trusted-ish input, not adversarial input from a hostile attacker. Understanding where your module ends and a different module should begin is a system design skill.

**Testing the public function and the helper separately has compounding value.** `test_protocol_relative_href_blocked` tests `validate_url()` directly. This would not be possible if URL validation were inlined. The two-level test structure (helper tests + integration tests) caught the `//` protocol-relative case independently before the safe mode integration test ran.

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation) for App 02.*
