# HTML / script sanitizer

Regex- and allowlist-based cleanup for **lightly untrusted** markup (triage, logging pipelines, or learning). It is **not** a substitute for a parser-backed sanitizer (for example [Bleach](https://github.com/mozilla/bleach) or [nh3](https://github.com/rushter/nh3)) or for **Content-Security-Policy** when input may be hostile.

## What it does

- Strips or neutralizes common XSS vectors: `<script>`, `<style>`, blocked containers (`iframe`, `object`, `embed`, `applet`, `form`, `base`), `meta` refresh, HTML comments (including IE conditional comment blocks), inline `on*` handlers.
- **Safe mode** keeps an allowlisted subset of tags and only `href` on `<a>`, `src`/`alt` on `<img>`; other attributes are removed. Inline `style` is never kept (dangerous CSS patterns are rejected if present).
- **Plain mode** removes tags with a simple regex and returns unescaped text.
- Validates `href` / `src`: allows `http:`, `https:`, and `mailto:` (on `href` only for mailto); blocks `javascript:`, `data:`, `vbscript:`, unknown schemes, and **protocol-relative** URLs (`//host/...`). Path-only relative URLs like `/path` or `page.html` are still allowed.

## CLI

Run from this directory (or ensure `html_sanitizer.py` and `errors.py` are importable together):

```bash
python html_sanitizer.py --input "<p>Hi</p><script>x</script>" --mode plain
python html_sanitizer.py --file page.html --mode safe --output clean.html
python html_sanitizer.py --input "<a href='https://a'>x</a>" --mode safe --allow p,a --report --show-diff
```

| Flag | Meaning |
|------|---------|
| `--input` / `-i` | HTML string (required unless `--file`) |
| `--file` / `-f` | Read UTF-8 from a file |
| `--mode` | `plain` (default) or `safe` |
| `--allow` | Comma-separated tag names for safe mode (replaces the default allowlist) |
| `--output` / `-o` | Write cleaned result as UTF-8 |
| `--report` | Print JSON (`findings`, `stats`, `summary`) to **stderr** |
| `--show-diff` | Print character counts and danger score to **stderr** |

Cleaned output goes to **stdout** (or `--output`). Diagnostics from `--report` and `--show-diff` go to **stderr** so pipes stay clean.

## Python API

```python
from html_sanitizer import sanitize_html, run

text, findings, stats = sanitize_html(html_string, mode="safe", allowed_tags=None)
report = run(html_string, {"mode": "plain", "source_name": "field-12"})
```

`findings` entries include `severity`, `category`, `line`, and `message` (snippet truncated to about 80 characters where applicable).

## Tests

```bash
pip install -r requirements.txt
python -m pytest
```

## Limits (read this for security)

- HTML is not parsed with a tree builder; regex edge cases differ from browsers (split tags, odd quoting, etc.).
- **Do not rely on this alone** for user-generated HTML shown as HTML in a browser; pair with a maintained sanitizer and CSP where appropriate.

## Layout

| File | Role |
|------|------|
| `html_sanitizer.py` | Sanitization, reporting, CLI entrypoint |
| `errors.py` | `InputError` and shared exceptions |
| `tests/test_html_sanitizer.py` | Pytest suite |

Intended role in broader tooling: markup step in a DataGuard-style pipeline.
