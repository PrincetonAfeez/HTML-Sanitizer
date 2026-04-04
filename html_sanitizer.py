"""HTML and script sanitizer.

Uses regex and allowlists for practical cleanup of untrusted-ish markup. This is a triage helper, not a
replacement for a hardened HTML sanitizer, browser parsing, or security controls (e.g. CSP) for hostile input.
"""

# Enable postponed evaluation of type annotations for cleaner forward references
from __future__ import annotations

# Import html for entity encoding/decoding and re for pattern-based cleaning
import argparse
import html
import json
import re
import sys
from pathlib import Path

from errors import InputError


# Regex to find and remove HTML comments (standard and IE conditional comments)
COMMENT_PATTERN = re.compile(
    r"(?:<!--\[if[\s\S]*?<!\[endif\]-->|<!--[\s\S]*?-->)",
    re.IGNORECASE | re.DOTALL,
)
# Regex to find and remove <script> blocks regardless of case or whitespace
SCRIPT_PATTERN = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL)
# Regex to find and remove <style> blocks to prevent CSS-based data exfiltration
STYLE_PATTERN = re.compile(r"<style\b[^>]*>.*?</style\s*>", re.IGNORECASE | re.DOTALL)
# Regex to block dangerous structural tags like iframes, forms, and embeds
BLOCKED_TAGS_PATTERN = re.compile(
    r"<(?:iframe|object|embed|applet|form|base)\b[^>]*>.*?</(?:iframe|object|embed|applet|form|base)\s*>|<(?:iframe|object|embed|applet|form|base)\b[^>]*/?>",
    re.IGNORECASE | re.DOTALL,
)
# Regex to detect meta-refresh tags often used for phishing or unauthorized redirects
META_REFRESH_PATTERN = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", re.IGNORECASE)
# Regex to find inline JavaScript event handlers (e.g., onclick, onerror, onload)
EVENT_HANDLER_PATTERN = re.compile(r"\s+on[a-z0-9_-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`|[^\s>]+)", re.IGNORECASE)
# Regex for dangerous CSS expressions or protocols like javascript: inside style attributes
STYLE_DANGER_PATTERN = re.compile(
    r"expression\s*\(|url\s*\(\s*javascript:|url\s*\(\s*['\"]?data:|-moz-binding|behavior\s*:",
    re.IGNORECASE,
)
# Regex to identify any HTML tag, capturing the name, attributes, and whether it's a closing tag
TAG_PATTERN = re.compile(r"<(?P<closing>/)?(?P<tag>[A-Za-z0-9]+)(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)
# Regex to parse individual attributes and their values within a tag string
ATTRIBUTE_PATTERN = re.compile(
    r"([^\s=<>'\"`/]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`|([^\s>]+)))?",
    re.DOTALL,
)

# A default allowlist of safe HTML tags and the specific attributes allowed for each
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

# Tags that do not require a closing tag in standard HTML
SELF_CLOSING_TAGS = {"br", "hr", "img"}


# Map a character position to its human-readable line number in the source text
def line_number_for_position(text: str, position: int) -> int:
    return text.count("\n", 0, max(position, 0)) + 1


# Helper to add a security finding or warning to the centralized results list
def add_finding(findings: list[dict], text: str, position: int, category: str, severity: str, message: str) -> None:
    findings.append(
        {
            "severity": severity,
            "category": category,
            "line": line_number_for_position(text, position),
            "message": message,
        }
    )


# Perform a regex substitution while logging every match found to the findings list
def replace_pattern(text: str, pattern: re.Pattern, replacement: str, findings: list[dict], category: str, severity: str, message_template: str) -> str:
    def replacement_function(match: re.Match) -> str:
        # Log the specific content found (truncated for the report)
        add_finding(findings, text, match.start(), category, severity, message_template.format(content=match.group(0)[:80]))
        return replacement

    return pattern.sub(replacement_function, text)


# Validate URLs to block dangerous protocols like 'javascript:' or 'data:'
def validate_url(raw_value: str, attribute_name: str) -> tuple[str, bool]:
    # Decode HTML entities and remove null bytes that might hide keywords
    decoded = html.unescape(raw_value).replace("\x00", "").strip()
    # Strip whitespace and lowercase for reliable prefix checking
    compact = re.sub(r"\s+", "", decoded).lower()
    allowed = ("http:", "https:", "mailto:")
    # Block non-web protocols often used in XSS attacks
    if compact.startswith(("javascript:", "data:", "vbscript:")):
        return "#removed", False
    # Protocol-relative URLs resolve against the page origin in browsers
    if compact.startswith("//"):
        return "#removed", False
    # Block unknown protocols (anything with a colon not in the allowlist)
    if ":" in compact and not compact.startswith(allowed):
        return "#removed", False
    # Prevent using mailto: in image sources (potential tracking/probing)
    if attribute_name == "src" and compact.startswith("mailto:"):
        return "#removed", False
    return decoded, True


# Filter the attributes of an allowed tag to remove event handlers and dangerous values
def sanitize_allowed_attributes(tag_name: str, raw_attrs: str, findings: list[dict], source_text: str, start_position: int, safe_tags: dict) -> str:
    kept = []
    allowed_attributes = safe_tags.get(tag_name, [])
    for match in ATTRIBUTE_PATTERN.finditer(raw_attrs):
        attribute_name = match.group(1).lower()
        # Extract the value from whichever quoting style was used (double, single, backtick, or unquoted)
        raw_value = next((group for group in match.groups()[1:] if group is not None), "")
        # Explicitly block any 'on*' attribute (e.g., onclick)
        if attribute_name.startswith("on"):
            add_finding(findings, source_text, start_position, "event_handler", "high", f"Removed event handler {attribute_name}.")
            continue
        # Check inline styles for dangerous CSS features
        if attribute_name == "style":
            if STYLE_DANGER_PATTERN.search(raw_value):
                add_finding(findings, source_text, start_position, "css_attack", "medium", "Removed dangerous inline style content.")
            continue
        # Remove any attribute not explicitly listed as safe for this specific tag
        if attribute_name not in allowed_attributes:
            if attribute_name not in {"", "/"}:
                add_finding(findings, source_text, start_position, "attribute_strip", "low", f"Removed attribute {attribute_name} from <{tag_name}>.")
            continue
        # Perform deep validation on links and image sources
        if attribute_name in {"href", "src"}:
            safe_value, is_safe = validate_url(raw_value, attribute_name)
            if not is_safe:
                add_finding(findings, source_text, start_position, "dangerous_url", "critical", f"Replaced dangerous {attribute_name} value on <{tag_name}>.")
            kept.append(f'{attribute_name}="{html.escape(safe_value, quote=True)}"')
            continue
        # Escape the value and keep it
        kept.append(f'{attribute_name}="{html.escape(raw_value, quote=True)}"')
    # Return attributes as a string with a leading space if any exist
    return (" " + " ".join(kept)) if kept else ""


# Reconstruct the HTML by allowing only specific tags and their sanitized attributes
def rebuild_safe_html(text: str, safe_tags: dict, findings: list[dict]) -> str:
    def replacement_function(match: re.Match) -> str:
        tag_name = match.group("tag").lower()
        closing = bool(match.group("closing"))
        raw_attrs = match.group("attrs") or ""
        # If the tag itself isn't safe, strip it entirely
        if tag_name not in safe_tags:
            add_finding(findings, text, match.start(), "tag_strip", "low", f"Removed disallowed tag <{tag_name}>.")
            return ""
        # Preserve closing tags for allowed elements
        if closing:
            return f"</{tag_name}>"
        # Sanitize attributes for the opening tag
        safe_attrs = sanitize_allowed_attributes(tag_name, raw_attrs, findings, text, match.start(), safe_tags)
        # Rebuild the tag; handle self-closing vs standard tags
        if tag_name in SELF_CLOSING_TAGS:
            return f"<{tag_name}{safe_attrs}>"
        return f"<{tag_name}{safe_attrs}>"

    return TAG_PATTERN.sub(replacement_function, text)


# Aggressively remove all HTML tags and return unescaped plain text
def strip_all_tags(text: str) -> str:
    without_tags = re.sub(r"<[^>]+>", "", text)
    return html.unescape(without_tags)


# Calculate a numerical score representing the overall risk level of the input
def danger_score(findings: list[dict]) -> int:
    # Assign weights to different severity levels
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 2, "info": 1}
    # Sum weights and cap the total score at 100
    return min(sum(weights.get(item.get("severity", "info"), 1) for item in findings), 100)


# Main pipeline for cleaning HTML content
def sanitize_html(input_text: str, mode: str = "plain", allowed_tags: list[str] | None = None) -> tuple[str, list[dict], dict]:
    findings = []
    # Configure the allowlist based on default or user-provided tags
    safe_tags = DEFAULT_SAFE_TAGS.copy()
    if allowed_tags is not None:
        safe_tags = {tag: DEFAULT_SAFE_TAGS.get(tag, []) for tag in allowed_tags if tag}

    text = input_text
    # Decode entities first to reveal hidden tags or scripts (e.g., &lt;script&gt;)
    decoded = html.unescape(text)
    if decoded != text:
        findings.append({"severity": "low", "category": "entity_decode", "line": 1, "message": "Decoded HTML entities before scanning."})
        text = decoded
    # Null bytes are a common bypass technique; remove them immediately
    if "\x00" in text:
        findings.append({"severity": "medium", "category": "null_byte", "line": 1, "message": "Removed null bytes used for obfuscation."})
        text = text.replace("\x00", "")

    # Multi-pass cleaning to handle nested obfuscation (up to 5 loops)
    previous = None
    loop_count = 0
    while text != previous and loop_count < 5:
        previous = text
        loop_count += 1
        # Strip comments, scripts, styles, and other high-risk elements
        text = replace_pattern(text, COMMENT_PATTERN, "", findings, "comment", "low", "Removed HTML comment.")
        text = replace_pattern(text, SCRIPT_PATTERN, "", findings, "script_tag", "critical", "Removed script tag and contents.")
        text = replace_pattern(text, STYLE_PATTERN, "", findings, "style_block", "medium", "Removed style block.")
        text = replace_pattern(text, BLOCKED_TAGS_PATTERN, "", findings, "blocked_tag", "critical", "Removed blocked tag container.")
        text = replace_pattern(text, META_REFRESH_PATTERN, "", findings, "meta_refresh", "critical", "Removed meta refresh tag.")
        text = replace_pattern(
            text,
            EVENT_HANDLER_PATTERN,
            "",
            findings,
            "event_handler",
            "high",
            "Removed inline event handler: {content}",
        )

    # Return either sanitized HTML or clean plain text based on the requested mode
    if mode == "safe":
        output = rebuild_safe_html(text, safe_tags, findings)
    else:
        output = strip_all_tags(text)

    # Compile the final statistics for the operation
    stats = {
        "mode": mode,
        "before_characters": len(input_text),
        "after_characters": len(output),
        "characters_removed": max(len(input_text) - len(output), 0),
        "danger_score": danger_score(findings),
        "passes": loop_count,
    }
    return output, findings, stats


# Public entry point for the HTML sanitizer
def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    mode = config.get("mode", "plain")
    allowed_tags = config.get("allowed_tags")
    # Execute the sanitization logic
    output, findings, stats = sanitize_html(input_text, mode=mode, allowed_tags=allowed_tags)

    # Create a human-friendly summary of the threats found
    summary = (
        f"Sanitized HTML in {mode} mode. Removed {stats['characters_removed']} characters "
        f"with danger score {stats['danger_score']}."
    )

    # Return the full report structure
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


def _parse_allowed_tags(raw: str | None) -> list[str] | None:
    if raw is None or not raw.strip():
        return None
    return [t.strip().lower() for t in raw.split(",") if t.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strip dangerous HTML; optional allowlisted safe HTML mode.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", "-i", help="HTML string to sanitize")
    src.add_argument("--file", "-f", type=Path, help="Path to a .html or .txt file (UTF-8)")
    parser.add_argument("--mode", choices=("plain", "safe"), default="plain", help="plain = text only; safe = allowlisted tags")
    parser.add_argument("--allow", help="Comma-separated tag names for safe mode (replaces default allowlist)")
    parser.add_argument("--output", "-o", type=Path, help="Write cleaned output to this file (UTF-8)")
    parser.add_argument("--report", action="store_true", help="Print JSON findings and stats to stderr")
    parser.add_argument(
        "--show-diff",
        action="store_true",
        help="Print before/after character counts to stderr",
    )
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


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InputError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc