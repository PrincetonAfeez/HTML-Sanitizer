from __future__ import annotations


import argparse
import html
import json
import re
import sys
from pathlib import Path

from errors import InputError


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

META_REFRESH_PATTERN = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", re.IGNORECASE)

EVENT_HANDLER_PATTERN = re.compile(r"\s+on[a-z0-9_-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`|[^\s>]+)", re.IGNORECASE)

STYLE_DANGER_PATTERN = re.compile(
    r"expression\s*\(|url\s*\(\s*javascript:|url\s*\(\s*['\"]?data:|-moz-binding|behavior\s*:",
    re.IGNORECASE,
)

TAG_PATTERN = re.compile(r"<(?P<closing>/)?(?P<tag>[A-Za-z0-9]+)(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)

ATTRIBUTE_PATTERN = re.compile(
    r"([^\s=<>'\"`/]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`|([^\s>]+)))?",
    re.DOTALL,
)

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

def replace_pattern(text: str, pattern: re.Pattern, replacement: str, findings: list[dict], category: str, severity: str, message_template: str) -> str:
    def replacement_function(match: re.Match) -> str:
        # Log the specific content found (truncated for the report)
        add_finding(findings, text, match.start(), category, severity, message_template.format(content=match.group(0)[:80]))
        return replacement

    return pattern.sub(replacement_function, text)

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

def sanitize_allowed_attributes(tag_name: str, raw_attrs: str, findings: list[dict], source_text: str, start_position: int, safe_tags: dict) -> str:
    kept = []
    allowed_attributes = safe_tags.get(tag_name, [])
    for match in ATTRIBUTE_PATTERN.finditer(raw_attrs):
        attribute_name = match.group(1).lower()
        raw_value = next((group for group in match.groups()[1:] if group is not None), "")        if attribute_name.startswith("on"):
            add_finding(findings, source_text, start_position, "event_handler", "high", f"Removed event handler {attribute_name}.")
            continue
        if attribute_name == "style":
            if STYLE_DANGER_PATTERN.search(raw_value):
                add_finding(findings, source_text, start_position, "css_attack", "medium", "Removed dangerous inline style content.")
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

def strip_all_tags(text: str) -> str:
    without_tags = re.sub(r"<[^>]+>", "", text)
    return html.unescape(without_tags)












def main() -> None:
    pass
