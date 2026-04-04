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














def main() -> None:
    pass
