App: CLI HTML/Script Sanitizer

What it does: Takes a string containing HTML and strips all dangerous content: <script> tags, onclick attributes, JavaScript: URLs, CSSexpression() attacks, data URIs, and iframe injections. Preserves safe formatting tags (<p>, <b>, <i>, <a> with a validated href) if the user wants them, or strips everything to plain text.

Why it matters: This is security-focused validation. XSS prevention is one of the most practical applications of regex-based input cleansing. Key skills: RegEx for HTML tag matching (handling malformed tags, nested quotes, case variations), allowlist vs. blocklist strategy, URL validation within attributes, recursive stripping (tags inside tags). 

Standalone value: Paste any HTML and get safe, clean output. Essential for anyone handling user-generated content.

Mega-app role: dataguard/html_sanitizer.py — handles markup data in the pipeline.



Features:
CLI Interface
•	--input flag for a direct HTML string or --file flag for a .html/.txt file
•	--mode flag: plain strips all HTML to text, safe preserves the allowlist (default: plain)
•	--allow flag to customize which tags survive in safe mode (comma-separated list)
•	--output flag to write the cleaned result to a file
•	--report flag to print the full threat report showing everything that was removed
•	--show-diff flag to display a before/after character count comparison

Core Dangerous Content Removal
•	Script tag stripping — removes all <script> tags and contents, handles variations like mixed case, extra whitespace, and injected attributes
•	Event handler removal — strips all on* attributes: onclick, onload, onerror, onmouseover, and the full set of 60+ DOM events, case-insensitive
•	JavaScript URI stripping — removes javascript: in href, src, action, and all URL-bearing attributes, handles obfuscation like entity encoding, tab insertion, and mixed case
•	CSS expression removal — strips expression(), url(javascript:...), -moz-binding, and behavior: from style attributes and <style> blocks
•	Data URI blocking — removes data: URIs from src, href, and style properties
•	Iframe/object/embed removal — strips <iframe>, <object>, <embed>, <applet>, <form>, and <meta refresh> tags entirely
•	Base tag removal — strips <base> tags that could redirect relative URLs
•	Comment removal — strips HTML comments including conditional IE comments

Obfuscation & Bypass Detection
•	HTML entity decoding before scanning so &#x6A;avascript: payloads are caught
•	Null byte stripping to catch java\x00script: tricks
•	Nested tag detection via looping: strips until no more changes, catching <scr<script>ipt>
•	Attribute quote handling: double quotes, single quotes, no quotes, and backtick quotes
•	Whitespace normalization inside tag and attribute names before checking

Safe Tag Preservation (--mode safe)
•	Default allowlist: p, b, i, u, strong, em, br, hr, ul, ol, li, h1–h6, blockquote, pre, code, a (with validated href), img (with validated src)
•	--allow flag overrides the default list with a user-specified set
•	All attributes on allowed tags are stripped except explicitly permitted ones: href on <a>, src and alt on <img>
•	Tags not on the allowlist are removed but their text content is preserved

Link & URL Validation
•	href attributes validated: only http:, https:, and mailto: allowed
•	All other protocols (javascript:, data:, vbscript:) replaced with href="#removed"
•	src attributes on <img> validated the same way
•	URLs checked after full entity decoding

Threat Report
•	Every removal logged with: line number, threat type, severity (critical/high/medium/low), the raw content removed, and surrounding context
•	Severity: script tags and JS URIs as critical, event handlers as high, CSS expressions and data URIs as medium, comments as low
•	Danger score (0–100) based on weighted threat counts
•	Obfuscation attempts called out separately as evidence of intentional attack
•	Diff summary: Removed 3 script tags, 7 event handlers — 847 characters stripped (23%)

Output
•	Cleaned HTML or plain text printed to stdout or written to --output file
•	Report printed to stderr so it does not contaminate the cleaned output in piped commands

Student-Level Code Style
•	A main sanitize_html() function that runs: decode entities, strip comments, remove dangerous tags, clean attributes, validate URLs, loop for bypasses
•	Each step is its own function: remove_script_tags(), strip_event_handlers(), validate_href(), detect_obfuscation()
•	Allowlist stored as a plain dict: SAFE_TAGS = {"p": [], "a": ["href"], "img": ["src", "alt"]}
•	The bypass loop with a comment: # keep stripping until nothing changes — catches nested tricks
•	Uses only: re, html, argparse, sys, os
•	Comments like # a production sanitizer would use bleach — regex has limits but works for our use case


html_sanitizer.py
Serves as a security-focused "filter" designed to neutralize malicious or distracting web content. It is built to handle untrusted input that might contain tracking scripts, phishing redirects, or layout-breaking styles.
•	Multi-Pass Threat Neutralization: It runs up to five cleaning cycles to defeat "nested obfuscation," where an attacker hides a malicious tag inside an encoded one to bypass simple single-pass filters.

•	XSS & Redirect Prevention: It aggressively strips <script>, <iframe>, <object>, and <meta-refresh> tags, as well as inline JavaScript event handlers (like onclick).

•	URL Protocol Enforcement: It inspects every link (href) and image source (src), blocking dangerous protocols like javascript:, data:, or vbscript: while allowing safe ones like https:.

•	Granular Attribute Filtering: It uses a "Strict Allowlist" approach. Even if a tag is allowed (like <a>), any attribute not explicitly marked as safe (like id, class, or style) is removed to prevent CSS-based attacks.

•	Risk Assessment: It calculates a Danger Score ($0$ to $100$) based on the types of threats it found, allowing upstream systems to flag or block highly suspicious inputs automatically.

The Tech Stack

Technology	Role in the Project
Python 3.10+	Leverages advanced Regex flags and functional programming for the cleaning pipeline.
re (Regex)	Extensively uses re.DOTALL and re.IGNORECASE to catch threats regardless of how they are formatted or spaced.
html Module	Used for essential entity decoding (to find hidden threats) and safe escaping (to render the final output).
Functional Replacement	Uses re.sub() with a callback function to log specific findings while simultaneously removing them.

1. Defensive Decoding
By using HTML.unescape() at the very beginning, the stack reveals "cloaked" attacks. For example, an attacker might write < script> to bypass a simple filter; this tech stack decodes it to <script> first, so it can be identified and destroyed.

2. Non-Greedy Pattern Matching
The use of re.DOTALL combined with non-greedy qualifiers (.*?) ensures that the script removes the entire contents of a tag (like everything between <script> and </script>) even if it spans multiple lines. This prevents "leftover" malicious code from remaining in the output.

3. Multi-Quoting Robustness
HTML attributes can be wrapped in double quotes ("), single quotes ('), backticks (`), or no quotes at all. The ATTRIBUTE_PATTERN regex is specifically designed to capture the value correctly regardless of the quoting style, ensuring no bypasses are possible via unusual syntax.

4. Standardized Reporting
By decoupling the "Finding" logic from the "Cleaning" logic, the tech stack provides a detailed audit log. A user doesn't just get clean text; they get a report explaining why a certain URL was replaced with #removed, which is vital for debugging and security forensics.
