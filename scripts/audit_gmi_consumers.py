#!/usr/bin/env python3
"""One-time, static-only GMI consumer inventory for the two authorized public hosts."""

from __future__ import annotations

import csv
import hashlib
import http.client
import json
import posixpath
import re
import ssl
import sys
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "work" / "audit_data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

AUTHORIZED_HOSTS = {"www.rbcis.com", "apps.rbcits.com"}
KNOWN_DENIED_PREFIXES = {
    "www.rbcis.com": ("/assets/rbcits/docs/gmi/entitlements",),
}
SEEDS = {
    "www.rbcis.com": [
        "https://www.rbcis.com/",
        "https://www.rbcis.com/en/",
        "https://www.rbcis.com/fr/",
        "https://www.rbcis.com/en/gmi/global-custody/market-newsflash.page",
    ],
    "apps.rbcits.com": [
        "https://apps.rbcits.com/",
        "https://apps.rbcits.com/gmi/drip/",
    ],
}
# Only sitemaps declared by live robots.txt are used automatically. The known apps
# sitemap is a legacy rbcits.com export and is retained in the prior coverage log.
SITEMAPS: dict[str, str] = {}

USER_AGENT = "RBCIS-GMI-Audit/1.0 security-review"
REQUEST_INTERVAL_SECONDS = 1.0
MAX_RESPONSE_BYTES = 12 * 1024 * 1024
TRACKING_KEYS = {
    "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid"
}
BINARY_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".csv", ".doc", ".docx", ".eot", ".exe", ".gif",
    ".gz", ".ico", ".jpeg", ".jpg", ".json", ".m4a", ".mov", ".mp3", ".mp4",
    ".otf", ".pdf", ".png", ".ppt", ".pptx", ".rar", ".rss", ".svg", ".tar",
    ".tgz", ".tif", ".tiff", ".ttf", ".txt", ".wav", ".webm", ".webp", ".woff",
    ".woff2", ".xls", ".xlsx", ".xml", ".zip",
}


class LinkScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[tuple[int, str]] = []
        self.base_href: str | None = None
        self.script_preloads: list[str] = []
        self._in_script = False
        self._script_src: str | None = None
        self._script_line = 0
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v for k, v in attrs}
        if tag.lower() in {"a", "area"} and values.get("href"):
            self.links.append(values["href"] or "")
        if tag.lower() in {"iframe", "frame"} and values.get("src"):
            self.links.append(values["src"] or "")
        if tag.lower() == "form" and values.get("action"):
            self.links.append(values["action"] or "")
        if values.get("formaction"):
            self.links.append(values["formaction"] or "")
        for navigation_attr in ("data-href", "data-url"):
            if values.get(navigation_attr):
                self.links.append(values[navigation_attr] or "")
        if tag.lower() == "base" and values.get("href") and self.base_href is None:
            self.base_href = values["href"]
        if tag.lower() == "link" and values.get("href"):
            rel = (values.get("rel") or "").lower().split()
            if any(item in rel for item in ("alternate", "canonical")):
                self.links.append(values["href"] or "")
            if "modulepreload" in rel or ("preload" in rel and (values.get("as") or "").lower() == "script"):
                self.script_preloads.append(values["href"] or "")
        if tag.lower() == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            refresh = values.get("content") or ""
            target = re.search(r"(?i)(?:^|;)\s*url\s*=\s*['\"]?([^'\";]+)", refresh)
            if target:
                self.links.append(target.group(1).strip())
        if tag.lower() == "script":
            self._in_script = True
            self._script_src = values.get("src")
            self._script_line = self.getpos()[0]
            self._script_chunks = []
            if self._script_src:
                self.scripts.append(self._script_src)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            if not self._script_src:
                body = "".join(self._script_chunks)
                if body.strip():
                    self.inline_scripts.append((self._script_line, body))
            self._in_script = False
            self._script_src = None
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_script and not self._script_src:
            self._script_chunks.append(data)


@dataclass
class Coverage:
    host: str
    url: str
    resource_type: str
    status: str
    content_type: str
    outcome: str
    discovered_from: str
    notes: str


@dataclass
class ScriptOccurrence:
    page_url: str
    source_url: str
    source_kind: str
    start_line: int
    text: str
    origin_detail: str = ""


@dataclass
class Finding:
    finding_id: str
    domain: str
    page_url: str
    js_source: str
    line: int
    endpoint_expression: str
    http_method: str
    execution_side: str
    page_access: str
    api_auth_type: str
    call_mechanism: str
    confidence: str
    summary: str


def canonicalize(raw: str, base: str | None = None) -> str | None:
    try:
        value = urljoin(base or "", raw.strip())
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.lower()
    if (parts.scheme.lower() == "https" and port == 443) or (parts.scheme.lower() == "http" and port == 80):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    path = re.sub(
        r"%([0-9A-Fa-f]{2})",
        lambda match: chr(int(match.group(1), 16)) if chr(int(match.group(1), 16)) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" else "%" + match.group(1).upper(),
        path,
    )
    path = quote(path, safe="/%:@!$&'()*+,;=-._~")
    pairs = []
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        lower = key.lower()
        if lower.startswith("utm_") or lower in TRACKING_KEYS:
            continue
        pairs.append((key, val))
    query = urlencode(pairs, doseq=True)
    return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))


def is_probable_page(url: str) -> bool:
    path = urlsplit(url).path.lower()
    extension = Path(path).suffix
    return extension not in BINARY_EXTENSIONS and extension not in {".css", ".js", ".map"}


SENSITIVE_QUERY_KEYS = re.compile(r"(?i)^(?:access_token|token|id_token|api_?key|client_secret|code|sig|signature|auth|authorization|password|passwd|secret|jwt|session|sessionid|samlresponse)$")


def is_known_denied(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        decoded = unquote(parts.path)
        if re.search(r"(?i)%2f|%5c", parts.path):
            decoded = unquote(decoded)
        policy_path = posixpath.normpath("/" + decoded.lstrip("/"))
        for prefix in KNOWN_DENIED_PREFIXES.get(host, ()):
            normalized_prefix = posixpath.normpath(prefix)
            if policy_path == normalized_prefix or policy_path.startswith(normalized_prefix + "/"):
                return True
    except ValueError:
        return False
    return False


def sanitize_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        query = []
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.match(key) else val))
        return urlunsplit((parts.scheme, host, parts.path, urlencode(query, doseq=True), parts.fragment))
    except ValueError:
        return value


def redact_auth(text: str) -> str:
    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*['\"]?\s*(?:basic|bearer)\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(['\"]authorization['\"]\s*:\s*['\"](?:basic|bearer)\s+)[^'\"]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)(['\"]?(?:x-api-key|cookie|set-cookie|client_secret|access_token|id_token|password|passwd|secret|jwt|sessionid|samlresponse)['\"]?\s*[:=]\s*['\"]?)[^'\"\s,;}]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:access_token|token|id_token|api_?key|client_secret|code|sig|signature|password|passwd|secret|jwt|session|sessionid|samlresponse)=)[^&#'\"\s]+", r"\1[REDACTED]", text)
    return text


def sanitize_expression(text: str) -> str:
    value = redact_auth(text)
    absolute_url = re.compile(r"https?://[^\s'\"`<>]+", re.I)
    return absolute_url.sub(lambda match: sanitize_url(match.group(0)), value)


class Fetcher:
    def __init__(self) -> None:
        self.last_request: dict[str, float] = defaultdict(lambda: 0.0)
        self.ssl_context = ssl.create_default_context()

    def get(self, url: str, redirect_hosts: set[str] | None = None) -> tuple[int, str, str, str]:
        host = (urlsplit(url).hostname or "").lower()
        delay = REQUEST_INTERVAL_SECONDS - (time.monotonic() - self.last_request[host])
        if delay > 0:
            time.sleep(delay)
        req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,text/javascript,*/*;q=0.5"})
        opener = build_opener(ScopedRedirectHandler(redirect_hosts))
        try:
            with opener.open(req, timeout=25) as response:
                self.last_request[host] = time.monotonic()
                status = int(response.status)
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                final_url = response.geturl()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError(f"response exceeds {MAX_RESPONSE_BYTES} bytes")
                charset = response.headers.get_content_charset() or "utf-8"
                return status, content_type, final_url, raw.decode(charset, errors="replace")
        except HTTPError as exc:
            self.last_request[host] = time.monotonic()
            return int(exc.code), exc.headers.get_content_type() if exc.headers else "", exc.geturl(), ""
        except OutOfScopeRedirect as exc:
            self.last_request[host] = time.monotonic()
            return 399, "", exc.target, ""


class OutOfScopeRedirect(Exception):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self.target = target


class ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str] | None) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parts = urlsplit(newurl)
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError:
            raise OutOfScopeRedirect(newurl)
        if self.allowed_hosts is not None and (host not in self.allowed_hosts or parts.scheme.lower() != "https" or port not in {None, 443}):
            raise OutOfScopeRedirect(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


GMI_MARKER = re.compile(r"(?i)(?:https?://[^\s'\"`]+)?/(?:gmiservice|gmi-api|gmiapi)(?:/[^\s'\"`<>)\]}]*)?|\bgmi(?:service|api)\b")
GMI_PATH_LOOSE = re.compile(r"(?i)['\"`]([^'\"`]*(?:/gmi/|gmiservice)[^'\"`]*)['\"`]")
IMPORT_RE = re.compile(r"(?m)(?:\b(?:import|export)\s*(?:[^'\"\n]*?from\s*)?|\bimport\s*\(|\brequire\s*\(|\bimportScripts\s*\()\s*['\"]([^'\"]+(?:\.m?js)?(?:\?[^'\"]*)?)['\"]")
SCRIPT_LITERAL_RE = re.compile(r"['\"`]([^'\"`\s<>]+\.m?js(?:\?[^'\"`<>]*)?)['\"`]", re.I)
SOURCE_MAP_RE = re.compile(r"(?m)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)")
CALL_HEAD_RE = re.compile(
    r"(?i)(?P<head>\$\s*\.\s*(?:ajax|getJSON|get|post)|jQuery\s*\.\s*(?:ajax|getJSON|get|post)|"
    r"(?:window\s*\.\s*)?fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete|head|options|request))?|"
    r"\$http(?:\s*\.\s*(?:get|post|put|patch|delete|head|jsonp))?|navigator\s*\.\s*sendBeacon|"
    r"[A-Za-z_$][\w$]*\s*\.\s*open)\s*\("
)
ASSIGN_RE = re.compile(r"(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,2000})")


def extract_balanced_call(text: str, open_index: int, limit: int = 12000) -> tuple[str, int]:
    depth = 0
    quote = ""
    escaped = False
    end_limit = min(len(text), open_index + limit)
    for index in range(open_index, end_limit):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index:index + 1], index + 1
    return text[open_index:end_limit], end_limit


def split_top_level(value: str, delimiter: str = ",") -> list[str]:
    result: list[str] = []
    start = 0
    quote = ""
    escaped = False
    depths = {"(": 0, "[": 0, "{": 0}
    closers = {")": "(", "]": "[", "}": "{"}
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in depths:
            depths[char] += 1
        elif char in closers:
            depths[closers[char]] = max(0, depths[closers[char]] - 1)
        elif char == delimiter and not any(depths.values()):
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return result


def top_level_property(obj: str, names: set[str]) -> str | None:
    body = obj.strip()
    if not body.startswith("{"):
        return None
    body = body[1:-1] if body.endswith("}") else body[1:]
    for item in split_top_level(body):
        match = re.match(r"(?is)^\s*['\"]?([A-Za-z_$][\w$-]*)['\"]?\s*:\s*(.+)$", item)
        if match and match.group(1).lower() in names:
            return match.group(2).strip()
    return None


def split_plus(expr: str) -> list[str]:
    return split_top_level(expr, "+")


def decode_literal(part: str) -> str | None:
    part = part.strip()
    if len(part) >= 2 and part[0] == part[-1] and part[0] in "'\"":
        inner = part[1:-1]
        return re.sub(r"\\([\\/'\"`])", r"\1", inner)
    if len(part) >= 2 and part[0] == part[-1] == "`":
        return re.sub(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}", r"${\1}", part[1:-1])
    return None


def resolve_expr(expr: str, symbols: dict[str, str], depth: int = 0) -> str:
    expr = expr.strip()
    if depth > 6:
        return expr
    if re.fullmatch(r"[A-Za-z_$][\w$]*", expr) and expr in symbols:
        return resolve_expr(symbols[expr], symbols, depth + 1)
    parts = split_plus(expr)
    if len(parts) > 1:
        resolved_parts = []
        for part in parts:
            resolved = resolve_expr(part, symbols, depth + 1)
            if resolved == part.strip() and re.fullmatch(r"[A-Za-z_$][\w$]*", part.strip()):
                resolved = "${" + part.strip() + "}"
            resolved_parts.append(resolved)
        return "".join(resolved_parts)
    literal = decode_literal(expr)
    if literal is not None:
        return literal
    return expr


def find_endpoint_for_call(head: str, args: list[str], symbols: dict[str, str]) -> tuple[str, str, str]:
    normalized = re.sub(r"\s+", "", head).lower()
    method = "GET"
    raw = ""
    mechanism = head.strip()
    if normalized.endswith(".open"):
        mechanism = "XMLHttpRequest.open"
        method = resolve_expr(args[0], symbols).strip("'\"").upper() if args else "UNKNOWN"
        raw = args[1] if len(args) > 1 else ""
    elif "sendbeacon" in normalized:
        mechanism = "navigator.sendBeacon"
        method = "POST"
        raw = args[0] if args else ""
    elif "fetch" in normalized:
        mechanism = "fetch"
        raw = args[0] if args else ""
        if len(args) > 1:
            method_expr = top_level_property(args[1], {"method"})
            if method_expr:
                method = resolve_expr(method_expr, symbols).strip("'\"").upper()
    elif normalized.startswith("axios"):
        mechanism = "axios"
        verb = normalized.rsplit(".", 1)[-1] if "." in normalized else ""
        if verb in {"get", "post", "put", "patch", "delete", "head", "options"}:
            method = verb.upper()
            raw = args[0] if args else ""
        else:
            config = args[0] if args else ""
            if config and not config.lstrip().startswith("{"):
                config = resolve_expr(config, symbols)
            raw = top_level_property(config, {"url", "uri", "endpoint"}) or ""
            method_expr = top_level_property(config, {"method"})
            method = resolve_expr(method_expr, symbols).strip("'\"").upper() if method_expr else "GET"
    elif normalized.startswith("$http"):
        mechanism = "Angular $http"
        verb = normalized.rsplit(".", 1)[-1] if "." in normalized else ""
        if verb in {"get", "post", "put", "patch", "delete", "head", "jsonp"}:
            method = "GET" if verb == "jsonp" else verb.upper()
            raw = args[0] if args else ""
        else:
            config = args[0] if args else ""
            if config and not config.lstrip().startswith("{"):
                config = resolve_expr(config, symbols)
            raw = top_level_property(config, {"url", "uri", "endpoint"}) or ""
            method_expr = top_level_property(config, {"method"})
            method = resolve_expr(method_expr, symbols).strip("'\"").upper() if method_expr else "GET"
    else:
        verb = normalized.rsplit(".", 1)[-1]
        mechanism = "jQuery.ajax" if verb == "ajax" else "jQuery shorthand"
        if verb in {"post"}:
            method = "POST"
        config = resolve_expr(args[0], symbols) if args else ""
        if verb == "ajax" and config.lstrip().startswith("{"):
            raw = top_level_property(config, {"url", "uri", "endpoint"}) or ""
            method_expr = top_level_property(config, {"method", "type"})
            method = resolve_expr(method_expr, symbols).strip("'\"").upper() if method_expr else "GET"
        else:
            raw = args[0] if args else ""
    return mechanism, method, raw


def detect_auth(fragment: str) -> str:
    xhr_auth = re.search(r"(?is)setRequestHeader\s*\(\s*['\"]authorization['\"]\s*,\s*([^\)]{1,300})", fragment)
    if xhr_auth:
        value = xhr_auth.group(1).strip()
        if re.search(r"(?i)['\"]\s*basic\s+[^'\"]+['\"]", value):
            return "Client-embedded credential (Basic)"
        if re.search(r"(?i)['\"]\s*bearer\s+[^'\"]+['\"]", value):
            return "Client-embedded credential (Bearer)"
        return "Dynamic/client-supplied authorization"
    auth = re.search(r"(?is)authorization\s*['\"]?\s*[:=]\s*([^,}\n]{1,300})", fragment)
    if auth:
        value = auth.group(1).strip()
        if re.search(r"(?i)['\"]\s*basic\s+[^'\"]+['\"]", value):
            return "Client-embedded credential (Basic)"
        if re.search(r"(?i)['\"]\s*bearer\s+[^'\"]+['\"]", value):
            return "Client-embedded credential (Bearer)"
        return "Dynamic/client-supplied authorization"
    if re.search(r"(?i)(credentials\s*:\s*['\"]include['\"]|withCredentials\s*[:=]\s*true)", fragment):
        return "Session-cookie/credentialed request"
    return "No explicit auth observed (cookies may still apply)"


def scan_occurrence(occ: ScriptOccurrence) -> tuple[list[Finding], list[dict[str, str]]]:
    findings: list[Finding] = []
    candidates: list[dict[str, str]] = []
    claimed_spans: list[tuple[int, int]] = []
    text = occ.text
    symbols = {name: value for name, value in ASSIGN_RE.findall(text)}
    for match in CALL_HEAD_RE.finditer(text):
            open_index = match.end() - 1
            call_body, call_end = extract_balanced_call(text, open_index)
            fragment = text[match.start():call_end]
            args = split_top_level(call_body[1:-1])
            mechanism, method, raw_endpoint = find_endpoint_for_call(match.group("head"), args, symbols)
            resolved_endpoint = resolve_expr(raw_endpoint, symbols) if raw_endpoint else ""
            if not GMI_MARKER.search(resolved_endpoint) and not GMI_MARKER.search(raw_endpoint):
                continue
            claimed_spans.append((match.start(), call_end))
            endpoint = redact_auth(resolved_endpoint or raw_endpoint or "Unresolved GMI expression")[:1000]
            raw_display = redact_auth(raw_endpoint)[:500]
            if raw_display and endpoint != raw_display and "${" in endpoint:
                endpoint = f"{endpoint} [expression: {raw_display}]"[:1000]
            line = occ.start_line + text.count("\n", 0, match.start())
            confidence = "Confirmed source occurrence" if endpoint != "Unresolved GMI expression" else "Probable"
            context = text[max(0, match.start() - 800):min(len(text), call_end + 800)]
            auth = detect_auth(context)
            summary = (
                f"Page statically includes a {mechanism} call to {endpoint}. "
                f"Authentication: {auth}; runtime execution not asserted."
            )
            if occ.origin_detail:
                summary += f" Detected through public source map: {occ.origin_detail}."
            raw_id = "|".join([occ.page_url, occ.source_url, str(line), endpoint, mechanism])
            findings.append(Finding(
                finding_id=hashlib.sha256(raw_id.encode()).hexdigest()[:12].upper(),
                domain=(urlsplit(occ.page_url).hostname or "").lower(),
                page_url=occ.page_url,
                js_source=occ.source_url,
                line=line,
                endpoint_expression=endpoint,
                http_method=method,
                execution_side="Client",
                page_access="Public",
                api_auth_type=auth,
                call_mechanism=mechanism,
                confidence=confidence,
                summary=summary,
            ))

    for marker in GMI_MARKER.finditer(text):
        if any(start <= marker.start() < end for start, end in claimed_spans):
            continue
        left = max(0, marker.start() - 400)
        right = min(len(text), marker.end() + 700)
        context = redact_auth(text[left:right])
        line = occ.start_line + text.count("\n", 0, marker.start())
        candidates.append({
            "domain": (urlsplit(occ.page_url).hostname or "").lower(),
            "page_url": occ.page_url,
            "js_source": occ.source_url,
            "line": str(line),
            "marker": redact_auth(marker.group(0))[:500],
            "reason": "GMI-like reference not tied to a recognized request sink",
            "context_sha256": hashlib.sha256(context.encode()).hexdigest(),
        })
    return findings, candidates


def source_map_occurrences(page_url: str, map_url: str, text: str) -> Iterable[ScriptOccurrence]:
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return []
        sources = payload.get("sources") or []
        contents = payload.get("sourcesContent") or []
        if not isinstance(sources, list) or not isinstance(contents, list):
            return []
    except (json.JSONDecodeError, TypeError, AttributeError, KeyError):
        return []
    result = []
    for idx, body in enumerate(contents):
        if not isinstance(body, str) or not body.strip():
            continue
        source_name = sources[idx] if idx < len(sources) else f"source-{idx}"
        result.append(ScriptOccurrence(page_url, f"{map_url}#{source_name}", "source-map", 1, body))
    return result


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    fetcher = Fetcher()
    coverage: list[Coverage] = []
    occurrences: list[ScriptOccurrence] = []
    page_queue: deque[tuple[str, str]] = deque()
    legacy_queue: deque[tuple[str, str]] = deque()
    queued_pages: set[str] = set()
    visited_pages: set[str] = set()
    visited_final_pages: set[str] = set()
    halted_hosts: set[str] = set()
    script_pages: dict[str, set[str]] = defaultdict(set)
    script_discovered_from: dict[str, str] = {}
    denied_recorded: set[str] = set()

    def enqueue_page(raw: str, base: str, discovered_from: str) -> None:
        decoded_raw = unquote(raw)
        if re.search(r"[\r\n]\s*https?:[/\\]", decoded_raw, re.I):
            return
        url = canonicalize(raw, base)
        if not url or (urlsplit(url).hostname or "").lower() not in AUTHORIZED_HOSTS:
            return
        parts = urlsplit(url)
        if parts.port not in {None, 443}:
            return
        if parts.scheme == "http":
            url = urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))
            parts = urlsplit(url)
        if not is_probable_page(url) or url in queued_pages or url in visited_pages:
            return
        queued_pages.add(url)
        target_queue = legacy_queue if discovered_from == "legacy sitemap path" else page_queue
        target_queue.append((url, discovered_from))

    for host, seeds in SEEDS.items():
        for seed in seeds:
            enqueue_page(seed, seed, "seed")

    prior_sources = [
        ROOT / "data" / "coverage-log.csv",
        DATA_DIR / "crawl_checkpoint.csv",
    ]
    for prior_coverage in prior_sources:
        if not prior_coverage.exists():
            continue
        with prior_coverage.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("resource_type") == "page" and row.get("status") == "200":
                    enqueue_page(row.get("url", ""), row.get("url", ""), "prior successful public page")

    # Robots and sitemaps are supplementary discovery sources; the link crawl remains primary.
    sitemap_queue: deque[tuple[str, str, str]] = deque()
    seen_sitemaps: set[str] = set()
    for host in sorted(AUTHORIZED_HOSTS):
        robots_url = f"https://{host}/robots.txt"
        try:
            status, content_type, final_url, body = fetcher.get(robots_url, AUTHORIZED_HOSTS)
            coverage.append(Coverage(host, robots_url, "robots", str(status), content_type, "fetched" if status == 200 else "excluded", "seed", "candidate source only"))
            if status == 200:
                for line in body.splitlines():
                    key, separator, value = line.partition(":")
                    value = value.strip()
                    if not separator or not value:
                        continue
                    if key.strip().lower() == "sitemap":
                        sitemap_url = canonicalize(value, robots_url)
                        if sitemap_url and (urlsplit(sitemap_url).hostname or "").lower() in AUTHORIZED_HOSTS:
                            sitemap_queue.append((host, sitemap_url, robots_url))
                    elif key.strip().lower() in {"allow", "disallow"} and is_probable_page(canonicalize(value, robots_url) or ""):
                        enqueue_page(value, robots_url, robots_url)
        except Exception as exc:
            coverage.append(Coverage(host, robots_url, "robots", "ERROR", "", "failed", "seed", str(exc)[:500]))
    for host, sitemap in SITEMAPS.items():
        sitemap_queue.append((host, sitemap, "seed"))
    while sitemap_queue:
        host, sitemap, discovered_from = sitemap_queue.popleft()
        sitemap = canonicalize(sitemap) or sitemap
        if sitemap in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap)
        try:
            status, content_type, final_url, body = fetcher.get(sitemap, AUTHORIZED_HOSTS)
            coverage.append(Coverage(host, sitemap, "sitemap", str(status), content_type, "fetched" if status == 200 else "excluded", discovered_from, "candidate source only"))
            if status != 200:
                continue
            root = ElementTree.fromstring(body)
            for loc in root.findall(".//{*}loc"):
                if not loc.text:
                    continue
                raw_candidate = loc.text.strip()
                candidate_parts = urlsplit(raw_candidate)
                candidate_host = (candidate_parts.hostname or "").lower()
                if candidate_host not in AUTHORIZED_HOSTS:
                    raw_candidate = urlunsplit(("https", host, candidate_parts.path or "/", candidate_parts.query, ""))
                candidate = canonicalize(raw_candidate, final_url)
                if not candidate:
                    continue
                if urlsplit(candidate).path.lower().endswith(".xml"):
                    sitemap_queue.append(((urlsplit(candidate).hostname or host).lower(), candidate, sitemap))
                else:
                    enqueue_page(candidate, final_url, "sitemap path")
        except Exception as exc:
            coverage.append(Coverage(host, sitemap, "sitemap", "ERROR", "", "failed", discovered_from, str(exc)[:500]))

    processed = 0
    attempted = 0
    while page_queue or legacy_queue:
        active_queue = page_queue if page_queue else legacy_queue
        url, discovered_from = active_queue.popleft()
        queued_pages.discard(url)
        host = (urlsplit(url).hostname or "").lower()
        if url in visited_pages:
            continue
        visited_pages.add(url)
        attempted += 1
        if attempted % 25 == 0:
            checkpoint_rows = [asdict(item) for item in coverage]
            write_csv(DATA_DIR / "crawl_checkpoint.csv", checkpoint_rows, list(asdict(Coverage("", "", "", "", "", "", "", "")).keys()))
            print(f"attempted={attempted} pages={processed} fresh_queue={len(page_queue)} legacy_queue={len(legacy_queue)} scripts={len(script_pages)} current={sanitize_url(url)[:180]}", flush=True)
        try:
            status, content_type, final_url, body = fetcher.get(url, AUTHORIZED_HOSTS)
        except Exception as exc:
            coverage.append(Coverage(host, url, "page", "ERROR", "", "failed", discovered_from, str(exc)[:500]))
            continue
        final_canonical = canonicalize(final_url) or url
        if status == 399:
            coverage.append(Coverage(host, url, "page", "BLOCKED_REDIRECT", content_type, "excluded", discovered_from, f"redirect target outside exact HTTPS/default-port scope: {final_canonical}"))
            continue
        if status in {403, 429}:
            coverage.append(Coverage(host, url, "page", str(status), content_type, "excluded", discovered_from, "individual inaccessible/rate-limited URL skipped; crawl continued"))
            continue
        if status < 200 or status >= 300:
            coverage.append(Coverage(host, url, "page", str(status), content_type, "excluded", discovered_from, "non-2xx"))
            continue
        if "html" not in content_type and not re.search(r"(?is)<html\b|<!doctype\s+html", body[:2000]):
            coverage.append(Coverage(host, url, "page", str(status), content_type, "excluded", discovered_from, "not HTML"))
            continue
        final_host = (urlsplit(final_canonical).hostname or "").lower()
        if final_host not in AUTHORIZED_HOSTS:
            coverage.append(Coverage(host, url, "page", str(status), content_type, "excluded", discovered_from, f"redirected out of scope to {final_canonical}"))
            continue
        if final_canonical in visited_final_pages:
            coverage.append(Coverage(final_host, url, "page", str(status), content_type, "deduplicated", discovered_from, f"same final page as {final_canonical}"))
            continue
        visited_final_pages.add(final_canonical)

        parser = LinkScriptParser()
        try:
            parser.feed(body)
        except Exception as exc:
            coverage.append(Coverage(host, final_canonical, "page", str(status), content_type, "partial", discovered_from, f"HTML parse warning: {exc}"))
        else:
            coverage.append(Coverage(host, final_canonical, "page", str(status), content_type, "scanned", discovered_from, f"{len(parser.scripts)} external scripts; {len(parser.inline_scripts)} inline blocks"))
        resolution_base = canonicalize(parser.base_href, final_canonical) if parser.base_href else final_canonical
        resolution_base = resolution_base or final_canonical
        for href in parser.links:
            enqueue_page(href, resolution_base, final_canonical)
        for src in parser.scripts + parser.script_preloads:
            script_url = canonicalize(src, resolution_base)
            if not script_url:
                continue
            script_pages[script_url].add(final_canonical)
            script_discovered_from.setdefault(script_url, final_canonical)
        for block_index, (start_line, inline) in enumerate(parser.inline_scripts, start=1):
            occurrences.append(ScriptOccurrence(final_canonical, f"INLINE:{final_canonical}#block-{block_index}@L{start_line}", "inline", start_line, inline))
        processed += 1

    # Fetch scripts. Static imports and source maps are appended until fixpoint.
    script_queue: deque[str] = deque(script_pages.keys())
    fetched_scripts: set[str] = set()
    script_bodies: dict[str, str] = {}
    import_graph: dict[str, set[str]] = defaultdict(set)
    source_map_texts: dict[str, list[tuple[str, str]]] = defaultdict(list)
    script_count = 0
    while script_queue:
        script_url = script_queue.popleft()
        if script_url in fetched_scripts:
            continue
        fetched_scripts.add(script_url)
        pages = sorted(script_pages[script_url])
        try:
            status, content_type, final_url, body = fetcher.get(script_url)
        except Exception as exc:
            coverage.append(Coverage((urlsplit(script_url).hostname or "").lower(), script_url, "script", "ERROR", "", "failed", script_discovered_from.get(script_url, ""), str(exc)[:500]))
            continue
        if status in {403, 429}:
            coverage.append(Coverage((urlsplit(script_url).hostname or "").lower(), script_url, "script", str(status), content_type, "asset host halted", script_discovered_from.get(script_url, ""), "safety stop for this asset"))
            continue
        if status < 200 or status >= 300:
            coverage.append(Coverage((urlsplit(script_url).hostname or "").lower(), script_url, "script", str(status), content_type, "excluded", script_discovered_from.get(script_url, ""), "non-2xx"))
            continue
        if content_type and not any(marker in content_type for marker in ("javascript", "ecmascript", "text/plain", "application/octet-stream")) and not final_url.lower().split("?", 1)[0].endswith((".js", ".mjs")):
            coverage.append(Coverage((urlsplit(script_url).hostname or "").lower(), script_url, "script", str(status), content_type, "excluded", script_discovered_from.get(script_url, ""), "response not JavaScript"))
            continue
        coverage.append(Coverage((urlsplit(script_url).hostname or "").lower(), script_url, "script", str(status), content_type, "scanned", script_discovered_from.get(script_url, ""), f"referenced by {len(pages)} page(s)"))
        script_bodies[script_url] = body
        script_references = set(IMPORT_RE.findall(body)) | set(SCRIPT_LITERAL_RE.findall(body))
        for imported in script_references:
            if not imported.startswith((".", "/", "http://", "https://", "//")):
                continue
            imported_url = canonicalize(imported, final_url)
            if not imported_url:
                continue
            import_graph[script_url].add(imported_url)
            script_pages.setdefault(imported_url, set())
            script_discovered_from.setdefault(imported_url, script_url)
            if imported_url not in fetched_scripts:
                script_queue.append(imported_url)
        for map_ref in SOURCE_MAP_RE.findall(body):
            map_url = canonicalize(map_ref, final_url)
            if not map_url:
                continue
            try:
                map_status, map_type, map_final, map_body = fetcher.get(map_url)
            except Exception as exc:
                coverage.append(Coverage((urlsplit(map_url).hostname or "").lower(), map_url, "source-map", "ERROR", "", "failed", script_url, str(exc)[:500]))
                continue
            coverage.append(Coverage((urlsplit(map_url).hostname or "").lower(), map_url, "source-map", str(map_status), map_type, "scanned" if map_status == 200 else "excluded", script_url, "public source map"))
            if map_status == 200:
                mapped = list(source_map_occurrences("", map_url, map_body))
                if mapped:
                    source_map_texts[script_url].extend((item.source_url, item.text) for item in mapped)
                else:
                    coverage.append(Coverage((urlsplit(map_url).hostname or "").lower(), map_url, "source-map", str(map_status), map_type, "partial", script_url, "map has no inspectable sourcesContent"))
        script_count += 1
        if script_count % 25 == 0:
            print(f"scripts={script_count} queued_scripts={len(script_queue)}", flush=True)

    # Propagate page attribution through the complete import graph, independent of fetch order.
    changed = True
    while changed:
        changed = False
        for parent, children in import_graph.items():
            parent_pages = script_pages.get(parent, set())
            for child in children:
                before = len(script_pages[child])
                script_pages[child].update(parent_pages)
                changed = changed or len(script_pages[child]) != before
    for script_url, body in script_bodies.items():
        for page_url in sorted(script_pages.get(script_url, set())):
            occurrences.append(ScriptOccurrence(page_url, script_url, "external", 1, body))
            for original_source, mapped_text in source_map_texts.get(script_url, []):
                occurrences.append(ScriptOccurrence(page_url, script_url, "source-map", 1, mapped_text, original_source))

    all_findings: list[Finding] = []
    all_candidates: list[dict[str, str]] = []
    for occurrence in occurrences:
        findings, candidates = scan_occurrence(occurrence)
        all_findings.extend(findings)
        all_candidates.extend(candidates)

    # Agreed output grain: one row per page URL + loaded JS/inline block + endpoint.
    unique_findings: dict[tuple, Finding] = {}
    for finding in all_findings:
        key = (
            finding.domain, finding.page_url, finding.js_source, finding.endpoint_expression,
        )
        existing = unique_findings.get(key)
        if existing is None:
            unique_findings[key] = finding
            continue
        existing.line = min(existing.line, finding.line)
        existing.http_method = ", ".join(sorted(set(existing.http_method.split(", ")) | set(finding.http_method.split(", "))))
        existing.call_mechanism = ", ".join(sorted(set(existing.call_mechanism.split(", ")) | set(finding.call_mechanism.split(", "))))
        existing.api_auth_type = ", ".join(sorted(set(existing.api_auth_type.split(", ")) | set(finding.api_auth_type.split(", "))))
        existing.summary = (
            f"Page statically includes {existing.call_mechanism} call(s) to {existing.endpoint_expression}. "
            f"Authentication: {existing.api_auth_type}; runtime execution not asserted."
        )
    findings = sorted(unique_findings.values(), key=lambda f: (f.domain, f.page_url, f.js_source, f.line, f.endpoint_expression))

    unique_candidates: dict[tuple, dict[str, str]] = {}
    for candidate in all_candidates:
        key = (candidate["domain"], candidate["page_url"], candidate["js_source"], candidate["line"], candidate["marker"])
        unique_candidates[key] = candidate
    candidates = sorted(unique_candidates.values(), key=lambda row: (row["domain"], row["page_url"], row["js_source"], int(row["line"])))

    finding_rows = [asdict(item) for item in findings]
    coverage_rows = [asdict(item) for item in coverage]
    for row in finding_rows:
        row["page_url"] = sanitize_url(redact_auth(row["page_url"]))
        if not row["js_source"].startswith("INLINE:"):
            row["js_source"] = sanitize_url(redact_auth(row["js_source"]))
        else:
            inline_value = row["js_source"][len("INLINE:"):]
            inline_url, separator, suffix = inline_value.partition("#")
            row["js_source"] = "INLINE:" + sanitize_url(redact_auth(inline_url)) + (separator + suffix if separator else "")
        row["endpoint_expression"] = sanitize_expression(row["endpoint_expression"])
        row["summary"] = sanitize_expression(row["summary"])
        stable_tuple = "|".join([row["domain"], row["page_url"], row["js_source"], row["endpoint_expression"]])
        row["finding_id"] = hashlib.sha256(stable_tuple.encode()).hexdigest()[:12].upper()
    sanitized_findings: dict[tuple[str, str, str, str], dict] = {}
    for row in finding_rows:
        key = (row["domain"], row["page_url"], row["js_source"], row["endpoint_expression"])
        existing = sanitized_findings.get(key)
        if existing is None:
            sanitized_findings[key] = row
            continue
        existing["line"] = min(int(existing["line"]), int(row["line"]))
        for field in ("http_method", "api_auth_type", "call_mechanism"):
            existing[field] = ", ".join(sorted(set(existing[field].split(", ")) | set(row[field].split(", "))))
    finding_rows = sorted(sanitized_findings.values(), key=lambda row: (row["domain"], row["page_url"], row["js_source"], row["endpoint_expression"]))
    for row in coverage_rows:
        row["url"] = sanitize_url(redact_auth(row["url"]))
        row["discovered_from"] = sanitize_url(redact_auth(row["discovered_from"])) if row["discovered_from"].startswith(("http://", "https://")) else redact_auth(row["discovered_from"])
        row["notes"] = sanitize_expression(row["notes"])
    for row in candidates:
        row["page_url"] = sanitize_url(redact_auth(row["page_url"]))
        if row["js_source"].startswith(("http://", "https://")):
            row["js_source"] = sanitize_url(redact_auth(row["js_source"]))
        elif row["js_source"].startswith("INLINE:"):
            inline_value = row["js_source"][len("INLINE:"):]
            inline_url, separator, suffix = inline_value.partition("#")
            row["js_source"] = "INLINE:" + sanitize_url(redact_auth(inline_url)) + (separator + suffix if separator else "")
        else:
            row["js_source"] = redact_auth(row["js_source"])
        row["marker"] = sanitize_expression(row["marker"])
    fieldnames = list(asdict(Finding("", "", "", "", 0, "", "", "", "", "", "", "", "")).keys())
    write_csv(DATA_DIR / "findings.csv", finding_rows, fieldnames)
    write_csv(DATA_DIR / "coverage.csv", coverage_rows, list(asdict(Coverage("", "", "", "", "", "", "", "")).keys()))
    write_csv(DATA_DIR / "candidates.csv", candidates, ["domain", "page_url", "js_source", "line", "marker", "reason", "context_sha256"])

    summary = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "authorized_hosts": sorted(AUTHORIZED_HOSTS),
        "pages_scanned": sum(1 for row in coverage if row.resource_type == "page" and row.outcome == "scanned"),
        "page_candidates_attempted": attempted,
        "page_queue_remaining": len(page_queue) + len(legacy_queue),
        "scripts_scanned": sum(1 for row in coverage if row.resource_type == "script" and row.outcome == "scanned"),
        "source_maps_scanned": sum(1 for row in coverage if row.resource_type == "source-map" and row.outcome == "scanned"),
        "findings": len(finding_rows),
        "candidates": len(candidates),
        "halted_hosts": sorted(halted_hosts),
    }
    (DATA_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
