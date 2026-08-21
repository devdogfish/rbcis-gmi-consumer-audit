#!/usr/bin/env python3
"""Reconcile attached GMI JS filename inventory with prior public crawl pages."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


WORKSPACE = Path(__file__).resolve().parents[1]
ATTACHMENT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else WORKSPACE / "scripts-filenames.txt"
OUTPUT = WORKSPACE / "work" / "reconciliation"
OUTPUT.mkdir(parents=True, exist_ok=True)
SCRIPT_BASE = "https://www.rbcis.com/assets/rbcits/js/sub/gmi/"


spec = importlib.util.spec_from_file_location("audit", WORKSPACE / "scripts" / "audit_gmi_consumers.py")
audit = importlib.util.module_from_spec(spec)
sys.modules["audit"] = audit
assert spec.loader is not None
spec.loader.exec_module(audit)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def inferred_names(name: str) -> list[tuple[str, str]]:
    candidates = [(name, "exact")]
    if not name.lower().endswith((".js", ".mjs")):
        inferred = re.sub(r"-js$", ".js", name, flags=re.I)
        if inferred == name:
            inferred = name + ".js"
        if inferred not in {item[0] for item in candidates}:
            candidates.append((inferred, "inferred extension"))
    return candidates


listed_names = []
for line in ATTACHMENT.read_text(encoding="utf-8-sig").splitlines():
    name = line.strip()
    if name and name not in listed_names:
        listed_names.append(name)

coverage_rows = read_csv(WORKSPACE / "work" / "audit_data" / "coverage.csv")
page_urls_by_host: dict[str, list[str]] = defaultdict(list)
for row in coverage_rows:
    if row.get("resource_type") != "page" or row.get("outcome") != "scanned" or row.get("status") != "200":
        continue
    url = row.get("url", "")
    host = (urlsplit(url).hostname or "").lower()
    if host in {"www.rbcis.com", "apps.rbcits.com"} and url not in page_urls_by_host[host]:
        page_urls_by_host[host].append(url)


script_inventory: list[dict] = []
script_findings: list[dict] = []
script_candidates: list[dict] = []
successful_names: dict[str, str] = {}
script_urls: dict[str, str] = {}
import_graph: dict[str, set[str]] = defaultdict(set)
reuse_inventory = all((OUTPUT / name).exists() for name in ("script_inventory.csv", "script_findings.csv", "script_candidates.csv"))
if reuse_inventory:
    script_inventory.extend(read_csv(OUTPUT / "script_inventory.csv"))
    script_findings.extend(read_csv(OUTPUT / "script_findings.csv"))
    script_candidates.extend(read_csv(OUTPUT / "script_candidates.csv"))
    for row in script_inventory:
        if row.get("http_status") == "200" and row.get("resolved_name"):
            successful_names[row["listed_name"]] = row["resolved_name"]
            script_urls[row["listed_name"]] = row["script_url"]


def match_inventory_script(script_url: str) -> str | None:
    parts = urlsplit(script_url)
    if (parts.hostname or "").lower() != "www.rbcis.com":
        return None
    target_prefix = "/assets/rbcits/js/sub/gmi/"
    if not unquote(parts.path).lower().startswith(target_prefix):
        return None
    basename = unquote(Path(parts.path).name)
    for listed_name in listed_names:
        if any(candidate.lower() == basename.lower() for candidate, _ in inferred_names(listed_name)):
            return listed_name
    return None


def fetch_scripts(fetcher) -> None:
    for index, listed_name in enumerate(listed_names, start=1):
        chosen = None
        last_status = ""
        last_type = ""
        for resolved_name, resolution in inferred_names(listed_name):
            url = SCRIPT_BASE + quote(resolved_name, safe="-._~")
            try:
                status, content_type, final_url, body = fetcher.get(url, {"www.rbcis.com"})
            except Exception as exc:
                last_status = "ERROR"
                last_type = ""
                print(f"script fetch error {listed_name}: {str(exc)[:160]}", flush=True)
                continue
            last_status = str(status)
            last_type = content_type
            if status in {403, 429}:
                script_inventory.append({
                    "listed_name": listed_name, "resolved_name": "", "resolution": "host halted",
                    "script_url": url, "http_status": str(status), "content_type": content_type,
                    "importing_page_count": 0, "gmi_call_count": 0, "embedded_auth_call_count": 0,
                    "candidate_reference_count": 0, "notes": "Safety stop on 403/429; remaining files not requested",
                })
                for remaining in listed_names[index:]:
                    script_inventory.append({
                        "listed_name": remaining, "resolved_name": "", "resolution": "not requested",
                        "script_url": SCRIPT_BASE + quote(remaining, safe="-._~"), "http_status": "SKIPPED",
                        "content_type": "", "importing_page_count": 0, "gmi_call_count": 0,
                        "embedded_auth_call_count": 0, "candidate_reference_count": 0,
                        "notes": "Host halted after 403/429",
                    })
                print(f"SAFETY STOP scripts: HTTP {status} at {url}", flush=True)
                return
            is_script_type = "javascript" in content_type or "ecmascript" in content_type or resolved_name.lower().endswith((".js", ".mjs"))
            is_script = status == 200 and is_script_type and not re.search(r"(?is)<html\b|<!doctype\s+html", body[:2000])
            if is_script:
                chosen = (resolved_name, resolution, final_url, content_type, body)
                break
        if chosen is None:
            script_inventory.append({
                "listed_name": listed_name,
                "resolved_name": "",
                "resolution": "unavailable",
                "script_url": SCRIPT_BASE + quote(listed_name, safe="-._~"),
                "http_status": last_status,
                "content_type": last_type,
                "importing_page_count": 0,
                "gmi_call_count": 0,
                "embedded_auth_call_count": 0,
                "candidate_reference_count": 0,
                "notes": "No public JavaScript response for exact/inferred filename",
            })
        else:
            resolved_name, resolution, final_url, content_type, body = chosen
            successful_names[listed_name] = resolved_name
            script_urls[listed_name] = final_url
            occurrence = audit.ScriptOccurrence(
                page_url="https://www.rbcis.com/__inventory_unmapped__",
                source_url=final_url,
                source_kind="inventory",
                start_line=1,
                text=body,
            )
            findings, candidates = audit.scan_occurrence(occurrence)
            for finding in findings:
                row = asdict(finding)
                row["listed_name"] = listed_name
                row["resolved_name"] = resolved_name
                row["script_url"] = final_url
                script_findings.append(row)
            for candidate in candidates:
                script_candidates.append({
                    "listed_name": listed_name,
                    "resolved_name": resolved_name,
                    "script_url": final_url,
                    **candidate,
                })
            for imported in audit.IMPORT_RE.findall(body):
                if not imported.startswith((".", "/", "http://", "https://", "//")):
                    continue
                imported_url = audit.canonicalize(imported, final_url)
                child = match_inventory_script(imported_url) if imported_url else None
                if child:
                    import_graph[listed_name].add(child)
            embedded = sum("Client-embedded credential" in finding.api_auth_type for finding in findings)
            has_auth_literal = bool(re.search(r"(?i)(authorization\s*['\"]?\s*[:=]|setRequestHeader\s*\(\s*['\"]authorization)", body))
            script_inventory.append({
                "listed_name": listed_name,
                "resolved_name": resolved_name,
                "resolution": resolution,
                "script_url": final_url,
                "http_status": "200",
                "content_type": content_type,
                "importing_page_count": 0,
                "gmi_call_count": len(findings),
                "embedded_auth_call_count": embedded,
                "candidate_reference_count": len(candidates),
                "notes": "Public script scanned; unresolved GMI refs with auth literal require review" if candidates and has_auth_literal else "Public script scanned; no credential values retained",
            })
        if index % 20 == 0:
            print(f"scripts {index}/{len(listed_names)}", flush=True)


def scan_pages(host: str, fetcher) -> tuple[list[dict], list[dict]]:
    imports: list[dict] = []
    statuses: list[dict] = []
    urls = page_urls_by_host.get(host, [])
    for index, page_url in enumerate(urls, start=1):
        try:
            status, content_type, final_url, body = fetcher.get(page_url, {host})
        except Exception as exc:
            statuses.append({"host": host, "page_url": page_url, "status": "ERROR", "outcome": "failed", "notes": str(exc)[:500]})
            continue
        if status in {403, 429}:
            statuses.append({"host": host, "page_url": page_url, "status": str(status), "outcome": "excluded", "notes": "Individual inaccessible/rate-limited URL skipped; scan continued"})
            continue
        if status != 200 or not ("html" in content_type or re.search(r"(?is)<html\b|<!doctype\s+html", body[:2000])):
            statuses.append({"host": host, "page_url": page_url, "status": str(status), "outcome": "excluded", "notes": content_type})
            continue
        parser = audit.LinkScriptParser()
        try:
            parser.feed(body)
        except Exception as exc:
            statuses.append({"host": host, "page_url": page_url, "status": str(status), "outcome": "partial", "notes": str(exc)[:500]})
        else:
            statuses.append({"host": host, "page_url": page_url, "status": str(status), "outcome": "scanned", "notes": f"{len(parser.scripts)} script tags"})
        resolution_base = audit.canonicalize(parser.base_href, final_url) if parser.base_href else final_url
        resolution_base = resolution_base or final_url
        seen_on_page = set()
        for src in parser.scripts + parser.script_preloads:
            script_url = audit.canonicalize(src, resolution_base)
            if not script_url:
                continue
            basename = unquote(Path(urlsplit(script_url).path).name)
            listed_name = match_inventory_script(script_url)
            if not listed_name:
                continue
            key = (page_url, listed_name, script_url)
            if key in seen_on_page:
                continue
            seen_on_page.add(key)
            imports.append({
                "host": host,
                "page_url": page_url,
                "listed_name": listed_name,
                "resolved_name": basename,
                "script_url": script_url,
                "import_type": "direct-script-tag",
                "imported_via": "",
            })
        if index % 25 == 0:
            print(f"pages {host} {index}/{len(urls)}", flush=True)
    return imports, statuses


www_fetcher = audit.Fetcher()
apps_fetcher = audit.Fetcher()
if not reuse_inventory:
    fetch_scripts(www_fetcher)
with ThreadPoolExecutor(max_workers=2) as pool:
    www_future = pool.submit(scan_pages, "www.rbcis.com", www_fetcher)
    apps_future = pool.submit(scan_pages, "apps.rbcits.com", apps_fetcher)
    www_imports, www_statuses = www_future.result()
    apps_imports, apps_statuses = apps_future.result()
page_imports = apps_imports + www_imports
page_statuses = apps_statuses + www_statuses

# The fresh crawler follows static/literal child-script loaders. Attribute any
# inventory script reached through that graph even when it was not a direct tag.
known_import_keys = {(row["page_url"], row["listed_name"], row["script_url"]) for row in page_imports}
for finding in read_csv(WORKSPACE / "work" / "audit_data" / "findings.csv"):
    if finding.get("js_source", "").startswith("INLINE:"):
        continue
    listed_name = match_inventory_script(finding.get("js_source", ""))
    if not listed_name:
        continue
    key = (finding["page_url"], listed_name, finding["js_source"])
    if key in known_import_keys:
        continue
    page_imports.append({
        "host": (urlsplit(finding["page_url"]).hostname or "").lower(),
        "page_url": finding["page_url"],
        "listed_name": listed_name,
        "resolved_name": successful_names.get(listed_name, listed_name),
        "script_url": finding["js_source"],
        "import_type": "loaded-script-graph",
        "imported_via": "fresh recursive crawl",
    })
    known_import_keys.add(key)

# Propagate page membership through literal static JS import/require edges.
pages_by_listed: dict[str, set[str]] = defaultdict(set)
for row in page_imports:
    pages_by_listed[row["listed_name"]].add(row["page_url"])
changed = True
while changed:
    changed = False
    for parent, children in import_graph.items():
        for child in children:
            before = len(pages_by_listed[child])
            pages_by_listed[child].update(pages_by_listed[parent])
            changed = changed or len(pages_by_listed[child]) != before
for parent, children in import_graph.items():
    for child in children:
        existing = {(row["page_url"], row["listed_name"]) for row in page_imports}
        for page_url in pages_by_listed[parent]:
            if (page_url, child) in existing:
                continue
            page_imports.append({
                "host": (urlsplit(page_url).hostname or "").lower(),
                "page_url": page_url,
                "listed_name": child,
                "resolved_name": successful_names.get(child, child),
                "script_url": script_urls.get(child, SCRIPT_BASE + quote(successful_names.get(child, child), safe="-._~")),
                "import_type": "static-import",
                "imported_via": parent,
            })
            existing.add((page_url, child))

pages_by_listed = defaultdict(set)
for row in page_imports:
    pages_by_listed[row["listed_name"]].add(row["page_url"])
for row in script_inventory:
    row["importing_page_count"] = len(pages_by_listed.get(row["listed_name"], set()))

# Expand script-level call sites to actual importing pages; retain unmapped insecure consumers.
reconciled_findings: list[dict] = []
for source_finding in script_findings:
    pages = sorted(pages_by_listed.get(source_finding["listed_name"], set()))
    if not pages:
        pages = ["No importing page found among scanned pages"]
    for page_url in pages:
        row = dict(source_finding)
        mapped = page_url.startswith("http")
        row["page_url"] = page_url
        row["domain"] = (urlsplit(page_url).hostname or "").lower() if mapped else "www.rbcis.com"
        row["page_access"] = "Public" if mapped else "Unmapped"
        row["js_source"] = source_finding["script_url"]
        row["confidence"] = "Confirmed source occurrence" if mapped else "Confirmed source occurrence; no importing page found"
        row["summary"] = (
            f"{'Public page statically imports' if mapped else 'Listed script contains'} a client-side {row['call_mechanism']} "
            f"{row['http_method']} call to {row['endpoint_expression']}. Authentication: {row['api_auth_type']}."
        )
        tuple_source = "|".join([row["domain"], row["page_url"], row["js_source"], row["endpoint_expression"]])
        row["finding_id"] = hashlib.sha256(tuple_source.encode()).hexdigest()[:12].upper()
        reconciled_findings.append(row)

deduped: dict[tuple[str, str, str, str], dict] = {}
for row in reconciled_findings:
    key = (row["domain"], row["page_url"], row["js_source"], row["endpoint_expression"])
    existing = deduped.get(key)
    if existing is None:
        deduped[key] = row
        continue
    existing["line"] = min(int(existing["line"]), int(row["line"]))
    for field in ("http_method", "api_auth_type", "call_mechanism"):
        existing[field] = ", ".join(sorted(set(existing[field].split(", ")) | set(row[field].split(", "))))
reconciled_findings = sorted(deduped.values(), key=lambda row: (row["domain"], row["page_url"], row["js_source"], row["endpoint_expression"]))

write_csv(OUTPUT / "script_inventory.csv", script_inventory, [
    "listed_name", "resolved_name", "resolution", "script_url", "http_status", "content_type",
    "importing_page_count", "gmi_call_count", "embedded_auth_call_count", "candidate_reference_count", "notes",
])
write_csv(OUTPUT / "script_findings.csv", script_findings, [
    "listed_name", "resolved_name", "script_url", "finding_id", "domain", "page_url", "js_source", "line",
    "endpoint_expression", "http_method", "execution_side", "page_access", "api_auth_type", "call_mechanism",
    "confidence", "summary",
])
write_csv(OUTPUT / "script_candidates.csv", script_candidates, [
    "listed_name", "resolved_name", "script_url", "domain", "page_url", "js_source", "line", "marker", "reason", "context_sha256",
])
write_csv(OUTPUT / "reconciled_findings.csv", reconciled_findings, [
    "listed_name", "resolved_name", "script_url", "finding_id", "domain", "page_url", "js_source", "line",
    "endpoint_expression", "http_method", "execution_side", "page_access", "api_auth_type", "call_mechanism", "confidence", "summary",
])
write_csv(OUTPUT / "page_imports.csv", page_imports, ["host", "page_url", "listed_name", "resolved_name", "script_url", "import_type", "imported_via"])
write_csv(OUTPUT / "page_scan_status.csv", page_statuses, ["host", "page_url", "status", "outcome", "notes"])

summary = {
    "listed_scripts": len(listed_names),
    "public_scripts_scanned": sum(row["http_status"] == "200" for row in script_inventory),
    "unavailable_scripts": sum(row["http_status"] != "200" for row in script_inventory),
    "scripts_with_gmi_calls": sum(int(row["gmi_call_count"]) > 0 for row in script_inventory),
    "scripts_with_embedded_auth": sum(int(row["embedded_auth_call_count"]) > 0 for row in script_inventory),
    "script_level_gmi_calls": len(script_findings),
    "reconciled_consumer_rows": len(reconciled_findings),
    "unresolved_candidate_references": len(script_candidates),
    "pages_requested": len(page_statuses),
    "pages_scanned": sum(row["outcome"] == "scanned" for row in page_statuses),
    "page_import_rows": len(page_imports),
    "scripts_imported_by_scanned_pages": len({row["listed_name"] for row in page_imports}),
    "gmi_scripts_not_imported": sum(int(row["gmi_call_count"]) > 0 and int(row["importing_page_count"]) == 0 for row in script_inventory),
}
(OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print(json.dumps(summary, indent=2), flush=True)
