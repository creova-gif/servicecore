from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
import socket
from collections import deque
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Route, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from pypdf import PdfReader
from pypdf.errors import PdfReadError, PdfStreamError
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, PdfObject

from servicecore.schemas import (
    CorruptPdfError,
    EncryptedPdfError,
    FindingEvidence,
    ScannerBlockedError,
    ScannerError,
    ScannerTimeoutError,
    SeverityLevel,
    SSRFBlockedError,
)

__all__ = [
    "PdfUaInspector",
    "ScannerBackend",
    "WebAxeScanner",
    "discover_pdf_links",
    "validate_public_url",
]

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
    }
)
_BLOCKED_HTTP_STATUSES: frozenset[int] = frozenset({403, 429, 503})
_REDIRECT_HTTP_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
_DYNAMIC_ID_RE = re.compile(r"#[A-Za-z_-]*\d[A-Za-z0-9_-]*")
_NTH_PSEUDO_RE = re.compile(r":nth-(?:child|of-type|last-child|last-of-type)\([^)]*\)")
_WHITESPACE_RE = re.compile(r"\s+")
_WCAG_TAG_RE = re.compile(r"^wcag(\d)(\d)(\d+)$")

_AXE_IMPACT_TO_SEVERITY: dict[str, SeverityLevel] = {
    "critical": "critical",
    "serious": "serious",
    "moderate": "moderate",
    "minor": "minor",
}

_PDF_RULE_METADATA: dict[str, tuple[SeverityLevel, str, str, str]] = {
    "PDF_UNTAGGED_DOCUMENT": (
        "critical",
        "WCAG 1.3.1",
        "IASR s.14",
        "Document lacks a /StructTreeRoot tag structure.",
    ),
    "PDF_MISSING_LANG": (
        "serious",
        "WCAG 3.1.1",
        "IASR s.14",
        "Document catalog is missing a non-empty /Lang entry.",
    ),
    "PDF_MISSING_TITLE": (
        "moderate",
        "WCAG 2.4.2",
        "IASR s.14",
        "Document metadata is missing a non-empty /Title entry.",
    ),
    "PDF_FIGURE_MISSING_ALT": (
        "serious",
        "WCAG 1.1.1",
        "IASR s.14",
        "PDF /Figure structure element is missing /Alt alternative text.",
    ),
    "PDF_TABLE_MISSING_HEADERS": (
        "serious",
        "WCAG 1.3.1",
        "IASR s.14",
        "PDF /Table structure element has no /TH header cell descendants.",
    ),
    "PDF_MISSING_TAB_ORDER": (
        "moderate",
        "WCAG 2.4.3",
        "IASR s.14",
        "PDF page is missing /Tabs /S structure reading order.",
    ),
}


class ScannerBackend(Protocol):
    """Protocol implemented by deterministic accessibility scanners."""

    def scan(self, target: str) -> list[FindingEvidence]: ...


def _is_global_ip(raw_ip: str) -> bool:
    """Return True only when raw_ip parses as a globally routable unicast IP."""
    cleaned = raw_ip.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return bool(ip_obj.is_global and not ip_obj.is_multicast)


def validate_public_url(url: str) -> str:
    """Validate that a URL uses http/https and resolves exclusively to global IPs."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Disallowed URL scheme: {parsed.scheme or '<empty>'}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL is missing a hostname")

    normalized_host = hostname.rstrip(".").lower()
    if normalized_host in _BLOCKED_HOSTNAMES or normalized_host.endswith(".localhost"):
        raise SSRFBlockedError(f"Blocked internal hostname: {hostname}")

    try:
        literal_ip = ipaddress.ip_address(normalized_host.split("%", 1)[0])
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not _is_global_ip(str(literal_ip)):
            raise SSRFBlockedError(f"Blocked non-global IP literal: {hostname}")
        return url

    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_infos = socket.getaddrinfo(normalized_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {exc}") from exc

    if not addr_infos:
        raise SSRFBlockedError(f"DNS resolution returned no addresses for {hostname}")

    for _, _, _, _, sockaddr in addr_infos:
        resolved_ip = str(sockaddr[0])
        if not _is_global_ip(resolved_ip):
            raise SSRFBlockedError(
                f"Hostname {hostname} resolved to non-global IP: {resolved_ip}"
            )

    return url


def _safe_http_get(
    url: str,
    *,
    max_redirects: int = 5,
    max_bytes: int = 25 * 1024 * 1024,
    timeout_s: float = 15.0,
) -> tuple[bytes, str, str]:
    """Fetch a public URL via HTTP GET, validating every redirect hop against SSRF."""
    current_url = url
    try:
        with httpx.Client(follow_redirects=False, timeout=timeout_s) as client:
            for hop in range(max_redirects + 1):
                validated_url = validate_public_url(current_url)
                with client.stream("GET", validated_url) as response:
                    status = response.status_code
                    if status in _REDIRECT_HTTP_STATUSES:
                        if hop >= max_redirects:
                            raise ScannerError(
                                f"Exceeded maximum redirects ({max_redirects}) for {url}"
                            )
                        location = response.headers.get("location")
                        if not location:
                            raise ScannerError(
                                f"Redirect status {status} missing Location header for {validated_url}"
                            )
                        current_url = urljoin(validated_url, location)
                        continue

                    if status in _BLOCKED_HTTP_STATUSES:
                        raise ScannerBlockedError(
                            f"Target returned HTTP {status} for {validated_url}"
                        )
                    if status >= 400:
                        raise ScannerError(
                            f"HTTP {status} error while fetching {validated_url}"
                        )

                    buffer = bytearray()
                    for chunk in response.iter_bytes():
                        buffer.extend(chunk)
                        if len(buffer) > max_bytes:
                            raise ScannerError(
                                f"Response body exceeded {max_bytes} byte cap for {validated_url}"
                            )

                    content_type = response.headers.get("content-type", "")
                    return bytes(buffer), str(response.url), content_type
    except httpx.TimeoutException as exc:
        raise ScannerTimeoutError(f"HTTP GET timed out for {current_url}: {exc}") from exc
    except httpx.HTTPError as exc:
        raise ScannerError(f"HTTP transport error for {current_url}: {exc}") from exc

    raise ScannerError(f"Exceeded maximum redirects ({max_redirects}) for {url}")


def discover_pdf_links(html: str, base_url: str, *, max_links: int = 10) -> list[str]:
    """Extract, resolve, SSRF-validate, and deduplicate PDF anchor links from HTML."""
    if max_links <= 0:
        return []

    soup = BeautifulSoup(html, "html.parser")
    discovered: list[str] = []
    seen: set[str] = set()

    for anchor in soup.find_all("a", href=True):
        raw_href = str(anchor["href"]).strip()
        if not raw_href:
            continue

        resolved = urljoin(base_url, raw_href)
        parsed = urlparse(resolved)
        if not parsed.path.lower().endswith(".pdf"):
            continue

        try:
            validated = validate_public_url(resolved)
        except SSRFBlockedError:
            continue

        if validated in seen:
            continue
        seen.add(validated)
        discovered.append(validated)
        if len(discovered) >= max_links:
            break

    return discovered


def _normalize_dom_signature(selector: str) -> str:
    """Strip volatile IDs and positional pseudo-classes for stable component fingerprints."""
    cleaned = _NTH_PSEUDO_RE.sub("", selector)
    cleaned = _DYNAMIC_ID_RE.sub("", cleaned)
    cleaned = _WHITESPACE_RE.sub(" ", cleaned).strip()
    return cleaned or "root"


def _compute_component_fingerprint(rule_id: str, selector: str) -> str:
    normalized = _normalize_dom_signature(selector)
    payload = f"{rule_id}|{normalized}".encode()
    return hashlib.sha256(payload).hexdigest()


def _compute_finding_id(source: str, target_url: str, rule_id: str, selector: str) -> str:
    payload = f"{source}|{target_url}|{rule_id}|{selector}".encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def _extract_wcag_criterion(tags: list[str]) -> str:
    for tag in tags:
        match = _WCAG_TAG_RE.match(tag.lower())
        if match:
            return f"WCAG {match.group(1)}.{match.group(2)}.{match.group(3)}"
    return "WCAG 2.1 AA"


class WebAxeScanner:
    """Playwright + axe-core accessibility scanner with deterministic HTML normalization."""

    _AXE_CDN_URL: str = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.2/axe.min.js"

    def scan_html(
        self,
        html: str,
        target_url: str,
        axe_results: dict[str, Any] | None = None,
    ) -> list[FindingEvidence]:
        """Normalize axe-core JSON violations into immutable FindingEvidence records."""
        results_payload: dict[str, Any] = axe_results if axe_results is not None else {"violations": []}
        raw_sha256 = hashlib.sha256(
            json.dumps(results_payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

        violations = results_payload.get("violations", [])
        if not isinstance(violations, list):
            return []

        findings: list[FindingEvidence] = []
        for violation in violations:
            if not isinstance(violation, dict):
                continue
            rule_id = str(violation.get("id") or "axe-unknown")
            impact = str(violation.get("impact") or "serious").lower()
            severity: SeverityLevel = _AXE_IMPACT_TO_SEVERITY.get(impact, "serious")
            raw_tags = violation.get("tags", [])
            tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
            wcag = _extract_wcag_criterion(tags)
            description = str(violation.get("help") or violation.get("description") or rule_id)

            nodes = violation.get("nodes", [])
            if not isinstance(nodes, list) or not nodes:
                nodes = [{"target": ["html"], "html": html[:200]}]

            for node in nodes:
                if not isinstance(node, dict):
                    continue
                target_field = node.get("target", ["html"])
                if isinstance(target_field, list) and target_field:
                    selector = " > ".join(str(part) for part in target_field)
                elif isinstance(target_field, str) and target_field.strip():
                    selector = target_field.strip()
                else:
                    selector = "html"

                raw_snippet = str(node.get("html") or html[:200])
                findings.append(
                    FindingEvidence(
                        finding_id=_compute_finding_id("axe-core", target_url, rule_id, selector),
                        source="axe-core",
                        rule_id=rule_id,
                        severity=severity,
                        wcag_criterion=wcag,
                        aoda_section="IASR s.14",
                        target_url=target_url,
                        target_selector=selector,
                        raw_snippet=raw_snippet,
                        component_fingerprint=_compute_component_fingerprint(rule_id, selector),
                        raw_scanner_sha256=raw_sha256,
                        description=description,
                    )
                )

        return findings

    def scan(self, target: str) -> list[FindingEvidence]:
        """Scan a live public URL using Playwright + axe-core with SSRF route interception."""
        validated_url = validate_public_url(target)

        def _handle_route(route: Route) -> None:
            req_url = route.request.url
            if req_url == "about:blank":
                route.continue_()
                return
            try:
                validate_public_url(req_url)
            except SSRFBlockedError:
                route.abort()
                return
            route.continue_()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
                page.route("**/*", _handle_route)
                try:
                    response = page.goto(validated_url, timeout=30_000, wait_until="domcontentloaded")
                except PlaywrightTimeoutError as exc:
                    raise ScannerTimeoutError(
                        f"Playwright navigation timed out for {validated_url}"
                    ) from exc
                except PlaywrightError as exc:
                    raise ScannerError(
                        f"Playwright navigation failed for {validated_url}: {exc}"
                    ) from exc

                if response is None:
                    raise ScannerError(f"Playwright received no response for {validated_url}")

                if response.status in _BLOCKED_HTTP_STATUSES:
                    raise ScannerBlockedError(
                        f"Target returned HTTP {response.status} for {validated_url}"
                    )

                content_type = response.headers.get("content-type", "").lower()
                if "application/pdf" in content_type:
                    browser.close()
                    return PdfUaInspector().scan(validated_url)

                html = page.content()
                page.add_script_tag(url=self._AXE_CDN_URL)
                axe_results: dict[str, Any] = page.evaluate("() => window.axe.run()")
                return self.scan_html(html, validated_url, axe_results=axe_results)
            finally:
                if browser.is_connected():
                    browser.close()


def _resolve_pdf_obj(obj: PdfObject | Any) -> Any:
    """Resolve IndirectObject references safely."""
    if isinstance(obj, IndirectObject):
        return obj.get_object()
    return obj


def _iter_struct_children(node: dict[Any, Any]) -> list[Any]:
    """Return child items from /K on a PDF structure element."""
    k_val = node.get("/K")
    if k_val is None:
        return []
    resolved_k = _resolve_pdf_obj(k_val)
    if isinstance(resolved_k, (ArrayObject, list)):
        return list(resolved_k)
    return [k_val]


def _table_has_th_descendant(table_node: dict[Any, Any]) -> bool:
    """Iteratively search a /Table node's /K subtree for any /TH header cell."""
    queue: deque[Any] = deque(_iter_struct_children(table_node))
    visited: set[int] = set()

    while queue:
        item = queue.popleft()
        if isinstance(item, IndirectObject):
            if item.idnum in visited:
                continue
            visited.add(item.idnum)
            item = item.get_object()

        if isinstance(item, (ArrayObject, list)):
            queue.extend(item)
            continue

        if isinstance(item, (DictionaryObject, dict)):
            if str(item.get("/S", "")) == "/TH":
                return True
            queue.extend(_iter_struct_children(item))

    return False


class PdfUaInspector:
    """Deterministic PDF/UA structural accessibility inspector using pypdf."""

    def _build_finding(
        self,
        *,
        rule_id: str,
        target_url: str,
        target_selector: str,
        raw_snippet: str,
        raw_sha256: str,
    ) -> FindingEvidence:
        severity, wcag, aoda, description = _PDF_RULE_METADATA[rule_id]
        return FindingEvidence(
            finding_id=_compute_finding_id("pypdf", target_url, rule_id, target_selector),
            source="pypdf",
            rule_id=rule_id,
            severity=severity,
            wcag_criterion=wcag,
            aoda_section=aoda,
            target_url=target_url,
            target_selector=target_selector,
            raw_snippet=raw_snippet,
            component_fingerprint=_compute_component_fingerprint(rule_id, target_selector),
            raw_scanner_sha256=raw_sha256,
            description=description,
        )

    def scan_bytes(self, data: bytes, target_url: str) -> list[FindingEvidence]:
        """Inspect raw PDF bytes for PDF/UA accessibility conformance issues."""
        if not data.startswith(b"%PDF-"):
            raise CorruptPdfError("Input bytes do not start with %PDF- magic header")

        raw_sha256 = hashlib.sha256(data).hexdigest()

        try:
            reader = PdfReader(io.BytesIO(data))
        except (PdfReadError, PdfStreamError, ValueError, KeyError, IndexError) as exc:
            raise CorruptPdfError(f"Failed to parse PDF structure: {exc}") from exc

        if reader.is_encrypted:
            try:
                decrypt_result = reader.decrypt("")
            except (PdfReadError, PdfStreamError, ValueError) as exc:
                raise EncryptedPdfError(f"PDF is encrypted: {exc}") from exc
            if decrypt_result == 0:
                raise EncryptedPdfError("PDF requires a non-empty password to decrypt")

        findings: list[FindingEvidence] = []
        try:
            root = _resolve_pdf_obj(reader.trailer.get("/Root"))
            if not isinstance(root, (DictionaryObject, dict)):
                raise CorruptPdfError("PDF trailer is missing a valid /Root catalog")

            lang = _resolve_pdf_obj(root.get("/Lang"))
            if not lang or not str(lang).strip():
                findings.append(
                    self._build_finding(
                        rule_id="PDF_MISSING_LANG",
                        target_url=target_url,
                        target_selector="catalog",
                        raw_snippet="/Catalog missing /Lang",
                        raw_sha256=raw_sha256,
                    )
                )

            metadata = reader.metadata
            title = metadata.get("/Title") if metadata is not None else None
            if not title or not str(title).strip():
                findings.append(
                    self._build_finding(
                        rule_id="PDF_MISSING_TITLE",
                        target_url=target_url,
                        target_selector="metadata",
                        raw_snippet="/Info missing /Title",
                        raw_sha256=raw_sha256,
                    )
                )

            for page_idx, page in enumerate(reader.pages):
                tabs = _resolve_pdf_obj(page.get("/Tabs"))
                if str(tabs) != "/S":
                    findings.append(
                        self._build_finding(
                            rule_id="PDF_MISSING_TAB_ORDER",
                            target_url=target_url,
                            target_selector=f"page[{page_idx}]",
                            raw_snippet=f"Page {page_idx} /Tabs={tabs!r} (expected /S)",
                            raw_sha256=raw_sha256,
                        )
                    )

            struct_root_ref = root.get("/StructTreeRoot")
            struct_root = _resolve_pdf_obj(struct_root_ref)
            if not isinstance(struct_root, (DictionaryObject, dict)):
                findings.append(
                    self._build_finding(
                        rule_id="PDF_UNTAGGED_DOCUMENT",
                        target_url=target_url,
                        target_selector="catalog",
                        raw_snippet="/Catalog missing /StructTreeRoot",
                        raw_sha256=raw_sha256,
                    )
                )
                return findings

            self._inspect_struct_tree(
                struct_root_ref=struct_root_ref,
                target_url=target_url,
                raw_sha256=raw_sha256,
                findings=findings,
            )
        except (PdfReadError, PdfStreamError) as exc:
            raise CorruptPdfError(f"Corrupt PDF stream during inspection: {exc}") from exc

        return findings

    def _inspect_struct_tree(
        self,
        *,
        struct_root_ref: Any,
        target_url: str,
        raw_sha256: str,
        findings: list[FindingEvidence],
    ) -> None:
        """Traverse /StructTreeRoot iteratively with indirect-object cycle protection."""
        queue: deque[Any] = deque([struct_root_ref])
        visited: set[int] = set()
        figure_idx = 0
        table_idx = 0

        while queue:
            current = queue.popleft()
            if isinstance(current, IndirectObject):
                if current.idnum in visited:
                    continue
                visited.add(current.idnum)
                current = current.get_object()

            if isinstance(current, (ArrayObject, list)):
                queue.extend(current)
                continue

            if not isinstance(current, (DictionaryObject, dict)):
                continue

            struct_type = str(current.get("/S", ""))
            if struct_type == "/Figure":
                alt_val = _resolve_pdf_obj(current.get("/Alt"))
                if not alt_val or not str(alt_val).strip():
                    findings.append(
                        self._build_finding(
                            rule_id="PDF_FIGURE_MISSING_ALT",
                            target_url=target_url,
                            target_selector=f"struct:Figure#{figure_idx}",
                            raw_snippet=f"/Figure#{figure_idx} missing /Alt",
                            raw_sha256=raw_sha256,
                        )
                    )
                figure_idx += 1
            elif struct_type == "/Table":
                if not _table_has_th_descendant(current):
                    findings.append(
                        self._build_finding(
                            rule_id="PDF_TABLE_MISSING_HEADERS",
                            target_url=target_url,
                            target_selector=f"struct:Table#{table_idx}",
                            raw_snippet=f"/Table#{table_idx} missing /TH descendant",
                            raw_sha256=raw_sha256,
                        )
                    )
                table_idx += 1

            queue.extend(_iter_struct_children(current))

    def scan(self, target: str) -> list[FindingEvidence]:
        """Scan a local PDF file path or a public http(s) PDF URL."""
        lower_target = target.lower()
        if lower_target.startswith(("http://", "https://")):
            data, final_url, _ = _safe_http_get(target)
            return self.scan_bytes(data, final_url)

        if "://" in target:
            validate_public_url(target)

        pdf_path = Path(target)
        data = pdf_path.read_bytes()
        return self.scan_bytes(data, str(pdf_path))
