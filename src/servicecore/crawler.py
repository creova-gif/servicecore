from __future__ import annotations

from collections import deque
from collections.abc import Callable
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from servicecore.scanners import (
    PdfUaInspector,
    ScannerBackend,
    WebAxeScanner,
    _safe_http_get,
    discover_pdf_links,
    validate_public_url,
)
from servicecore.schemas import FindingEvidence, ScannerError, SSRFBlockedError

__all__ = [
    "CrawlConfig",
    "SiteCrawlScanner",
]

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def _default_html_fetcher(url: str) -> str:
    """Fetch public HTML via SSRF-safe HTTP GET and decode as UTF-8."""
    data, _, _ = _safe_http_get(url)
    return data.decode("utf-8", errors="replace")


def _normalize_url(url: str) -> str:
    """Strip URL fragments and normalize empty root paths to '/'."""
    defragged, _ = urldefrag(url.strip())
    parsed = urlparse(defragged)
    if not parsed.path:
        return parsed._replace(path="/").geturl()
    return defragged


class CrawlConfig(BaseModel):
    """Bounded configuration for multi-page site and PDF crawling."""

    max_pages: int = Field(default=5, ge=1, le=20)
    max_pdfs: int = Field(default=5, ge=0, le=20)


class SiteCrawlScanner:
    """Same-origin BFS site & PDF crawler implementing ScannerBackend."""

    def __init__(
        self,
        web_scanner: ScannerBackend | None = None,
        pdf_scanner: ScannerBackend | None = None,
        html_fetcher: Callable[[str], str] | None = None,
        config: CrawlConfig | None = None,
    ) -> None:
        self.web_scanner: ScannerBackend = web_scanner or WebAxeScanner()
        self.pdf_scanner: ScannerBackend = pdf_scanner or PdfUaInspector()
        self.html_fetcher: Callable[[str], str] = html_fetcher or _default_html_fetcher
        self.config: CrawlConfig = config or CrawlConfig()
        self.affected_pages: dict[tuple[str, str], int] = {}
        self.crawled_pages: list[str] = []
        self.discovered_pdfs: list[str] = []

    def _extract_same_origin_links(
        self,
        html: str,
        base_url: str,
        root_netloc: str,
    ) -> list[str]:
        """Extract SSRF-validated, same-origin, non-PDF HTML links from anchor tags."""
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        for anchor in soup.find_all("a", href=True):
            raw_href = str(anchor["href"]).strip()
            if not raw_href or raw_href.startswith("#"):
                continue

            resolved = _normalize_url(urljoin(base_url, raw_href))
            parsed = urlparse(resolved)
            if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
                continue
            if parsed.netloc.lower() != root_netloc:
                continue
            if parsed.path.lower().endswith(".pdf"):
                continue

            try:
                validated = validate_public_url(resolved)
            except (SSRFBlockedError, ScannerError):
                continue

            links.append(validated)
        return links

    def _collect_pdf_links(
        self,
        html: str,
        base_url: str,
        seen_pdfs: set[str],
        discovered_pdfs: list[str],
    ) -> None:
        """Discover, SSRF-validate, and record unique PDF links up to max_pdfs."""
        remaining = self.config.max_pdfs - len(discovered_pdfs)
        if remaining <= 0:
            return

        candidates = discover_pdf_links(html, base_url, max_links=self.config.max_pdfs)
        for pdf_url in candidates:
            if len(discovered_pdfs) >= self.config.max_pdfs:
                break
            try:
                validated = validate_public_url(pdf_url)
            except (SSRFBlockedError, ScannerError):
                continue
            if validated in seen_pdfs:
                continue
            seen_pdfs.add(validated)
            discovered_pdfs.append(validated)

    def scan(self, target: str) -> list[FindingEvidence]:
        """Crawl up to max_pages same-origin HTML pages and max_pdfs PDFs."""
        validated_root = validate_public_url(target)
        root_url = _normalize_url(validated_root)
        root_netloc = urlparse(root_url).netloc.lower()

        queue: deque[str] = deque([root_url])
        visited_pages: set[str] = {root_url}
        crawled_pages: list[str] = []
        discovered_pdfs: list[str] = []
        seen_pdfs: set[str] = set()

        html_findings_by_key: dict[tuple[str, str], FindingEvidence] = {}
        pages_per_key: dict[tuple[str, str], set[str]] = {}

        while queue and len(crawled_pages) < self.config.max_pages:
            current_url = queue.popleft()
            is_root = current_url == root_url

            try:
                current_url = _normalize_url(validate_public_url(current_url))
                html = self.html_fetcher(current_url)
                page_findings = self.web_scanner.scan(current_url)
            except SSRFBlockedError:
                if is_root:
                    raise
                continue
            except ScannerError:
                if is_root:
                    raise
                continue

            crawled_pages.append(current_url)

            for finding in page_findings:
                key = (finding.rule_id, finding.component_fingerprint)
                pages_per_key.setdefault(key, set()).add(current_url)
                if key not in html_findings_by_key:
                    html_findings_by_key[key] = finding

            self._collect_pdf_links(html, current_url, seen_pdfs, discovered_pdfs)

            for link in self._extract_same_origin_links(html, current_url, root_netloc):
                if link not in visited_pages:
                    visited_pages.add(link)
                    queue.append(link)

        pdf_findings: list[FindingEvidence] = []
        for pdf_url in discovered_pdfs:
            try:
                validated_pdf = validate_public_url(pdf_url)
                pdf_findings.extend(self.pdf_scanner.scan(validated_pdf))
            except (SSRFBlockedError, ScannerError):
                continue

        self.crawled_pages = crawled_pages
        self.discovered_pdfs = discovered_pdfs
        self.affected_pages = {key: len(urls) for key, urls in pages_per_key.items()}

        aggregated_html_findings: list[FindingEvidence] = []
        for key, finding in html_findings_by_key.items():
            count = self.affected_pages[key]
            if count > 1:
                updated_desc = f"{finding.description} [affected_pages={count}]".strip()
                aggregated_html_findings.append(
                    finding.model_copy(update={"description": updated_desc})
                )
            else:
                aggregated_html_findings.append(finding)

        return aggregated_html_findings + pdf_findings
