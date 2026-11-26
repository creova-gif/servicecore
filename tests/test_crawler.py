from __future__ import annotations

import hashlib
import socket
from typing import Literal

import pytest

from servicecore.crawler import CrawlConfig, SiteCrawlScanner
from servicecore.scanners import PdfUaInspector, ScannerBackend
from servicecore.schemas import FindingEvidence, ScannerError, SSRFBlockedError


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def _make_finding(
    *,
    source: Literal["axe-core", "pypdf"] = "axe-core",
    rule_id: str = "color-contrast",
    target_url: str = "https://example.com/",
    target_selector: str = ".nav-link",
    component_fingerprint: str = "fp-shared-nav",
    description: str = "Insufficient contrast",
) -> FindingEvidence:
    return FindingEvidence(
        finding_id=_sha256_hex(f"{source}|{target_url}|{rule_id}|{target_selector}")[:16],
        source=source,
        rule_id=rule_id,
        severity="serious",
        wcag_criterion="WCAG 1.4.3",
        aoda_section="IASR s.14",
        target_url=target_url,
        target_selector=target_selector,
        raw_snippet="<a class='nav-link'>Home</a>",
        component_fingerprint=component_fingerprint,
        raw_scanner_sha256=_sha256_hex(f"{target_url}|{rule_id}"),
        description=description,
    )


class _FakeWebScanner:
    def __init__(self, findings_by_url: dict[str, list[FindingEvidence]]) -> None:
        self._findings_by_url = findings_by_url
        self.scanned_urls: list[str] = []

    def scan(self, target: str) -> list[FindingEvidence]:
        self.scanned_urls.append(target)
        return list(self._findings_by_url.get(target, []))


class _FakePdfScanner:
    def __init__(self, findings_by_url: dict[str, list[FindingEvidence]]) -> None:
        self._findings_by_url = findings_by_url
        self.scanned_urls: list[str] = []

    def scan(self, target: str) -> list[FindingEvidence]:
        self.scanned_urls.append(target)
        return list(self._findings_by_url.get(target, []))


@pytest.fixture
def mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]]:
        del port, family, type, proto, flags
        if host in {"example.com", "other.org", "cdn.example.com"}:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        raise OSError(f"Unknown test host: {host}")

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


def test_site_crawl_scanner_satisfies_protocol() -> None:
    scanner: ScannerBackend = SiteCrawlScanner()
    assert isinstance(scanner, SiteCrawlScanner)


def test_crawl_config_bounds() -> None:
    cfg = CrawlConfig()
    assert cfg.max_pages == 5
    assert cfg.max_pdfs == 5

    with pytest.raises(ValueError):
        CrawlConfig(max_pages=0)
    with pytest.raises(ValueError):
        CrawlConfig(max_pages=21)
    with pytest.raises(ValueError):
        CrawlConfig(max_pdfs=-1)
    with pytest.raises(ValueError):
        CrawlConfig(max_pdfs=21)


def test_root_ssrf_blocked_propagates() -> None:
    scanner = SiteCrawlScanner(
        web_scanner=_FakeWebScanner({}),
        pdf_scanner=_FakePdfScanner({}),
        html_fetcher=lambda _url: "",
    )
    with pytest.raises(SSRFBlockedError):
        scanner.scan("http://127.0.0.1/admin")


def test_same_origin_bfs_respects_max_pages(mock_public_dns: None) -> None:
    del mock_public_dns
    pages = {
        "https://example.com/": (
            "<a href='/about'>About</a>"
            "<a href='/contact'>Contact</a>"
            "<a href='https://other.org/external'>External</a>"
        ),
        "https://example.com/about": "<a href='/team'>Team</a>",
        "https://example.com/contact": "<a href='/careers'>Careers</a>",
        "https://example.com/team": "<p>Team</p>",
        "https://example.com/careers": "<p>Careers</p>",
    }
    web = _FakeWebScanner(
        {
            "https://example.com/": [_make_finding(target_url="https://example.com/", component_fingerprint="fp-1")],
            "https://example.com/about": [_make_finding(target_url="https://example.com/about", component_fingerprint="fp-2")],
            "https://example.com/contact": [_make_finding(target_url="https://example.com/contact", component_fingerprint="fp-3")],
        }
    )
    scanner = SiteCrawlScanner(
        web_scanner=web,
        pdf_scanner=_FakePdfScanner({}),
        html_fetcher=lambda url: pages[url],
        config=CrawlConfig(max_pages=3, max_pdfs=0),
    )

    findings = scanner.scan("https://example.com")

    assert scanner.crawled_pages == [
        "https://example.com/",
        "https://example.com/about",
        "https://example.com/contact",
    ]
    assert web.scanned_urls == [
        "https://example.com/",
        "https://example.com/about",
        "https://example.com/contact",
    ]
    assert len(findings) == 3


def test_filters_private_ip_and_off_origin_links(mock_public_dns: None) -> None:
    del mock_public_dns
    pages = {
        "https://example.com/": (
            "<a href='http://127.0.0.1/admin'>Admin</a>"
            "<a href='http://169.254.169.254/latest/meta-data/'>Metadata</a>"
            "<a href='https://other.org/phish'>Off-origin</a>"
            "<a href='mailto:info@example.com'>Mail</a>"
            "<a href='/valid'>Valid</a>"
            "<a href='http://127.0.0.1/secret.pdf'>Private PDF</a>"
        ),
        "https://example.com/valid": "<p>OK</p>",
    }
    web = _FakeWebScanner({})
    pdf = _FakePdfScanner({})
    scanner = SiteCrawlScanner(
        web_scanner=web,
        pdf_scanner=pdf,
        html_fetcher=lambda url: pages[url],
        config=CrawlConfig(max_pages=5, max_pdfs=5),
    )

    findings = scanner.scan("https://example.com/")

    assert findings == []
    assert scanner.crawled_pages == [
        "https://example.com/",
        "https://example.com/valid",
    ]
    assert scanner.discovered_pdfs == []
    assert pdf.scanned_urls == []


def test_bad_secondary_pdf_scanner_error_does_not_crash_crawl(mock_public_dns: None) -> None:
    del mock_public_dns
    pages = {
        "https://example.com/": (
            "<a href='/docs/bad.pdf'>Bad PDF</a>"
            "<a href='/docs/good.pdf'>Good PDF</a>"
        ),
    }

    class _FlakyPdfScanner:
        def scan(self, target: str) -> list[FindingEvidence]:
            if target.endswith("bad.pdf"):
                raise ScannerError("Corrupt PDF")
            return [
                _make_finding(
                    source="pypdf",
                    rule_id="PDF_UNTAGGED_DOCUMENT",
                    target_url=target,
                    target_selector="pdf:/Catalog",
                    component_fingerprint="fp-pdf-1",
                    description="Untagged PDF",
                )
            ]

    scanner = SiteCrawlScanner(
        web_scanner=_FakeWebScanner({}),
        pdf_scanner=_FlakyPdfScanner(),
        html_fetcher=lambda url: pages[url],
        config=CrawlConfig(max_pages=2, max_pdfs=5),
    )

    findings = scanner.scan("https://example.com/")
    assert len(findings) == 1
    assert findings[0].rule_id == "PDF_UNTAGGED_DOCUMENT"
    assert findings[0].target_url == "https://example.com/docs/good.pdf"


def test_discovered_pdf_scanning_with_pdfua_inspector(
    mock_public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del mock_public_dns
    pages = {
        "https://example.com/": "<a href='/reports/annual.pdf'>Annual Report</a>",
    }

    minimal_untagged_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer << /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
    )

    def _fake_safe_http_get(
        url: str,
        *,
        max_redirects: int = 5,
        max_bytes: int = 25 * 1024 * 1024,
        timeout_s: float = 15.0,
    ) -> tuple[bytes, str, str]:
        del max_redirects, max_bytes, timeout_s
        return minimal_untagged_pdf, url, "application/pdf"

    monkeypatch.setattr("servicecore.scanners._safe_http_get", _fake_safe_http_get)

    scanner = SiteCrawlScanner(
        web_scanner=_FakeWebScanner({}),
        pdf_scanner=PdfUaInspector(),
        html_fetcher=lambda url: pages[url],
        config=CrawlConfig(max_pages=2, max_pdfs=2),
    )

    findings = scanner.scan("https://example.com/")
    assert scanner.discovered_pdfs == ["https://example.com/reports/annual.pdf"]
    rule_ids = {f.rule_id for f in findings}
    assert "PDF_UNTAGGED_DOCUMENT" in rule_ids


def test_affected_pages_aggregation_across_crawled_pages(mock_public_dns: None) -> None:
    del mock_public_dns
    pages = {
        "https://example.com/": "<a href='/a'>A</a><a href='/b'>B</a>",
        "https://example.com/a": "<p>Page A</p>",
        "https://example.com/b": "<p>Page B</p>",
    }
    shared_rule = "color-contrast"
    shared_fp = "fp-header-contrast"
    unique_rule = "image-alt"
    unique_fp = "fp-hero-img"

    web = _FakeWebScanner(
        {
            "https://example.com/": [
                _make_finding(
                    rule_id=shared_rule,
                    target_url="https://example.com/",
                    component_fingerprint=shared_fp,
                ),
            ],
            "https://example.com/a": [
                _make_finding(
                    rule_id=shared_rule,
                    target_url="https://example.com/a",
                    component_fingerprint=shared_fp,
                ),
                _make_finding(
                    rule_id=unique_rule,
                    target_url="https://example.com/a",
                    target_selector="img.hero",
                    component_fingerprint=unique_fp,
                    description="Missing alt text",
                ),
            ],
            "https://example.com/b": [
                _make_finding(
                    rule_id=shared_rule,
                    target_url="https://example.com/b",
                    component_fingerprint=shared_fp,
                ),
            ],
        }
    )

    scanner = SiteCrawlScanner(
        web_scanner=web,
        pdf_scanner=_FakePdfScanner({}),
        html_fetcher=lambda url: pages[url],
        config=CrawlConfig(max_pages=5, max_pdfs=0),
    )

    findings = scanner.scan("https://example.com/")

    assert scanner.affected_pages[(shared_rule, shared_fp)] == 3
    assert scanner.affected_pages[(unique_rule, unique_fp)] == 1
    assert len(findings) == 2

    by_rule = {f.rule_id: f for f in findings}
    assert "[affected_pages=3]" in by_rule[shared_rule].description
    assert "[affected_pages=" not in by_rule[unique_rule].description
