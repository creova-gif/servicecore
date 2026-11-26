from __future__ import annotations

import io
import socket
from typing import Any

import httpx
import pytest
from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

from servicecore.scanners import (
    PdfUaInspector,
    ScannerBackend,
    WebAxeScanner,
    _safe_http_get,
    discover_pdf_links,
    validate_public_url,
)
from servicecore.schemas import (
    CorruptPdfError,
    EncryptedPdfError,
    ScannerBlockedError,
    SSRFBlockedError,
)


def _mock_public_dns(monkeypatch: pytest.MonkeyPatch, ip: str = "93.184.216.34") -> None:
    def _fake_getaddrinfo(
        host: str,
        port: int | str | None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ip, int(port or 443)),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


def _build_untagged_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _build_tagged_pdf_with_missing_alt_and_th() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=200, height=200)
    page[NameObject("/Tabs")] = NameObject("/S")

    writer.add_metadata({"/Title": "Accessible Report"})
    root = writer._root_object
    root[NameObject("/Lang")] = TextStringObject("en-CA")

    figure = DictionaryObject({NameObject("/S"): NameObject("/Figure")})
    figure_ref = writer._add_object(figure)

    td_cell = DictionaryObject({NameObject("/S"): NameObject("/TD")})
    td_ref = writer._add_object(td_cell)
    tr_row = DictionaryObject(
        {
            NameObject("/S"): NameObject("/TR"),
            NameObject("/K"): ArrayObject([td_ref]),
        }
    )
    tr_ref = writer._add_object(tr_row)
    table = DictionaryObject(
        {
            NameObject("/S"): NameObject("/Table"),
            NameObject("/K"): ArrayObject([tr_ref]),
        }
    )
    table_ref = writer._add_object(table)

    struct_root = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/StructTreeRoot"),
            NameObject("/K"): ArrayObject([figure_ref, table_ref]),
        }
    )
    struct_root_ref = writer._add_object(struct_root)
    root[NameObject("/StructTreeRoot")] = struct_root_ref

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _build_cyclic_struct_pdf() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=200, height=200)
    page[NameObject("/Tabs")] = NameObject("/S")
    writer.add_metadata({"/Title": "Cyclic Tagged PDF"})
    root = writer._root_object
    root[NameObject("/Lang")] = TextStringObject("en-CA")

    node_a = DictionaryObject({NameObject("/S"): NameObject("/Sect")})
    node_a_ref = writer._add_object(node_a)
    node_b = DictionaryObject(
        {
            NameObject("/S"): NameObject("/P"),
            NameObject("/K"): node_a_ref,
        }
    )
    node_b_ref = writer._add_object(node_b)
    node_a[NameObject("/K")] = node_b_ref

    struct_root = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/StructTreeRoot"),
            NameObject("/K"): node_a_ref,
        }
    )
    root[NameObject("/StructTreeRoot")] = writer._add_object(struct_root)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _build_encrypted_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt("secret-password")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.mark.parametrize(
    "blocked_url",
    [
        "file:///etc/passwd",
        "ftp://example.com/archive.zip",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(1)",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost:8080/health",
    ],
)
def test_validate_public_url_blocks_ssrf_targets(blocked_url: str) -> None:
    with pytest.raises(SSRFBlockedError):
        validate_public_url(blocked_url)


def test_validate_public_url_allows_mocked_public_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_public_dns(monkeypatch, "93.184.216.34")
    url = "https://example.org/accessibility"
    assert validate_public_url(url) == url


def test_safe_http_get_blocks_redirect_to_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_public_dns(monkeypatch, "93.184.216.34")

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        )

    transport = httpx.MockTransport(_handler)
    real_client = httpx.Client

    def _patched_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", _patched_client)

    with pytest.raises(SSRFBlockedError):
        _safe_http_get("https://example.org/start")


def test_safe_http_get_raises_scanner_blocked_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_public_dns(monkeypatch, "93.184.216.34")

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=403, text="Forbidden")

    transport = httpx.MockTransport(_handler)
    real_client = httpx.Client

    def _patched_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", _patched_client)

    with pytest.raises(ScannerBlockedError):
        _safe_http_get("https://example.org/protected")


def test_discover_pdf_links_extracts_and_caps_at_10(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_public_dns(monkeypatch, "93.184.216.34")

    anchors = [
        '<a href="/docs/first.pdf">First</a>',
        '<a href="https://example.org/docs/second.PDF">Second</a>',
        '<a href="/docs/first.pdf">Duplicate</a>',
        '<a href="http://127.0.0.1/internal.pdf">SSRF Blocked</a>',
        '<a href="https://example.org/page.html">Not a PDF</a>',
    ]
    anchors.extend(f'<a href="/docs/file_{i}.pdf">File {i}</a>' for i in range(1, 15))
    html = f"<html><body>{''.join(anchors)}</body></html>"

    links = discover_pdf_links(html, "https://example.org/index.html", max_links=10)
    assert len(links) == 10
    assert links[0] == "https://example.org/docs/first.pdf"
    assert links[1] == "https://example.org/docs/second.PDF"
    assert all("127.0.0.1" not in link for link in links)


def test_web_axe_scanner_scan_html_stable_fingerprint() -> None:
    scanner = WebAxeScanner()
    axe_run_1: dict[str, Any] = {
        "violations": [
            {
                "id": "color-contrast",
                "impact": "serious",
                "tags": ["wcag2aa", "wcag143"],
                "help": "Elements must meet minimum color contrast ratio thresholds",
                "nodes": [
                    {
                        "target": ["div#id-123 > button.primary:nth-child(2)"],
                        "html": '<button class="primary">Submit</button>',
                    }
                ],
            }
        ]
    }
    axe_run_2: dict[str, Any] = {
        "violations": [
            {
                "id": "color-contrast",
                "impact": "serious",
                "tags": ["wcag2aa", "wcag143"],
                "help": "Elements must meet minimum color contrast ratio thresholds",
                "nodes": [
                    {
                        "target": ["div#id-999 > button.primary:nth-child(5)"],
                        "html": '<button class="primary">Submit</button>',
                    }
                ],
            }
        ]
    }

    findings_1 = scanner.scan_html("<html></html>", "https://example.org", axe_results=axe_run_1)
    findings_2 = scanner.scan_html("<html></html>", "https://example.org", axe_results=axe_run_2)

    assert len(findings_1) == 1
    assert len(findings_2) == 1
    assert findings_1[0].source == "axe-core"
    assert findings_1[0].rule_id == "color-contrast"
    assert findings_1[0].wcag_criterion == "WCAG 1.4.3"
    assert findings_1[0].component_fingerprint == findings_2[0].component_fingerprint
    assert len(findings_1[0].raw_scanner_sha256) == 64


def test_pdf_ua_inspector_untagged_pdf() -> None:
    inspector = PdfUaInspector()
    findings = inspector.scan_bytes(_build_untagged_pdf(), "https://example.org/untagged.pdf")
    rule_ids = {finding.rule_id for finding in findings}
    assert {
        "PDF_UNTAGGED_DOCUMENT",
        "PDF_MISSING_LANG",
        "PDF_MISSING_TITLE",
        "PDF_MISSING_TAB_ORDER",
    }.issubset(rule_ids)


def test_pdf_ua_inspector_tagged_missing_alt_and_th() -> None:
    inspector = PdfUaInspector()
    findings = inspector.scan_bytes(
        _build_tagged_pdf_with_missing_alt_and_th(),
        "https://example.org/tagged.pdf",
    )
    rule_ids = {finding.rule_id for finding in findings}
    assert rule_ids == {"PDF_FIGURE_MISSING_ALT", "PDF_TABLE_MISSING_HEADERS"}


def test_pdf_ua_inspector_corrupt_bytes_raises() -> None:
    inspector = PdfUaInspector()
    with pytest.raises(CorruptPdfError):
        inspector.scan_bytes(b"NOT_A_PDF_FILE", "https://example.org/bad.pdf")


def test_pdf_ua_inspector_encrypted_pdf_raises() -> None:
    inspector = PdfUaInspector()
    with pytest.raises(EncryptedPdfError):
        inspector.scan_bytes(_build_encrypted_pdf(), "https://example.org/encrypted.pdf")


def test_pdf_ua_inspector_cyclic_struct_tree_terminates() -> None:
    inspector = PdfUaInspector()
    findings = inspector.scan_bytes(_build_cyclic_struct_pdf(), "https://example.org/cyclic.pdf")
    assert findings == []


def test_scanners_conform_to_protocol() -> None:
    web_scanner: ScannerBackend = WebAxeScanner()
    pdf_scanner: ScannerBackend = PdfUaInspector()
    assert callable(web_scanner.scan)
    assert callable(pdf_scanner.scan)
