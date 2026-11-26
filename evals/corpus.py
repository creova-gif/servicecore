from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any

from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

__all__ = ["BenchmarkSiteFixture", "build_smb_benchmark_corpus"]


@dataclass(frozen=True)
class BenchmarkSiteFixture:
    """Deterministic SMB site/PDF benchmark fixture with expected rule IDs."""

    name: str
    kind: str
    target_url: str
    expected_rule_ids: frozenset[str]
    html: str = ""
    axe_results: dict[str, Any] | None = None
    pdf_bytes: bytes = b""


def _make_untagged_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _make_tagged_missing_alt_pdf() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    page[NameObject("/Tabs")] = NameObject("/S")

    fig = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/StructElem"),
            NameObject("/S"): NameObject("/Figure"),
        }
    )
    fig_ref = writer._add_object(fig)
    struct_root = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/StructTreeRoot"),
            NameObject("/K"): ArrayObject([fig_ref]),
        }
    )
    struct_ref = writer._add_object(struct_root)
    writer._root_object[NameObject("/StructTreeRoot")] = struct_ref
    writer._root_object[NameObject("/Lang")] = TextStringObject("en-CA")
    writer.add_metadata({"/Title": "SMB Accessibility Notice"})

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def build_smb_benchmark_corpus() -> list[BenchmarkSiteFixture]:
    """Build 5 deterministic SMB web & PDF audit fixtures for precision/latency evals."""
    return [
        BenchmarkSiteFixture(
            name="smb-1-ontario-clinic",
            kind="html",
            target_url="https://clinic.example.ca",
            html="<html><body><img src='logo.png'><button></button></body></html>",
            axe_results={
                "violations": [
                    {
                        "id": "image-alt",
                        "impact": "critical",
                        "tags": ["wcag2a", "wcag111"],
                        "description": "Images must have alternate text",
                        "nodes": [{"target": ["img"], "html": "<img src='logo.png'>"}],
                    },
                    {
                        "id": "button-name",
                        "impact": "critical",
                        "tags": ["wcag2a", "wcag412"],
                        "description": "Buttons must have discernible text",
                        "nodes": [{"target": ["button"], "html": "<button></button>"}],
                    },
                ]
            },
            expected_rule_ids=frozenset({"image-alt", "button-name"}),
        ),
        BenchmarkSiteFixture(
            name="smb-2-saas-pricing",
            kind="html",
            target_url="https://saas.example.com/pricing",
            html="<html><body><p style='color:#aaa'>Low contrast</p></body></html>",
            axe_results={
                "violations": [
                    {
                        "id": "color-contrast",
                        "impact": "serious",
                        "tags": ["wcag2aa", "wcag143"],
                        "description": "Insufficient color contrast",
                        "nodes": [{"target": ["p"], "html": "<p style='color:#aaa'>Low contrast</p>"}],
                    }
                ]
            },
            expected_rule_ids=frozenset({"color-contrast"}),
        ),
        BenchmarkSiteFixture(
            name="smb-3-nonprofit-clean",
            kind="html",
            target_url="https://nonprofit.example.org",
            html="<html lang='en'><head><title>Clean</title></head><body><h1>Hi</h1></body></html>",
            axe_results={"violations": []},
            expected_rule_ids=frozenset(),
        ),
        BenchmarkSiteFixture(
            name="smb-4-municipal-untagged-pdf",
            kind="pdf",
            target_url="https://town.example.ca/budget.pdf",
            pdf_bytes=_make_untagged_pdf(),
            expected_rule_ids=frozenset(
                {
                    "PDF_UNTAGGED_DOCUMENT",
                    "PDF_MISSING_LANG",
                    "PDF_MISSING_TITLE",
                    "PDF_MISSING_TAB_ORDER",
                }
            ),
        ),
        BenchmarkSiteFixture(
            name="smb-5-lawfirm-figure-pdf",
            kind="pdf",
            target_url="https://law.example.ca/intake.pdf",
            pdf_bytes=_make_tagged_missing_alt_pdf(),
            expected_rule_ids=frozenset({"PDF_FIGURE_MISSING_ALT"}),
        ),
    ]
