from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from anthropic import RateLimitError

from servicecore.schemas import EvidenceMismatchError, FindingEvidence, RemediationPatch
from servicecore.synthesizer import (
    DEFAULT_WCAG_AODA,
    WCAG_AODA_MAP,
    ClaudeSynthesizer,
    deduplicate_findings,
    lookup_wcag_aoda,
    sanitize_html_snippet,
    validate_patch_binding,
)


def _make_finding(
    finding_id: str = "f-1",
    *,
    source: str = "axe-core",
    rule_id: str = "image-alt",
    target_selector: str = "img.hero",
    component_fingerprint: str = "fp-hero-img",
    raw_snippet: str = '<img class="hero" src="/hero.png">',
) -> FindingEvidence:
    wcag, aoda = lookup_wcag_aoda(rule_id)
    return FindingEvidence(
        finding_id=finding_id,
        source=source,  # type: ignore[arg-type]
        rule_id=rule_id,
        severity="serious",
        wcag_criterion=wcag,
        aoda_section=aoda,
        target_url="https://example.com",
        target_selector=target_selector,
        raw_snippet=raw_snippet,
        component_fingerprint=component_fingerprint,
        raw_scanner_sha256="a" * 64,
        description="Missing alt text",
    )


def _make_html_patch(
    finding: FindingEvidence,
    *,
    rule_id: str | None = None,
    target_selector: str | None = None,
    after_snippet: str = '<img class="hero" src="/hero.png" alt="Hero banner">',
) -> RemediationPatch:
    return RemediationPatch(
        finding_id=finding.finding_id,
        rule_id=rule_id or finding.rule_id,
        target_selector=target_selector or finding.target_selector,
        patch_kind="html_diff",
        before_snippet=finding.raw_snippet,
        after_snippet=after_snippet,
        wcag_criterion=finding.wcag_criterion,
        aoda_section=finding.aoda_section,
        component_fingerprint=finding.component_fingerprint,
        synthesized_by="claude",
    )


def test_wcag_aoda_map_covers_rules_and_fallback() -> None:
    expected_axe = {
        "color-contrast",
        "image-alt",
        "label",
        "link-name",
        "button-name",
        "html-has-lang",
        "document-title",
        "heading-order",
    }
    expected_pdf = {
        "PDF_UNTAGGED_DOCUMENT",
        "PDF_MISSING_LANG",
        "PDF_MISSING_TITLE",
        "PDF_FIGURE_MISSING_ALT",
        "PDF_TABLE_MISSING_HEADERS",
        "PDF_MISSING_TAB_ORDER",
    }
    assert expected_axe.issubset(WCAG_AODA_MAP.keys())
    assert expected_pdf.issubset(WCAG_AODA_MAP.keys())
    assert lookup_wcag_aoda("unknown-axe-rule") == DEFAULT_WCAG_AODA


def test_deduplicate_findings_preserves_first_seen_order() -> None:
    f1 = _make_finding("f-1", component_fingerprint="fp-a")
    f2 = _make_finding("f-2", component_fingerprint="fp-b")
    f3 = _make_finding("f-3", component_fingerprint="fp-a")
    f4 = _make_finding("f-4", component_fingerprint="fp-c")

    deduped = deduplicate_findings([f1, f2, f3, f4])
    assert [f.finding_id for f in deduped] == ["f-1", "f-2", "f-4"]


def test_validate_patch_binding_accepts_valid_patch() -> None:
    finding = _make_finding()
    patch = _make_html_patch(finding)
    validated = validate_patch_binding(patch, {finding.finding_id: finding})
    assert validated == patch


def test_validate_patch_binding_rejects_mismatched_rule_id() -> None:
    finding = _make_finding()
    patch = _make_html_patch(finding, rule_id="button-name")
    with pytest.raises(EvidenceMismatchError, match="rule_id"):
        validate_patch_binding(patch, {finding.finding_id: finding})


def test_validate_patch_binding_rejects_mismatched_target_selector() -> None:
    finding = _make_finding()
    patch = _make_html_patch(finding, target_selector="div.other")
    with pytest.raises(EvidenceMismatchError, match="target_selector"):
        validate_patch_binding(patch, {finding.finding_id: finding})


@pytest.mark.parametrize(
    "bad_snippet",
    [
        '<img src="/x.png" alt="ok"><script>alert(1)</script>',
        '<img src="/x.png" ONCLICK="alert(1)" alt="ok">',
        '<a href="JaVaScRiPt:alert(1)">Click</a>',
    ],
)
def test_validate_patch_binding_rejects_xss_in_after_snippet(bad_snippet: str) -> None:
    finding = _make_finding()
    patch = _make_html_patch(finding, after_snippet=bad_snippet)
    with pytest.raises(EvidenceMismatchError):
        validate_patch_binding(patch, {finding.finding_id: finding})


def test_sanitize_html_snippet_allows_safe_html() -> None:
    safe = '<button type="button" aria-label="Close modal">X</button>'
    assert sanitize_html_snippet(safe) == safe


class _FakeMessages:
    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.calls = 0

    def create(self, **kwargs: Any) -> Any:
        self.calls += 1
        return self._handler(self.calls, kwargs)


class _FakeAnthropicClient:
    def __init__(self, handler: Any) -> None:
        self.messages = _FakeMessages(handler)


def test_claude_synthesizer_empty_list_spends_zero_tokens() -> None:
    client = _FakeAnthropicClient(lambda _c, _k: pytest.fail("Should not call LLM"))
    synth = ClaudeSynthesizer(client=client)
    patches, in_tok, out_tok = synth.synthesize([])
    assert patches == []
    assert in_tok == 0
    assert out_tok == 0
    assert client.messages.calls == 0


def test_claude_synthesizer_valid_mocked_patch() -> None:
    finding = _make_finding()

    def _handler(_calls: int, kwargs: dict[str, Any]) -> Any:
        prompt = kwargs["messages"][0]["content"]
        assert "<untrusted_evidence>" in prompt
        assert "</untrusted_evidence>" in prompt
        payload = {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "target_selector": finding.target_selector,
            "patch_kind": "html_diff",
            "before_snippet": finding.raw_snippet,
            "after_snippet": '<img class="hero" src="/hero.png" alt="Company logo">',
            "pdf_remediation_steps": [],
            "wcag_criterion": finding.wcag_criterion,
            "aoda_section": finding.aoda_section,
            "component_fingerprint": finding.component_fingerprint,
        }
        return SimpleNamespace(
            content=[SimpleNamespace(text=json.dumps(payload))],
            usage=SimpleNamespace(input_tokens=120, output_tokens=45),
        )

    synth = ClaudeSynthesizer(client=_FakeAnthropicClient(_handler))
    patches, in_tok, out_tok = synth.synthesize([finding])
    assert len(patches) == 1
    assert patches[0].synthesized_by == "claude"
    assert patches[0].after_snippet == '<img class="hero" src="/hero.png" alt="Company logo">'
    assert in_tok == 120
    assert out_tok == 45


def test_claude_synthesizer_hallucinated_patch_falls_back_to_deterministic() -> None:
    finding = _make_finding()

    def _handler(_calls: int, _kwargs: dict[str, Any]) -> Any:
        # Hallucinated rule_id that does not match finding
        payload = {
            "finding_id": finding.finding_id,
            "rule_id": "hallucinated-rule",
            "target_selector": finding.target_selector,
            "patch_kind": "html_diff",
            "before_snippet": finding.raw_snippet,
            "after_snippet": '<img class="hero" src="/hero.png" alt="Hero">',
            "pdf_remediation_steps": [],
            "wcag_criterion": finding.wcag_criterion,
            "aoda_section": finding.aoda_section,
            "component_fingerprint": finding.component_fingerprint,
        }
        return SimpleNamespace(
            content=[SimpleNamespace(text=json.dumps(payload))],
            usage=SimpleNamespace(input_tokens=80, output_tokens=30),
        )

    synth = ClaudeSynthesizer(client=_FakeAnthropicClient(_handler))
    patches, in_tok, out_tok = synth.synthesize([finding])
    assert len(patches) == 1
    assert patches[0].synthesized_by == "deterministic_template"
    assert patches[0].rule_id == finding.rule_id
    assert patches[0].target_selector == finding.target_selector
    assert in_tok == 80
    assert out_tok == 30


def test_claude_synthesizer_retries_transient_rate_limit_then_falls_back() -> None:
    finding = _make_finding(
        finding_id="f-pdf",
        source="pypdf",
        rule_id="PDF_MISSING_TITLE",
        target_selector="document",
        component_fingerprint="fp-pdf-title",
        raw_snippet="Metadata: /Title missing",
    )
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    resp = httpx.Response(429, request=req)

    def _handler(_calls: int, _kwargs: dict[str, Any]) -> Any:
        raise RateLimitError("rate limited", response=cast(Any, resp), body=None)

    client = _FakeAnthropicClient(_handler)
    synth = ClaudeSynthesizer(client=client, max_attempts=3, base_backoff_seconds=0.0)
    patches, in_tok, out_tok = synth.synthesize([finding])
    assert client.messages.calls == 3
    assert len(patches) == 1
    assert patches[0].synthesized_by == "deterministic_template"
    assert patches[0].patch_kind == "pdf_tag_action"
    assert len(patches[0].pdf_remediation_steps) >= 1
    assert in_tok == 0
    assert out_tok == 0
