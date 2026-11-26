from __future__ import annotations

from typing import Any

from servicecore.exporter import verify_bundle
from servicecore.schemas import AuditBundle, FindingEvidence, UnsignedFindingError

__all__ = ["export_sarif"]

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "ServiceCore"
_TOOL_VERSION = "0.1.0"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "SERIOUS": "error",
    "MODERATE": "warning",
    "MINOR": "note",
}


def _map_severity_to_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity.upper(), "warning")


def _build_rule(finding: FindingEvidence) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.wcag_criterion},
        "properties": {
            "wcag_criterion": finding.wcag_criterion,
            "aoda_section": finding.aoda_section,
        },
    }


def _build_result(finding: FindingEvidence, evidence_digest: str | None) -> dict[str, Any]:
    message_text = finding.description.strip() or f"{finding.rule_id}: {finding.wcag_criterion}"
    return {
        "ruleId": finding.rule_id,
        "level": _map_severity_to_level(finding.severity),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.target_url,
                    }
                },
                "logicalLocations": [
                    {
                        "name": finding.target_selector,
                        "fullyQualifiedName": finding.target_selector,
                        "kind": "element",
                    }
                ],
            }
        ],
        "properties": {
            "wcag_criterion": finding.wcag_criterion,
            "aoda_section": finding.aoda_section,
            "component_fingerprint": finding.component_fingerprint,
            "raw_scanner_sha256": finding.raw_scanner_sha256,
            "evidence_digest": evidence_digest,
        },
    }


def export_sarif(bundle: AuditBundle) -> dict[str, Any]:
    """Export a verified, signed AuditBundle as a SARIF 2.1.0 document."""
    ok, reason = verify_bundle(bundle)
    if not ok:
        raise UnsignedFindingError(reason)

    rejected_ids = {r.finding_id for r in bundle.reviews if r.status == "REJECTED"}

    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in bundle.findings:
        if finding.finding_id in rejected_ids:
            continue
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = _build_rule(finding)
        results.append(_build_result(finding, bundle.evidence_digest))

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "semanticVersion": _TOOL_VERSION,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
