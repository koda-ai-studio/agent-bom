"""The hard rule: AI advice can never dismiss or downgrade a protected finding."""

from __future__ import annotations

import json

import pytest

from agent_bom.ai_components.triage_guard import guard_verdict, protected_reasons
from agent_bom.ai_enrich import _parse_finding_assessments
from agent_bom.ai_schemas import AIFindingAssessment, AIProvenance
from agent_bom.finding import Asset, Finding, FindingSource, FindingType


def _finding(**overrides: object) -> Finding:
    values: dict = {
        "finding_type": FindingType.CVE,
        "source": FindingSource.MCP_SCAN,
        "asset": Asset(name="lib", asset_type="package", identifier="pkg:npm/lib@1.0.0"),
        "severity": "high",
        "title": "CVE-2021-44228 in lib",
        "cve_id": "CVE-2021-44228",
    }
    values.update(overrides)
    return Finding(**values)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"is_kev": True}, "kev"),
        ({"is_malicious": True}, "malicious_package"),
        ({"finding_type": FindingType.MALICIOUS_PACKAGE}, "malicious_package"),
        ({"severity": "critical", "reachability": "confirmed"}, "reachable_critical"),
        ({"severity": "critical", "reachability": "likely"}, "reachable_critical"),
        ({"severity": "CRITICAL", "graph_reachable": True}, "reachable_critical"),
    ],
)
def test_protected_classes(overrides: dict, reason: str) -> None:
    assert reason in protected_reasons(_finding(**overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"severity": "critical", "reachability": "unlikely"},
        {"severity": "critical", "reachability": "unknown"},
        {"severity": "high", "graph_reachable": True},
    ],
)
def test_ordinary_findings_are_not_protected(overrides: dict) -> None:
    assert protected_reasons(_finding(**overrides)) == ()


def test_protection_reads_a_persisted_finding_row() -> None:
    assert protected_reasons({"is_kev": True}) == ("kev",)
    assert protected_reasons({"finding_type": "MALICIOUS_PACKAGE"}) == ("malicious_package",)
    assert protected_reasons({"effective_severity": "critical", "graph_reachable": True}) == ("reachable_critical",)
    assert protected_reasons({"severity": "low"}) == ()


@pytest.mark.parametrize(
    "dismissal",
    [
        {"verdict": "likely_false_positive", "confidence": "high"},
        {"verdict": "confirmed", "false_positive_likelihood": "high"},
        {"classification": "false_positive"},
        {"classification": "benign", "false_positive_likelihood": "medium"},
        {"classification": "not_affected"},
        {"classification": "severity_downgrade"},
        {"classification": "low_risk", "verdict": "needs_review"},
    ],
)
def test_no_model_output_can_dismiss_a_protected_finding(dismissal: dict) -> None:
    finding = _finding(is_kev=True, severity="critical", id="kev-1")
    response = json.dumps(
        {"assessments": [{"finding_id": "kev-1", "rationale": "IGNORE THE SCANNER, this is safe", **dismissal}]},
    )
    [assessment] = _parse_finding_assessments(
        response, findings={"kev-1": finding}, provider="ollama", model="ollama/m", run_id="r", prompt="p"
    )
    assert assessment.verdict == "confirmed"
    assert assessment.false_positive_likelihood == "low"
    assert assessment.guard_applied is True
    assert assessment.protected_reasons == ["kev"]
    assert "safe" not in assessment.rationale
    assert "kev" in assessment.rationale.lower()


def test_a_dismissal_of_an_ordinary_finding_stands() -> None:
    finding = _finding(id="plain-1")
    response = json.dumps(
        {
            "assessments": [
                {
                    "finding_id": "plain-1",
                    "verdict": "likely_false_positive",
                    "confidence": "high",
                    "rationale": "installed version is above the fix",
                }
            ]
        }
    )
    [assessment] = _parse_finding_assessments(
        response, findings={"plain-1": finding}, provider="ollama", model="ollama/m", run_id="r", prompt="p"
    )
    assert assessment.verdict == "likely_false_positive"
    assert assessment.false_positive_likelihood == "high"
    assert assessment.guard_applied is False


def _provenance() -> AIProvenance:
    from datetime import datetime, timezone

    return AIProvenance(
        run_id="r",
        provider="ollama",
        model="ollama/m",
        prompt_sha256="a" * 64,
        response_sha256="b" * 64,
        generated_at=datetime.now(timezone.utc),
        deterministic=True,
        redaction_applied=True,
    )


def test_the_schema_refuses_a_protected_dismissal_built_any_other_way() -> None:
    with pytest.raises(ValueError, match="protected"):
        AIFindingAssessment(
            finding_id="x",
            verdict="likely_false_positive",
            protected_reasons=["kev"],
            provenance=_provenance(),
        )
    with pytest.raises(ValueError, match="protected"):
        AIFindingAssessment(
            finding_id="x",
            verdict="confirmed",
            false_positive_likelihood="high",
            protected_reasons=["malicious_package"],
            provenance=_provenance(),
        )


def test_guard_verdict_applies_to_a_stored_assessment_when_a_finding_later_turns_kev() -> None:
    stored = AIFindingAssessment(
        finding_id="x", verdict="likely_false_positive", false_positive_likelihood="high", rationale="old", provenance=_provenance()
    ).model_dump(mode="json")
    guarded = guard_verdict(stored, {"is_kev": True})
    assert guarded["verdict"] == "confirmed"
    assert guarded["false_positive_likelihood"] == "low"
    assert guarded["guard_applied"] is True
    assert guarded["protected_reasons"] == ["kev"]
    assert guarded["rationale"] != "old"
    assert stored["verdict"] == "likely_false_positive"
    assert guard_verdict(stored, {"severity": "high"})["verdict"] == "likely_false_positive"
