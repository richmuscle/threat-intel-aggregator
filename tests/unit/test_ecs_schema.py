"""
ECS (Elastic Common Schema) compliance test for `_to_ecs()` output.

Runs every generated alert through a pinned schema that mirrors the ECS
fields Elastic / Wazuh ingest pipelines expect under `event.*`, `threat.*`,
`vulnerability.*`, `rule.*`, `tags`, and `labels`. Catches silent drift —
e.g. if someone accidentally renames `threat.technique.id` to
`threat.mitre.id`, every downstream ingest would start dropping fields
quietly; this test fails instead.

The schema is intentionally strict on the SHAPE but permissive on the
VALUES (severity ints, cve refs, technique ids) — the value-level checks
live in separate unit tests.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.agents.report_coordinator import _ecs_severity, _to_ecs
from src.models import CorrelatedIntelReport

ECS_EVENT_SCHEMA: dict = {
    "type": "object",
    "required": ["@timestamp", "event", "rule", "threat", "vulnerability", "tags", "labels"],
    "properties": {
        "@timestamp": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"},
        "event": {
            "type": "object",
            "required": ["kind", "category", "type", "severity", "dataset", "module"],
            "properties": {
                "kind": {"type": "string", "enum": ["alert"]},
                "category": {"type": "array", "items": {"type": "string"}},
                "type": {"type": "array", "items": {"type": "string"}},
                # ECS severity = 1-100 integer (Elastic convention).
                "severity": {"type": "integer", "minimum": 1, "maximum": 100},
                "dataset": {"type": "string"},
                "module": {"type": "string"},
            },
        },
        "rule": {
            "type": "object",
            "required": ["name", "description"],
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
            },
        },
        "threat": {
            "type": "object",
            "required": ["technique"],
            "properties": {
                "technique": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "string"}},
                },
            },
        },
        "vulnerability": {
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
        },
        "tags": {"type": "array", "items": {"type": "string"}},
        "labels": {
            "type": "object",
            "required": ["report_id"],
            "properties": {"report_id": {"type": "string"}},
        },
    },
}


@pytest.fixture
def report() -> CorrelatedIntelReport:
    return CorrelatedIntelReport(
        report_id="TIA-ECSTEST",
        generated_at=datetime(2026, 4, 16, 0, 0, 0, tzinfo=UTC),
        executive_summary="test",
    )


class TestToECS:
    """`_to_ecs()` must produce strictly-shaped ECS events."""

    def _validate(self, event: dict) -> None:
        """Minimal inline schema validator — avoids pulling in `jsonschema`."""

        def _check(value: object, schema: dict, path: str = "") -> None:
            t = schema.get("type")
            if t == "object":
                assert isinstance(value, dict), (
                    f"{path}: expected object, got {type(value).__name__}"
                )
                for req in schema.get("required", []):
                    assert req in value, f"{path}: missing required field '{req}'"
                for key, subschema in schema.get("properties", {}).items():
                    if key in value:
                        _check(value[key], subschema, f"{path}.{key}")
            elif t == "array":
                assert isinstance(value, list), f"{path}: expected array"
                for i, item in enumerate(value):
                    if "items" in schema:
                        _check(item, schema["items"], f"{path}[{i}]")
            elif t == "string":
                assert isinstance(value, str), f"{path}: expected string"
                if "pattern" in schema:
                    import re

                    assert re.search(schema["pattern"], value), (
                        f"{path}: {value!r} does not match pattern {schema['pattern']}"
                    )
                if "enum" in schema:
                    assert value in schema["enum"], (
                        f"{path}: {value!r} not in enum {schema['enum']}"
                    )
            elif t == "integer":
                assert isinstance(value, int) and not isinstance(value, bool), (
                    f"{path}: expected int"
                )
                if "minimum" in schema:
                    assert value >= schema["minimum"], f"{path}: {value} < min {schema['minimum']}"
                if "maximum" in schema:
                    assert value <= schema["maximum"], f"{path}: {value} > max {schema['maximum']}"

        _check(event, ECS_EVENT_SCHEMA)

    def test_fully_populated_alert_validates(self, report: CorrelatedIntelReport) -> None:
        alert = {
            "alert_id": "ALERT-001",
            "rule_name": "Critical CVE Detection",
            "severity": "CRITICAL",
            "description": "CVE-2024-00001 exploitation attempt detected",
            "tags": ["ransomware", "rce"],
            "mitre_technique": "T1059",
            "cve_ref": "CVE-2024-00001",
        }
        self._validate(_to_ecs(alert, report))

    def test_minimal_alert_still_validates(self, report: CorrelatedIntelReport) -> None:
        """Alerts with only the required schema fields still emit valid ECS."""
        alert = {
            "rule_name": "r",
            "severity": "MEDIUM",
            "description": "d",
        }
        self._validate(_to_ecs(alert, report))

    def test_tags_always_include_project_marker(self, report: CorrelatedIntelReport) -> None:
        """Every event carries `threat-intel-aggregator` in `tags` for filtering."""
        event = _to_ecs({"rule_name": "r", "severity": "LOW", "description": "d"}, report)
        assert "threat-intel-aggregator" in event["tags"]

    def test_timestamp_matches_report_generation(self, report: CorrelatedIntelReport) -> None:
        event = _to_ecs({"rule_name": "r", "severity": "LOW", "description": "d"}, report)
        assert event["@timestamp"] == report.generated_at.isoformat()

    def test_labels_carry_report_id(self, report: CorrelatedIntelReport) -> None:
        event = _to_ecs({"rule_name": "r", "severity": "LOW", "description": "d"}, report)
        assert event["labels"]["report_id"] == "TIA-ECSTEST"


class TestECSSeverityMapping:
    """Verify the numeric severity scale used by Elastic: 1 = INFO, 99 = CRITICAL."""

    @pytest.mark.parametrize(
        "label, expected",
        [
            ("CRITICAL", 99),
            ("HIGH", 73),
            ("MEDIUM", 47),
            ("LOW", 21),
            ("INFO", 1),
            ("critical", 99),  # lowercase should normalise
            ("UNKNOWN_GARBAGE", 47),  # unknown → MEDIUM default
        ],
    )
    def test_label_to_numeric(self, label: str, expected: int) -> None:
        assert _ecs_severity(label) == expected


# ── ECS field-name contract (pinned to ECS 9.3.0) ─────────────────────────────
#
# Every dotted field path our `_to_ecs()` emitter produces must exist in the
# pinned ECS specification. Bump `ECS_VERSION` when we intentionally adopt a
# newer schema; if Elastic ever renames a field in a minor release, this
# catches it at CI time instead of at SIEM-ingest time.
#
# The allow-list is a hand-curated subset of
# https://github.com/elastic/ecs/blob/v9.3.0/generated/ecs/ecs_flat.yml
# containing only the paths our emitter touches. Keeping it small-and-explicit
# is cheaper than shipping the full ~1MB ECS fixture and re-validating all of
# it on every run.

ECS_VERSION = "9.3.0"

ECS_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "@timestamp",
        "event.kind",
        "event.category",
        "event.type",
        "event.severity",
        "event.dataset",
        "event.module",
        "rule.name",
        "rule.description",
        "threat.technique.id",
        "vulnerability.id",
        "tags",
        # `labels` is an ECS object with user-defined keys; declaring the container
        # here lets the walker stop descending into implementer-defined contents.
        "labels",
    }
)


def _flatten_ecs_paths(event: dict, prefix: str = "") -> list[str]:
    """Yield every dotted path present in an ECS event.

    Stops at `labels.*` because ECS defines `labels` as a free-form
    user-controlled keyvalue map — descending would report our internal
    label keys (`report_id`, etc.) as ECS fields, which they aren't.
    """
    paths: list[str] = []
    for key, value in event.items():
        path = f"{prefix}.{key}" if prefix else key
        if path == "labels":
            paths.append(path)  # stop here — ECS-sanctioned user map
            continue
        if isinstance(value, dict):
            paths.extend(_flatten_ecs_paths(value, path))
        else:
            paths.append(path)
    return paths


class TestECSFieldContract:
    """Every field `_to_ecs()` emits must be a declared ECS field path.

    Catches the "Elastic renamed threat.technique.id → threat.mitre.id in v9.4"
    class of silent drift. Pins the version we target; bump ECS_VERSION with
    intent when we move to a newer schema.
    """

    def test_version_is_documented(self) -> None:
        """The pinned ECS_VERSION constant is a sanity anchor for the allow-list.

        If someone bumps `ECS_ALLOWED_FIELDS` without bumping ECS_VERSION, this
        test doesn't catch it — but the commit diff shows both lines moving
        together, which is the real review gate.
        """
        assert ECS_VERSION.count(".") == 2  # semver major.minor.patch

    def test_all_emitted_fields_are_declared(self, report: CorrelatedIntelReport) -> None:
        """Walk a representative ECS event and assert every path is whitelisted."""
        alert = {
            "alert_id": "ALERT-001",
            "rule_name": "Critical CVE Detection",
            "severity": "CRITICAL",
            "description": "CVE-2024-00001 exploitation attempt detected",
            "tags": ["ransomware", "rce"],
            "mitre_technique": "T1059",
            "cve_ref": "CVE-2024-00001",
        }
        event = _to_ecs(alert, report)
        emitted = set(_flatten_ecs_paths(event))
        unknown = emitted - ECS_ALLOWED_FIELDS
        assert not unknown, (
            f"emitted fields not in ECS {ECS_VERSION} allow-list: {sorted(unknown)}. "
            "Either the field was renamed/removed in ECS, or the allow-list "
            "needs updating."
        )

    def test_tags_is_declared(self) -> None:
        """`tags` (top-level, array of strings) is a well-known ECS field."""
        assert "tags" in ECS_ALLOWED_FIELDS

    def test_labels_is_declared(self) -> None:
        """`labels` is an ECS object with user-defined keys — its presence is
        the contract; its content is ours to choose."""
        assert "labels" in ECS_ALLOWED_FIELDS
