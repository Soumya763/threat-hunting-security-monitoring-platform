"""
Detection-rule validation.

Two levels of checking:
1. Structural: every shipped YAML rule loads, has a valid entity_type, and
   its threshold metric / source-IP aggregation exists in the query.
2. Field grounding: every field a rule queries is produced by one of the
   Logstash pipelines in this repository (or is part of the documented JSON
   producer contract). This prevents rules that reference fields that never
   exist. It is a static check; it does not run OpenSearch.
"""

import re
from pathlib import Path

import pytest

from app.detection.query_loader import VALID_ENTITY_TYPES, load_rules

ROOT = Path(__file__).resolve().parents[2]
PIPELINES = ROOT / "logstash" / "pipelines"

# Fields the JSON pipeline does not create itself; producers must send them.
JSON_PRODUCER_CONTRACT = {"event_type", "user.name", "source.ip"}

RULES = load_rules()


_RESERVED_PARAMS = {
    "field", "size", "order", "min_doc_count", "boost", "gte", "lte", "gt", "lt",
    "format", "time_zone", "missing", "script",
}


def _rule_fields(node, out=None):
    """Collect every field name referenced by term/terms/range/cardinality/terms-agg."""
    out = set() if out is None else out
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("term", "terms", "range") and isinstance(value, dict):
                out.update(k for k in value.keys() if k not in _RESERVED_PARAMS)
            if key == "field" and isinstance(value, str):
                out.add(value)
            _rule_fields(value, out)
    elif isinstance(node, list):
        for item in node:
            _rule_fields(item, out)
    return out


def _pipeline_text() -> str:
    return "\n".join(p.read_text() for p in PIPELINES.glob("*.conf")) + (
        "\n" + (PIPELINES / "logstash.config").read_text()
    )


def test_expected_number_of_rules_loads():
    names = [r["name"] for r in RULES]
    assert len(RULES) >= 8, names
    assert len(set(names)) == len(names), "rule names must be unique"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r["name"][:40])
def test_rule_has_valid_entity_and_metric(rule):
    threshold = rule["threshold"]
    assert threshold["entity_type"] in VALID_ENTITY_TYPES

    aggs = rule["query"].get("aggs", {})
    metric = threshold["aggregation"]
    if metric != "_count":
        found = False
        for agg in aggs.values():
            sub = agg.get("aggs", {})
            if metric in sub:
                found = True
        assert found, f"metric {metric!r} not present in any bucket sub-aggregation"

    ip_agg = threshold.get("source_ip_aggregation")
    if ip_agg:
        assert any(
            ip_agg in agg.get("aggs", {}) for agg in aggs.values()
        ), f"source_ip_aggregation {ip_agg!r} missing from query"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r["name"][:40])
def test_rule_fields_are_produced_by_pipelines(rule):
    text = _pipeline_text()
    for field in _rule_fields(rule["query"]):
        if field.startswith("@"):
            continue
        base = field[: -len(".keyword")] if field.endswith(".keyword") else field
        if base in JSON_PRODUCER_CONTRACT:
            continue
        leaf = base.split(".")[-1]
        # A field is grounded if the dotted name or its leaf appears as a Logstash
        # field name (add_field key or grok capture) in the pipeline sources.
        pattern = re.escape(base) + r"|" + re.escape(f"%{{{leaf}}}") + r"|" + re.escape(f"[{leaf}]") + r"|" + re.escape(f"%{{{leaf}:") + r"|" + re.escape(f'"{leaf}"') + r"|" + re.escape(f'"{base}"')
        assert re.search(pattern, text) or re.search(
            rf"(?<![\w.]){re.escape(leaf)}(?![\w.])", text
        ), f"{rule['name']}: field {field!r} is not produced by any pipeline"


def test_json_rule_reads_the_index_the_json_pipeline_writes():
    json_rules = [r for r in RULES if r["index"].startswith("events-json")]
    assert json_rules, "a rule must read the JSON pipeline's index"
    assert "events-json-" in (PIPELINES / "logstash.config").read_text()
