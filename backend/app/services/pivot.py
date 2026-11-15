"""
Local-context pivots: search the platform's own log indices in OpenSearch for an
indicator.

Read-only: the query is built here from a validated indicator, never from raw
user input, and it is limited to the log index patterns in settings and to a
lookback window. If the search service is unreachable, the result says so; it
never reports "no matching events" for a search that did not run.

Limitation: the Logstash pipelines do not index file hashes, so hash pivots
currently return zero events unless a producer sends hashes into the logs.
"""

import logging
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

MAX_SAMPLES = 10


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _pick(source: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
        if "." in key:
            node: Any = source
            for part in key.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            if node not in (None, ""):
                return node
    return None


def search_local_context(value: str, *, lookback_days: int | None = None) -> dict[str, Any]:
    from app.database.opensearch import opensearch_client

    days = lookback_days or settings.pivot_lookback_days
    body = {
        "size": MAX_SAMPLES,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "must": [{"query_string": {"query": f'"{_escape(value)}"', "lenient": True}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}}],
            }
        },
        "aggs": {
            "event_types": {"terms": {"field": "event_type.keyword", "size": 10}},
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen": {"max": {"field": "@timestamp"}},
        },
    }
    base = {"status": "unavailable", "lookback_days": days, "total": None, "event_types": [],
            "first_seen": None, "last_seen": None, "samples": [], "message": None,
            "indices": settings.opensearch_log_indices}
    try:
        response = opensearch_client.search(index=settings.opensearch_log_indices, body=body, request_timeout=8)
    except Exception as exc:  # connection, auth, index errors
        logger.warning("Local log pivot failed: %s", type(exc).__name__)
        base["message"] = "Local log search is unavailable, so no conclusion can be drawn from it."
        return base

    hits = response.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    aggs = response.get("aggregations", {})
    samples = []
    for hit in hits.get("hits", []):
        src = hit.get("_source", {})
        samples.append({
            "timestamp": src.get("@timestamp"),
            "index": hit.get("_index"),
            "event_type": src.get("event_type"),
            "source_ip": _pick(src, "source.ip", "source_ip"),
            "destination_ip": _pick(src, "destination.ip", "destination_ip"),
            "host": _pick(src, "source_name"),
            "summary": str(src.get("message") or "")[:200] or None,
        })

    base.update({
        "status": "ok",
        "total": total,
        "event_types": [{"event_type": b["key"], "count": b["doc_count"]}
                        for b in aggs.get("event_types", {}).get("buckets", [])],
        "first_seen": aggs.get("first_seen", {}).get("value_as_string"),
        "last_seen": aggs.get("last_seen", {}).get("value_as_string"),
        "samples": samples,
        "message": None if total else f"No matching events in the last {days} day(s).",
    })
    return base
