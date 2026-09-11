"""
Focused regression test for app.detection.executor.execute_rule's
OpenSearch client call shape.

Guards against the exact production bug this test was written for:
opensearch-py 3.2.0's OpenSearch.search() only accepts a `body` keyword
argument (plus index/params/headers) - it does NOT accept top-level
query/aggs/size as separate keyword arguments the way elasticsearch-py's
Elasticsearch.search() did. Passing **search_kwargs (spreading
size/query/aggs as separate kwargs) raised, in production:
    OpenSearch.search() got an unexpected keyword argument 'query'

This mocks es_client.search (no real OpenSearch connection needed) and
asserts it is called with a single body= dict - never with query/aggs/size
spread as top-level kwargs - and that the plain dict search() returns is
passed straight through unchanged.
"""

from unittest.mock import patch

from app.detection import executor

# Same shape as threat_hunting_queries/templates/lateral_movement.yaml -
# the actual rule that failed in production.
RULE = {
    "name": "Lateral Movement - Multiple Host Logins by Single User",
    "index": "events-windows-*",
    "query": {
        "bool": {
            "filter": [
                {"term": {"event_type.keyword": "windows_login"}},
                {"range": {"@timestamp": {"gte": "now-15m", "lte": "now"}}},
            ]
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "username.keyword", "size": 50},
                "aggs": {"distinct_hosts": {"cardinality": {"field": "source_name.keyword"}}},
            }
        },
    },
    "threshold": {"aggregation": "distinct_hosts", "min_count": 3, "window_minutes": 15},
}


def test_execute_rule_calls_search_with_body_kwarg_not_spread():
    """The exact production regression: search() must be called with a
    single body= dict, never with query/aggs/size spread as separate
    keyword arguments (which opensearch-py 3.2.0 rejects outright)."""
    fake_response = {"took": 3, "hits": {"total": {"value": 0}}, "aggregations": {}}

    with patch.object(executor.es_client, "search", return_value=fake_response) as mock_search:
        result = executor.execute_rule(RULE)

    mock_search.assert_called_once()
    _, kwargs = mock_search.call_args
    assert kwargs.get("index") == "events-windows-*"
    assert "body" in kwargs, "search() must be called with a body= dict, not spread kwargs"
    assert kwargs["body"] == executor.build_search_body(RULE)
    # These leaking through as top-level kwargs is exactly what broke
    # against opensearch-py 3.2.0.
    assert "query" not in kwargs
    assert "aggs" not in kwargs
    assert "size" not in kwargs
    assert result == fake_response


def test_execute_rule_returns_plain_dict_unchanged():
    """opensearch-py's search() already returns a plain dict - execute_rule
    must return it as-is, with no .body unwrapping."""
    fake_response = {"took": 1, "hits": {}, "aggregations": {"by_user": {"buckets": []}}}

    with patch.object(executor.es_client, "search", return_value=fake_response):
        result = executor.execute_rule(RULE)

    assert result is fake_response


def test_execute_rule_wraps_search_exception():
    """An OpenSearchException from the client is still wrapped as
    RuleExecutionError with the original message prefix - unrelated
    error-handling behavior, unchanged by this fix."""
    from opensearchpy.exceptions import ConnectionError as OSConnectionError

    with patch.object(executor.es_client, "search", side_effect=OSConnectionError("boom")):
        try:
            executor.execute_rule(RULE)
            assert False, "expected RuleExecutionError"
        except executor.RuleExecutionError as e:
            assert str(e).startswith(
                "Elasticsearch error while executing rule "
                "'Lateral Movement - Multiple Host Logins by Single User'"
            )
