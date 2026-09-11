"""
Rule executor.

Takes a single rule dict, as returned by app.detection.query_loader.load_rules,
and runs it against Elasticsearch using the shared es_client. This only
executes the query and returns the raw response — it does not evaluate the
threshold, generate alerts, or schedule anything (later stages).
"""

from typing import Any

from opensearchpy.exceptions import OpenSearchException

from app.database.elasticsearch import es_client


class RuleExecutionError(Exception):
    """Raised when a rule fails to execute against Elasticsearch."""


def build_search_body(rule: dict[str, Any]) -> dict[str, Any]:
    """
    Build the Elasticsearch search() kwargs from a rule's `query` field.

    Rule YAML files combine filters and aggregations under a single `query`
    key (query.bool + query.aggs). A real search request needs `aggs` as a
    sibling of `query`, so split them apart here.
    """
    rule_query = rule["query"]

    body: dict[str, Any] = {"size": 0}

    if "bool" in rule_query:
        body["query"] = {"bool": rule_query["bool"]}

    if "aggs" in rule_query:
        body["aggs"] = rule_query["aggs"]

    return body


def execute_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a single loaded rule against Elasticsearch.

    Returns the raw Elasticsearch response as a plain dict.
    Raises RuleExecutionError if the request fails for any reason
    (connection issue, bad query, index problem, etc.).
    """
    index = rule.get("index")
    name = rule.get("name", "unknown rule")

    if not index:
        raise RuleExecutionError(f"Rule '{name}' has no 'index' to query")

    search_kwargs = build_search_body(rule)

    try:
        # opensearch-py's search() only accepts body/index/params/headers -
        # unlike elasticsearch-py 8.x, it does NOT accept top-level
        # query/aggs/size as separate keyword arguments. The whole search
        # body must be passed as a single `body=` dict.
        response = es_client.search(index=index, body=search_kwargs)
    except OpenSearchException as exc:
        # Base exception for all opensearch-py client/server errors -
        # connection failures, timeouts, non-2xx responses, etc. (covers
        # what ApiError/TransportError covered for elasticsearch-py).
        raise RuleExecutionError(
            f"Elasticsearch error while executing rule '{name}' "
            f"against index '{index}': {exc}"
        ) from exc
    except Exception as exc:
        raise RuleExecutionError(
            f"Unexpected error while executing rule '{name}' "
            f"against index '{index}': {exc}"
        ) from exc

    # opensearch-py's search() returns the deserialized response body
    # directly (a plain dict), unlike elasticsearch-py 8.x's
    # ObjectApiResponse wrapper - no .body access needed here anymore.
    return response


if __name__ == "__main__":
    from app.detection.query_loader import load_rules

    for rule in load_rules():
        try:
            result = execute_rule(rule)
            took = result.get("took")
            hits = result.get("hits", {}).get("total", {})
            print(f"{rule['name']}: took={took}ms hits={hits}")
        except RuleExecutionError as e:
            print(f"{rule['name']}: FAILED - {e}")
