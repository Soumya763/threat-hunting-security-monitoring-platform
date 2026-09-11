"""
OpenSearch/Elasticsearch client setup.

Provides a single shared client instance. Later stages (detection engine,
etc.) will query the indices that Logstash is already writing into.

Uses the opensearch-py client rather than the official elasticsearch-py
client because elasticsearch-py 8.x refuses to talk to genuine OpenSearch
servers (it raises UnsupportedProductError against anything that doesn't
identify itself as Elastic's own product via a response header) -
opensearch-py has no such restriction, so the same client works against
either. settings.elasticsearch_host is passed through unchanged, exactly
as before: locally it's a plain http:// URL with no auth (matching
docker-compose's unauthenticated Elasticsearch 8.15.3 container);
in production it can be an authenticated https:// service URI (e.g. an
Aiven OpenSearch "Service URI" with the username/password embedded
directly in the URL) - the scheme and any embedded credentials are
parsed from that single URL string, so no separate config fields are
needed for auth/TLS.
"""

from opensearchpy import OpenSearch

from app.config import settings

es_client = OpenSearch(settings.elasticsearch_host)
