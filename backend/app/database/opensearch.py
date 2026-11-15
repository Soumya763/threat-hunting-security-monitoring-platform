"""
OpenSearch client setup (the project's search and log analytics engine).

A single shared client is created from settings.opensearch_host, which is one
URL. Its scheme and any embedded credentials are read from that string. Local
development uses the unauthenticated OpenSearch container from
docker-compose.yml; production can use an authenticated HTTPS endpoint, for
example a managed OpenSearch "Service URI" with the credentials embedded.

The opensearch-py client is used on purpose: the elasticsearch-py client
refuses to talk to OpenSearch servers because they do not identify as the
Elastic product.
"""

from opensearchpy import OpenSearch

from app.config import settings

opensearch_client = OpenSearch(settings.opensearch_host)
