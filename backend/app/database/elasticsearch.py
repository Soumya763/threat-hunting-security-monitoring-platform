"""
Elasticsearch client setup.

Provides a single shared client instance. Later stages (detection engine,
etc.) will query the indices that Logstash is already writing into.
"""

from elasticsearch import Elasticsearch

from app.config import settings

es_client = Elasticsearch(settings.elasticsearch_host)
