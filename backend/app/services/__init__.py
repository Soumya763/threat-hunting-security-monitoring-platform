"""
Service-layer package.

Business logic shared across API routes lives here so it doesn't get
duplicated between routers. Currently: lifecycle transition rules and
audit-log read/write helpers used by api/alerts.py and api/incidents.py.
"""
