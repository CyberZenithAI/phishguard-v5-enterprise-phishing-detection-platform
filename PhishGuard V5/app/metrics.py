from prometheus_client import Counter

REQUESTS = Counter("requests_total", "Total API requests")

def track():
    REQUESTS.inc()