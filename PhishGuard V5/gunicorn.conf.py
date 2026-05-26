# gunicorn.conf.py

bind = "0.0.0.0:8000"

workers = 2

worker_class = "uvicorn.workers.UvicornWorker"

keepalive = 120

timeout = 60

graceful_timeout = 30

worker_connections = 1000

max_requests = 1000

max_requests_jitter = 50

accesslog = "-"

errorlog = "-"

loglevel = "info"

capture_output = True
