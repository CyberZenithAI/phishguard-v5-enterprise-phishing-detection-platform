import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        correlation_id = getattr(record, "correlation_id", None)
        if correlation_id:
            payload["correlation_id"] = correlation_id

        return json.dumps(payload)


def configure_logging() -> None:

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)
