from dataclasses import dataclass
from datetime import datetime, UTC
from uuid import uuid4


@dataclass(slots=True)
class ExecutionContext:

    correlation_id: str
    started_at: str

    @classmethod
    def create(cls) -> "ExecutionContext":

        return cls(
            correlation_id=str(uuid4()),
            started_at=datetime.now(UTC).isoformat(),
        )
