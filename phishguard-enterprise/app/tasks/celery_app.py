from celery import Celery
from app.core.config import settings
from app.analysis.domain_analyzer import analyze_domain

celery_app = Celery(
    "phishguard",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
)

@celery_app.task(name="analyze_domain", bind=True)
def analyze_domain_task(self, url: str):
    import asyncio
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(analyze_domain(url))
    return {"task_id": self.request.id, "status": "completed", **result}
