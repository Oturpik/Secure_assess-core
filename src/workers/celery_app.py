from celery import Celery
from src.config import settings  # Import settings directly

# Initialize Celery app
celery_app = Celery(
    "secure_assess",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "src.workers.sast_worker"  # Only include SAST worker for now
    ]
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour timeout for tasks
    worker_prefetch_multiplier=1,  # Disable prefetching
    task_routes={
        "src.workers.sast_worker.*": {"queue": "sast"},
        "src.workers.dast_worker.*": {"queue": "dast"},
        "src.workers.sca_worker.*": {"queue": "sca"},
        "src.workers.cleanup_worker.*": {"queue": "cleanup"}
    }
)

# Optional: Configure task priority
celery_app.conf.task_queue_max_priority = 10
celery_app.conf.task_default_priority = 5

if __name__ == "__main__":
    celery_app.start()
