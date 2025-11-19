"""
Script to start a Celery worker dedicated to SAST scanning.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.workers.celery_app import celery_app
from src.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)

if __name__ == "__main__":
    logger.info("Starting SAST worker...")
    
    # Set Celery worker environment variables
    os.environ["CELERY_BROKER_URL"] = settings.celery_broker_url
    os.environ["CELERY_RESULT_BACKEND"] = settings.celery_result_backend
    
    # Start the worker with specific queue and concurrency
    celery_args = [
        "worker",
        "--loglevel=INFO",
        "--queues=sast",  # Only process SAST tasks
        "--concurrency=2",  # Number of concurrent tasks
        "--pool=solo",  # Use solo pool for Windows compatibility
        "--hostname=sast@%h"  # Unique hostname for SAST worker
    ]
    
    celery_app.worker_main(celery_args)