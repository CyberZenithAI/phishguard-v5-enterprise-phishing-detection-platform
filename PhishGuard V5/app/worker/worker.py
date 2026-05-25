# app/worker/worker.py

import os
import time
import redis
import logging

logging.basicConfig(level=logging.INFO)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")

r = redis.Redis(
    host=REDIS_HOST,
    port=6379,
    decode_responses=True
)

while True:

    try:
        job = r.lpop("queue")

        if job:
            logging.info(f"Processing {job}")

    except Exception as e:
        logging.error(str(e))

    time.sleep(1)
