import time
import redis

r = redis.Redis(host="redis", decode_responses=True)

while True:
    job = r.lpop("queue")
    if job:
        print(f"Processing {job}")
    time.sleep(1)