"""Run the Lab 2 MD5/Argon2 benchmark inside the web container.

Usage: docker compose exec -T web python - < class5/measure.py
The first two output lines follow the course's measurement example exactly.
"""

import hashlib
import json
import platform
import sys
import time

from argon2 import PasswordHasher


N = 100_000
t = time.time()
for _ in range(N):
    hashlib.md5(b"guess").hexdigest()
md5_seconds = time.time() - t
md5_rate = N / md5_seconds
print(f"MD5    : {md5_rate:,.0f} guesses/second")

ph = PasswordHasher()
t = time.time()
ph.hash("guess")
one = time.time() - t
argon2_rate = 1 / one
print(f"Argon2 : {one*1000:.0f} ms for ONE guess  ({1/one:.1f} guesses/second)")

measurement = {
    "md5": {
        "iterations": N,
        "seconds": md5_seconds,
        "rate": md5_rate,
        "daily": md5_rate * 86400,
    },
    "argon2": {
        "iterations": 1,
        "seconds": one,
        "rate": argon2_rate,
        "daily": argon2_rate * 86400,
    },
    "ratio": md5_rate / argon2_rate,
    "parameters": {
        "type": ph.type.name,
        "memory_cost": ph.memory_cost,
        "time_cost": ph.time_cost,
        "parallelism": ph.parallelism,
        "hash_len": ph.hash_len,
        "salt_len": ph.salt_len,
    },
    "python": {
        "version": sys.version,
        "implementation": platform.python_implementation(),
    },
    "platform": {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    },
}
print("MEASUREMENT_JSON=" + json.dumps(measurement, sort_keys=True))
