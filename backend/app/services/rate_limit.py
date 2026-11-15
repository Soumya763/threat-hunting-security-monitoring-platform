"""Per-user sliding-window limiter for analysis submissions (in-process)."""

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException

from app.config import settings


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float):
        self._max = max_events
        self._window = window_seconds
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] > self._window:
                events.popleft()
            if len(events) >= self._max:
                raise HTTPException(
                    status_code=429,
                    detail="Too many analysis requests. Please wait a minute and try again.",
                )
            events.append(now)


submission_limiter = SlidingWindowLimiter(settings.analysis_submissions_per_minute, 60.0)
