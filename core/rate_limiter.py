"""
core/rate_limiter.py
Sliding-window rate limiter for application actions and session protection.
"""

import time
from typing import Dict, List, Tuple


def check_sliding_window_rate_limit(
    tracker: Dict[str, List[float]],
    action: str,
    max_requests: int = 10,
    window_seconds: int = 60,
    current_time: float = None
) -> Tuple[bool, int]:
    """
    Sliding-window rate limiter on a tracker dictionary.
    Returns (is_allowed, seconds_to_wait).
    """
    if current_time is None:
        current_time = time.time()

    timestamps = tracker.get(action, [])
    # Evict expired entries
    timestamps = [t for t in timestamps if current_time - t < window_seconds]

    if len(timestamps) >= max_requests:
        oldest = timestamps[0]
        wait_sec = max(1, int(window_seconds - (current_time - oldest)) + 1)
        tracker[action] = timestamps
        return False, wait_sec

    timestamps.append(current_time)
    tracker[action] = timestamps
    return True, 0
