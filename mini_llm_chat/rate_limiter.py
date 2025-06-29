"""Rate limiter using sliding window approach."""

import logging
import time
from typing import List


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: float = None):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


class SimpleRateLimiter:
    """Sliding window rate limiter for API calls."""

    def __init__(self, max_calls: int, time_window: int) -> None:
        """Initialize rate limiter with max calls per time window."""
        if max_calls <= 0:
            raise ValueError("max_calls must be a positive integer")
        if time_window <= 0:
            raise ValueError("time_window must be a positive integer")

        self.max_calls = max_calls
        self.time_window = time_window
        self.calls: List[float] = []
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Rate limiter initialized: {max_calls} calls per {time_window} seconds")

    def acquire(self) -> None:
        """Acquire permission to make an API call, blocking if rate limit exceeded."""
        current_time = time.time()

        # Remove expired calls from sliding window
        self.calls = [
            call_time
            for call_time in self.calls
            if current_time - call_time < self.time_window
        ]

        self.logger.debug(f"Active calls in window: {len(self.calls)}/{self.max_calls}")

        if len(self.calls) >= self.max_calls:
            oldest_call_time = self.calls[0]
            sleep_time = self.time_window - (current_time - oldest_call_time) + 0.1

            self.logger.info(f"Rate limit exceeded. Sleeping for {sleep_time:.2f} seconds.")
            print(f"Rate limit exceeded. Sleeping for {sleep_time:.2f} seconds.")
            time.sleep(sleep_time)

        self.calls.append(time.time())
        self.logger.debug(f"API call permitted. Total calls in window: {len(self.calls)}")

    def get_remaining_calls(self) -> int:
        """Get number of API calls remaining in current window."""
        current_time = time.time()

        self.calls = [
            call_time
            for call_time in self.calls
            if current_time - call_time < self.time_window
        ]

        return max(0, self.max_calls - len(self.calls))

    def reset(self) -> None:
        """Reset rate limiter by clearing all recorded calls."""
        self.calls.clear()
        self.logger.debug("Rate limiter reset - all call history cleared")
