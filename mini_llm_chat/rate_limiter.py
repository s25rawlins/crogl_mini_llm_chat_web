"""
Rate Limiter Module

This module implements a simple token bucket rate limiter to control the frequency
of API calls to prevent abuse and manage costs when interacting with LLM APIs.

The rate limiter uses a sliding window approach where it tracks timestamps of
previous API calls and enforces a maximum number of calls within a specified
time window.
"""

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
    """
    A token bucket-style rate limiter implementation.

    This class implements rate limiting using a sliding window approach where:
    1. We track timestamps of all API calls within the current time window
    2. Before each new call, we remove expired timestamps (older than time_window)
    3. If we've reached max_calls, we sleep until the oldest call expires
    4. We add the current timestamp to track this new call

    This approach is simpler than a true token bucket but provides similar
    functionality for our use case.

    Design Decisions:
    - Uses sliding window instead of fixed window to provide smoother rate limiting
    - Stores timestamps in memory (suitable for single-process applications)
    - Blocks the calling thread when rate limit is exceeded (simple but effective)

    Alternative Approaches Considered:
    - Fixed window: Simpler but can allow bursts at window boundaries
    - True token bucket: More complex but allows for burst capacity
    - Redis-based: Better for distributed systems but overkill for this use case
    - Async/non-blocking: More complex and not needed for our CLI application
    """

    def __init__(self, max_calls: int, time_window: int) -> None:
        """
        Initialize the rate limiter.

        Args:
            max_calls (int): Maximum number of API calls allowed within the time window.
                           This prevents excessive API usage and helps manage costs.
            time_window (int): Time window in seconds for the rate limit.
                             Calls older than this are not counted toward the limit.

        Raises:
            ValueError: If max_calls or time_window are not positive integers.
        """
        # Input validation to prevent configuration errors
        if max_calls <= 0:
            raise ValueError("max_calls must be a positive integer")
        if time_window <= 0:
            raise ValueError("time_window must be a positive integer")

        self.max_calls = max_calls
        self.time_window = time_window

        # List to store timestamps of API calls within the current window
        # We use a list instead of a deque for simplicity, though deque would
        # be more efficient for large numbers of calls
        self.calls: List[float] = []

        # Set up logging for debugging rate limiting behavior
        self.logger = logging.getLogger(__name__)
        self.logger.debug(
            f"Rate limiter initialized: {max_calls} calls per {time_window} seconds"
        )

    def acquire(self) -> None:
        """
        Acquire permission to make an API call.

        This method implements the core rate limiting logic:
        1. Get current timestamp
        2. Remove expired call timestamps (sliding window cleanup)
        3. Check if we're at the rate limit
        4. If at limit, calculate sleep time and wait
        5. Record this call's timestamp

        The method blocks (sleeps) if the rate limit would be exceeded,
        ensuring that API calls never exceed the configured rate.

        Raises:
            No exceptions are raised - the method will always eventually succeed
            by sleeping if necessary.
        """
        current_time = time.time()

        # Clean up expired timestamps (sliding window approach)
        # This removes all calls that are older than our time window
        # List comprehension is used for efficiency and readability
        self.calls = [
            call_time
            for call_time in self.calls
            if current_time - call_time < self.time_window
        ]

        self.logger.debug(f"Active calls in window: {len(self.calls)}/{self.max_calls}")

        # Check if we've reached the rate limit
        if len(self.calls) >= self.max_calls:
            # Calculate how long we need to wait for the oldest call to expire
            # The oldest call is at index 0 since we maintain chronological order
            oldest_call_time = self.calls[0]
            sleep_time = self.time_window - (current_time - oldest_call_time)

            # Add a small buffer (0.1 seconds) to avoid race conditions
            # where we might still be at the limit due to floating-point precision
            sleep_time += 0.1

            self.logger.info(
                f"Rate limit exceeded. Sleeping for {sleep_time:.2f} seconds."
            )
            print(f"Rate limit exceeded. Sleeping for {sleep_time:.2f} seconds.")

            # Block the current thread until we can proceed
            # This is a simple approach suitable for our CLI application
            time.sleep(sleep_time)

        # Record this API call's timestamp
        # We append to maintain chronological order (oldest first)
        self.calls.append(time.time())

        self.logger.debug(
            f"API call permitted. Total calls in window: {len(self.calls)}"
        )

    def get_remaining_calls(self) -> int:
        """
        Get the number of API calls remaining in the current window.

        This is useful for displaying rate limit status to users or
        for making decisions about whether to make additional calls.

        Returns:
            int: Number of calls that can be made without hitting the rate limit.
        """
        current_time = time.time()

        # Clean up expired timestamps first
        self.calls = [
            call_time
            for call_time in self.calls
            if current_time - call_time < self.time_window
        ]

        return max(0, self.max_calls - len(self.calls))

    def reset(self) -> None:
        """
        Reset the rate limiter by clearing all recorded calls.

        This is primarily useful for testing or if you want to
        reset the rate limiting state for any reason.
        """
        self.calls.clear()
        self.logger.debug("Rate limiter reset - all call history cleared")
