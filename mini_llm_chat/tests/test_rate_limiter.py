"""
Rate Limiter Tests Module

This module contains comprehensive unit tests for the rate limiting functionality.
It tests the sliding window rate limiting algorithm, edge cases, and error conditions.
"""

import time
from unittest.mock import patch

import pytest

from mini_llm_chat.rate_limiter import SimpleRateLimiter


class TestSimpleRateLimiter:
    """Test cases for the SimpleRateLimiter class."""

    def test_initialization_valid_parameters(self):
        """Test that rate limiter initializes correctly with valid parameters."""
        limiter = SimpleRateLimiter(max_calls=5, time_window=60)

        assert limiter.max_calls == 5
        assert limiter.time_window == 60
        assert limiter.calls == []

    def test_initialization_invalid_max_calls(self):
        """Test that initialization fails with invalid max_calls."""
        with pytest.raises(ValueError, match="max_calls must be a positive integer"):
            SimpleRateLimiter(max_calls=0, time_window=60)

        with pytest.raises(ValueError, match="max_calls must be a positive integer"):
            SimpleRateLimiter(max_calls=-1, time_window=60)

    def test_initialization_invalid_time_window(self):
        """Test that initialization fails with invalid time_window."""
        with pytest.raises(ValueError, match="time_window must be a positive integer"):
            SimpleRateLimiter(max_calls=5, time_window=0)

        with pytest.raises(ValueError, match="time_window must be a positive integer"):
            SimpleRateLimiter(max_calls=5, time_window=-1)

    def test_acquire_within_limit(self):
        """Test that acquire works when within rate limit."""
        limiter = SimpleRateLimiter(max_calls=3, time_window=60)

        # Should be able to make calls within limit
        limiter.acquire()  # Call 1
        limiter.acquire()  # Call 2
        limiter.acquire()  # Call 3

        assert len(limiter.calls) == 3

    @patch("time.time")
    @patch("time.sleep")
    def test_acquire_exceeds_limit_triggers_sleep(self, mock_sleep, mock_time):
        """Test that acquire sleeps when rate limit is exceeded."""
        # Mock time to control the sliding window - need enough values for all calls
        mock_time.side_effect = [1000.0] * 20  # Provide plenty of values

        limiter = SimpleRateLimiter(max_calls=2, time_window=60)

        # First two calls should work
        limiter.acquire()
        limiter.acquire()

        # Third call should trigger sleep
        limiter.acquire()

        # Verify sleep was called
        mock_sleep.assert_called_once()
        sleep_time = mock_sleep.call_args[0][0]
        assert sleep_time > 0

    @patch("time.time")
    def test_sliding_window_cleanup(self, mock_time):
        """Test that old calls are cleaned up from the sliding window."""
        # Mock time progression - need enough values for all time.time() calls
        mock_time.side_effect = [
            1000.0,  # First call cleanup
            1000.0,  # First call append
            1030.0,  # Second call cleanup
            1030.0,  # Second call append
            1070.0,  # Third call cleanup
            1070.0,  # Third call append
        ]

        limiter = SimpleRateLimiter(max_calls=2, time_window=60)

        # First call
        limiter.acquire()
        assert len(limiter.calls) == 1

        # Second call
        limiter.acquire()
        assert len(limiter.calls) == 2

        # Third call - first call should be cleaned up (older than 60 seconds)
        limiter.acquire()
        assert len(limiter.calls) == 2  # Old call cleaned up, new call added

    def test_get_remaining_calls_empty(self):
        """Test get_remaining_calls with no previous calls."""
        limiter = SimpleRateLimiter(max_calls=5, time_window=60)

        remaining = limiter.get_remaining_calls()
        assert remaining == 5

    def test_get_remaining_calls_with_calls(self):
        """Test get_remaining_calls with some previous calls."""
        limiter = SimpleRateLimiter(max_calls=5, time_window=60)

        # Make some calls
        limiter.acquire()
        limiter.acquire()

        remaining = limiter.get_remaining_calls()
        assert remaining == 3

    def test_get_remaining_calls_at_limit(self):
        """Test get_remaining_calls when at the limit."""
        limiter = SimpleRateLimiter(max_calls=2, time_window=60)

        # Make calls up to limit
        limiter.acquire()
        limiter.acquire()

        remaining = limiter.get_remaining_calls()
        assert remaining == 0

    @patch("time.time")
    def test_get_remaining_calls_with_expired_calls(self, mock_time):
        """Test get_remaining_calls cleans up expired calls."""
        # Mock time progression - need enough values for all time.time() calls
        mock_time.side_effect = [
            1000.0,  # First call cleanup
            1000.0,  # First call append
            1030.0,  # Second call cleanup
            1030.0,  # Second call append
            1070.0,  # get_remaining_calls check (70 seconds later)
        ]

        limiter = SimpleRateLimiter(max_calls=3, time_window=60)

        # Make calls
        limiter.acquire()  # This will be expired
        limiter.acquire()  # This will still be valid

        # Check remaining calls - should clean up expired call
        remaining = limiter.get_remaining_calls()
        assert remaining == 2  # 3 max - 1 valid call = 2 remaining

    def test_reset(self):
        """Test that reset clears all call history."""
        limiter = SimpleRateLimiter(max_calls=3, time_window=60)

        # Make some calls
        limiter.acquire()
        limiter.acquire()
        assert len(limiter.calls) == 2

        # Reset
        limiter.reset()
        assert len(limiter.calls) == 0

        # Should be able to make full quota of calls again
        remaining = limiter.get_remaining_calls()
        assert remaining == 3

    @patch("time.time")
    @patch("time.sleep")
    @patch("builtins.print")
    def test_acquire_prints_sleep_message(self, mock_print, mock_sleep, mock_time):
        """Test that acquire prints a message when sleeping."""
        mock_time.side_effect = [1000.0] * 10  # Provide enough values

        limiter = SimpleRateLimiter(max_calls=1, time_window=60)

        # First call should work
        limiter.acquire()

        # Second call should trigger sleep and print message
        limiter.acquire()

        # Verify print was called with sleep message
        mock_print.assert_called()
        print_args = str(mock_print.call_args)
        assert "Rate limit exceeded" in print_args
        assert "Sleeping for" in print_args

    @patch("time.time")
    @patch("time.sleep")
    def test_sleep_time_calculation(self, mock_sleep, mock_time):
        """Test that sleep time is calculated correctly."""
        # Mock time: first call at 1000, second call at 1010
        mock_time.side_effect = [
            1000.0,
            1000.0,
            1010.0,
            1010.0,
            1010.0,
        ]  # Provide enough values

        limiter = SimpleRateLimiter(max_calls=1, time_window=60)

        # First call
        limiter.acquire()

        # Second call should sleep for remaining time + buffer
        limiter.acquire()

        # Sleep time should be: 60 - (1010 - 1000) + 0.1 = 50.1 seconds
        expected_sleep_time = 60 - 10 + 0.1
        mock_sleep.assert_called_once_with(expected_sleep_time)

    def test_multiple_acquire_cycles(self):
        """Test multiple acquire cycles to ensure state is maintained correctly."""
        limiter = SimpleRateLimiter(
            max_calls=2, time_window=1
        )  # Short window for testing

        # First cycle
        limiter.acquire()
        limiter.acquire()
        assert len(limiter.calls) == 2

        # Wait for window to expire
        time.sleep(1.1)

        # Second cycle - old calls should be cleaned up
        limiter.acquire()
        assert len(limiter.calls) == 1  # Only new call should remain

    def test_edge_case_zero_remaining_calls(self):
        """Test edge case where remaining calls calculation could go negative."""
        limiter = SimpleRateLimiter(max_calls=1, time_window=60)

        # Make maximum calls
        limiter.acquire()

        # Should return 0, not negative
        remaining = limiter.get_remaining_calls()
        assert remaining == 0

    @patch("time.time")
    def test_floating_point_precision_buffer(self, mock_time):
        """Test that floating point precision buffer prevents race conditions."""
        # Mock time to simulate edge case where timing is very close
        mock_time.side_effect = [
            1000.0,
            1000.0,
            1059.999999,
            1059.999999,
            1059.999999,
        ]  # Just under 60 seconds

        limiter = SimpleRateLimiter(max_calls=1, time_window=60)

        # First call
        limiter.acquire()

        # This call is just under the time window - should still trigger rate limiting
        # due to the 0.1 second buffer
        with patch("time.sleep") as mock_sleep:
            limiter.acquire()
            mock_sleep.assert_called_once()

    def test_concurrent_access_simulation(self):
        """Test behavior under simulated concurrent access."""
        limiter = SimpleRateLimiter(max_calls=5, time_window=60)

        # Simulate rapid successive calls
        for i in range(5):
            limiter.acquire()

        assert len(limiter.calls) == 5
        assert limiter.get_remaining_calls() == 0

    @patch("mini_llm_chat.rate_limiter.logging.getLogger")
    def test_logging_initialization(self, mock_get_logger):
        """Test that logger is properly initialized."""
        mock_logger = mock_get_logger.return_value

        limiter = SimpleRateLimiter(max_calls=5, time_window=60)

        # Verify logger was obtained and debug message was logged
        mock_get_logger.assert_called_once_with("mini_llm_chat.rate_limiter")
        mock_logger.debug.assert_called_once()

    @patch("mini_llm_chat.rate_limiter.logging.getLogger")
    def test_logging_during_acquire(self, mock_get_logger):
        """Test that appropriate log messages are generated during acquire."""
        mock_logger = mock_get_logger.return_value

        limiter = SimpleRateLimiter(max_calls=2, time_window=60)
        limiter.acquire()

        # Should log debug messages about active calls and permission
        debug_calls = mock_logger.debug.call_args_list
        assert len(debug_calls) >= 2  # At least initialization and acquire logs

    @patch("mini_llm_chat.rate_limiter.logging.getLogger")
    @patch("time.sleep")
    def test_logging_during_rate_limit(self, mock_sleep, mock_get_logger):
        """Test that info message is logged when rate limit is exceeded."""
        mock_logger = mock_get_logger.return_value

        limiter = SimpleRateLimiter(max_calls=1, time_window=60)
        limiter.acquire()  # First call
        limiter.acquire()  # Second call should trigger rate limit

        # Should log info message about rate limit exceeded
        info_calls = mock_logger.info.call_args_list
        assert len(info_calls) >= 1
        info_message = str(info_calls[-1])
        assert "Rate limit exceeded" in info_message

    @patch("mini_llm_chat.rate_limiter.logging.getLogger")
    def test_logging_during_reset(self, mock_get_logger):
        """Test that reset operation is logged."""
        mock_logger = mock_get_logger.return_value

        limiter = SimpleRateLimiter(max_calls=2, time_window=60)
        limiter.acquire()
        limiter.reset()

        # Should log debug message about reset
        debug_calls = mock_logger.debug.call_args_list
        reset_logged = any("reset" in str(call).lower() for call in debug_calls)
        assert reset_logged


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
