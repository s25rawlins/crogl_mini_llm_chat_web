"""
Cache Tests Module

This module contains comprehensive unit tests for the caching functionality.
It tests Redis caching, fallback behavior, and cache operations.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from mini_llm_chat.cache import (
    BaseCache,
    CacheManager,
    MemoryCache,
    RedisCache,
    get_cache,
    hash_request,
)


class TestBaseCache:
    """Test cases for the BaseCache abstract base class."""

    def test_base_cache_is_abstract(self):
        """Test that BaseCache cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseCache()


class TestMemoryCache:
    """Test cases for the MemoryCache implementation."""

    def test_memory_cache_initialization(self):
        """Test MemoryCache initialization."""
        cache = MemoryCache()
        assert cache.cache == {}

    def test_memory_cache_set_and_get(self):
        """Test setting and getting values from memory cache."""
        cache = MemoryCache()

        result = cache.set("test_key", "test_value")
        assert result is True

        value = cache.get("test_key")
        assert value == "test_value"

    def test_memory_cache_get_nonexistent_key(self):
        """Test getting a non-existent key returns None."""
        cache = MemoryCache()

        result = cache.get("nonexistent_key")

        assert result is None

    def test_memory_cache_delete_existing_key(self):
        """Test deleting an existing key."""
        cache = MemoryCache()
        cache.set("test_key", "test_value")

        result = cache.delete("test_key")
        assert result is True

        value = cache.get("test_key")
        assert value is None

    def test_memory_cache_delete_nonexistent_key(self):
        """Test deleting a non-existent key doesn't raise error."""
        cache = MemoryCache()

        result = cache.delete("nonexistent_key")
        assert result is True

    def test_memory_cache_clear(self):
        """Test clearing all cache entries."""
        cache = MemoryCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        result = cache.clear()
        assert result is True

        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.cache == {}

    def test_memory_cache_exists_true(self):
        """Test exists method returns True for existing key."""
        cache = MemoryCache()
        cache.set("test_key", "test_value")

        result = cache.exists("test_key")

        assert result is True

    def test_memory_cache_exists_false(self):
        """Test exists method returns False for non-existent key."""
        cache = MemoryCache()

        result = cache.exists("nonexistent_key")

        assert result is False

    def test_memory_cache_max_size_eviction(self):
        """Test that memory cache evicts old items when max size is reached."""
        cache = MemoryCache(max_size=2)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")  # Should evict key1

        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"


class TestRedisCache:
    """Test cases for the RedisCache implementation."""

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_initialization_success(self, mock_redis_class):
        """Test successful Redis cache initialization."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)

        assert cache.redis_client == mock_redis
        mock_redis.ping.assert_called_once()

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_initialization_connection_error(self, mock_redis_class):
        """Test Redis cache initialization with connection error."""
        mock_redis = MagicMock()
        mock_redis.ping.side_effect = Exception("Connection failed")
        mock_redis_class.return_value = mock_redis

        with pytest.raises(Exception, match="Connection failed"):
            RedisCache(host="localhost", port=6379)

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_set_success(self, mock_redis_class):
        """Test successful Redis set operation."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        cache.set("test_key", "test_value", ttl=300)

        mock_redis.setex.assert_called_once_with("test_key", 300, '"test_value"')

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_set_error(self, mock_redis_class):
        """Test Redis set operation with error."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)

        # Should not raise exception, just log error
        cache.set("test_key", "test_value")

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_get_success(self, mock_redis_class):
        """Test successful Redis get operation."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.get.return_value = b'"test_value"'
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        result = cache.get("test_key")

        assert result == "test_value"
        mock_redis.get.assert_called_once_with("test_key")

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_get_not_found(self, mock_redis_class):
        """Test Redis get operation when key not found."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.get.return_value = None
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        result = cache.get("nonexistent_key")

        assert result is None

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_get_error(self, mock_redis_class):
        """Test Redis get operation with error."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.get.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        result = cache.get("test_key")

        assert result is None

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_delete_success(self, mock_redis_class):
        """Test successful Redis delete operation."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.delete.return_value = 1
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        cache.delete("test_key")

        mock_redis.delete.assert_called_once_with("test_key")

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_delete_error(self, mock_redis_class):
        """Test Redis delete operation with error."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.delete.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)

        # Should not raise exception, just log error
        cache.delete("test_key")

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_clear_success(self, mock_redis_class):
        """Test successful Redis clear operation."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.flushdb.return_value = True
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        cache.clear()

        mock_redis.flushdb.assert_called_once()

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_clear_error(self, mock_redis_class):
        """Test Redis clear operation with error."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.flushdb.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)

        # Should not raise exception, just log error
        cache.clear()

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_exists_true(self, mock_redis_class):
        """Test Redis exists operation returns True."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.exists.return_value = 1
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        result = cache.exists("test_key")

        assert result is True
        mock_redis.exists.assert_called_once_with("test_key")

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_exists_false(self, mock_redis_class):
        """Test Redis exists operation returns False."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.exists.return_value = 0
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        result = cache.exists("test_key")

        assert result is False

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_exists_error(self, mock_redis_class):
        """Test Redis exists operation with error."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.exists.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        result = cache.exists("test_key")

        assert result is False

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_get_info_success(self, mock_redis_class):
        """Test successful Redis get_info operation."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.dbsize.return_value = 5
        mock_redis.info.return_value = {"used_memory": 1024}
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        info = cache.get_info()

        assert info["backend"] == "redis"
        assert info["keys"] == 5
        assert info["memory_usage"] == 1024

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_get_info_error(self, mock_redis_class):
        """Test Redis get_info operation with error."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.dbsize.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)
        info = cache.get_info()

        assert info["backend"] == "redis"
        assert info["keys"] == 0
        assert info["memory_usage"] == 0

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_json_serialization(self, mock_redis_class):
        """Test Redis cache handles complex data types via JSON."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True
        mock_redis.get.return_value = b'{"key": "value", "number": 42}'
        mock_redis_class.return_value = mock_redis

        cache = RedisCache(host="localhost", port=6379)

        # Test setting complex data
        test_data = {"key": "value", "number": 42}
        cache.set("test_key", test_data)

        # Verify JSON serialization was used
        expected_json = json.dumps(test_data)
        mock_redis.set.assert_called_with("test_key", expected_json)

        # Test getting complex data
        result = cache.get("test_key")
        assert result == test_data


class TestCacheManager:
    """Test cases for the CacheManager class."""

    def test_cache_manager_initialization(self):
        """Test CacheManager initialization."""
        manager = CacheManager()
        assert manager.cache is not None

    def test_cache_manager_with_custom_backend(self):
        """Test CacheManager with custom backend."""
        custom_cache = MemoryCache()
        manager = CacheManager(cache_backend=custom_cache)
        assert manager.cache == custom_cache

    def test_cache_conversation(self):
        """Test caching conversation messages."""
        manager = CacheManager(cache_backend=MemoryCache())
        messages = [{"role": "user", "content": "Hello"}]

        result = manager.cache_conversation(1, 1, messages)
        assert result is True

        cached = manager.get_cached_conversation(1, 1)
        assert cached == messages

    def test_cache_user_session(self):
        """Test caching user session data."""
        manager = CacheManager(cache_backend=MemoryCache())
        session_data = {"user_id": 1, "preferences": {}}

        result = manager.cache_user_session(1, session_data)
        assert result is True

        cached = manager.get_cached_session(1)
        assert cached == session_data

    def test_cache_api_response(self):
        """Test caching API responses."""
        manager = CacheManager(cache_backend=MemoryCache())
        response = {"choices": [{"message": {"content": "Hello"}}]}

        result = manager.cache_api_response("hash123", response)
        assert result is True

        cached = manager.get_cached_api_response("hash123")
        assert cached == response

    def test_invalidate_user_cache(self):
        """Test invalidating user cache."""
        manager = CacheManager(cache_backend=MemoryCache())
        session_data = {"user_id": 1}

        manager.cache_user_session(1, session_data)
        result = manager.invalidate_user_cache(1)
        assert result is True

        cached = manager.get_cached_session(1)
        assert cached is None

    def test_get_cache_stats(self):
        """Test getting cache statistics."""
        manager = CacheManager(cache_backend=MemoryCache())
        stats = manager.get_cache_stats()

        assert "backend" in stats
        assert stats["available"] is True


class TestHashRequest:
    """Test cases for the hash_request function."""

    def test_hash_request_consistent(self):
        """Test that hash_request produces consistent results."""
        messages = [{"role": "user", "content": "Hello"}]
        model = "gpt-3.5-turbo"
        temperature = 0.7

        hash1 = hash_request(messages, model, temperature)
        hash2 = hash_request(messages, model, temperature)

        assert hash1 == hash2

    def test_hash_request_different_inputs(self):
        """Test that different inputs produce different hashes."""
        messages1 = [{"role": "user", "content": "Hello"}]
        messages2 = [{"role": "user", "content": "Hi"}]
        model = "gpt-3.5-turbo"
        temperature = 0.7

        hash1 = hash_request(messages1, model, temperature)
        hash2 = hash_request(messages2, model, temperature)

        assert hash1 != hash2

    def test_hash_request_length(self):
        """Test that hash_request produces expected length."""
        messages = [{"role": "user", "content": "Hello"}]
        model = "gpt-3.5-turbo"
        temperature = 0.7

        hash_result = hash_request(messages, model, temperature)

        assert len(hash_result) == 16  # Truncated to 16 characters


class TestGetCache:
    """Test cases for the get_cache function."""

    def test_get_cache_returns_manager(self):
        """Test that get_cache returns a CacheManager instance."""
        cache = get_cache()
        assert isinstance(cache, CacheManager)


class TestCacheIntegration:
    """Integration tests for cache functionality."""

    def test_memory_cache_integration(self):
        """Test memory cache with realistic usage patterns."""
        cache = MemoryCache()

        # Test storing different data types
        cache.set("string", "hello")
        cache.set("number", 42)
        cache.set("list", [1, 2, 3])
        cache.set("dict", {"key": "value"})

        # Test retrieval
        assert cache.get("string") == "hello"
        assert cache.get("number") == 42
        assert cache.get("list") == [1, 2, 3]
        assert cache.get("dict") == {"key": "value"}

        # Test existence checks
        assert cache.exists("string") is True
        assert cache.exists("nonexistent") is False

        # Test deletion
        cache.delete("string")
        assert cache.exists("string") is False
        assert cache.get("string") is None

        # Test info
        info = cache.get_info()
        assert info["backend"] == "memory"
        assert info["keys"] == 3  # string was deleted

    @patch("mini_llm_chat.cache.redis.Redis")
    def test_redis_cache_integration(self, mock_redis_class):
        """Test Redis cache with realistic usage patterns."""
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis_class.return_value = mock_redis

        # Mock Redis responses
        mock_redis.set.return_value = True
        mock_redis.get.side_effect = [
            b'"hello"',  # string value
            b"42",  # number value
            b"[1, 2, 3]",  # list value
            None,  # deleted value
        ]
        mock_redis.exists.side_effect = [1, 0, 0]  # exists, not exists, not exists
        mock_redis.delete.return_value = 1
        mock_redis.dbsize.return_value = 2
        mock_redis.info.return_value = {"used_memory": 2048}

        cache = RedisCache(host="localhost", port=6379)

        # Test storing different data types
        cache.set("string", "hello")
        cache.set("number", 42)
        cache.set("list", [1, 2, 3])

        # Test retrieval
        assert cache.get("string") == "hello"
        assert cache.get("number") == 42
        assert cache.get("list") == [1, 2, 3]

        # Test existence checks
        assert cache.exists("string") is True
        assert cache.exists("nonexistent") is False

        # Test deletion
        cache.delete("string")
        assert cache.get("string") is None

        # Test info
        info = cache.get_info()
        assert info["backend"] == "redis"
        assert info["keys"] == 2
        assert info["memory_usage"] == 2048


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
