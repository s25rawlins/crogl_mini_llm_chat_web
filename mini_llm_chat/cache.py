"""
Cache Module

This module provides caching functionality using Redis to improve performance
and reduce API calls. It implements conversation caching, rate limiting cache,
and general-purpose caching utilities.
"""

import json
import logging
import os
import pickle
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class CacheError(Exception):
    """Raised when cache operations fail."""

    pass


class BaseCache(ABC):
    """Base cache interface for different cache implementations."""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        pass

    @abstractmethod
    def clear(self) -> bool:
        """Clear all cache entries."""
        pass

    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get cache information and statistics."""
        pass


class MemoryCache(BaseCache):
    """Simple in-memory cache implementation for fallback."""

    def __init__(self, max_size: int = 1000):
        """
        Initialize memory cache.

        Args:
            max_size: Maximum number of items to store
        """
        self.cache: Dict[str, Any] = {}
        self.max_size = max_size
        self.access_order: List[str] = []
        logger.info(f"Initialized memory cache with max size {max_size}")

    def get(self, key: str) -> Optional[Any]:
        """Get value from memory cache."""
        if key in self.cache:
            # Update access order (LRU)
            self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in memory cache."""
        try:
            # Remove if already exists
            if key in self.cache:
                self.access_order.remove(key)

            # Add new item
            self.cache[key] = value
            self.access_order.append(key)

            # Evict oldest items if over max size
            while len(self.cache) > self.max_size:
                oldest_key = self.access_order.pop(0)
                del self.cache[oldest_key]

            # Note: TTL not implemented for memory cache
            if ttl:
                logger.debug(f"TTL {ttl} ignored for memory cache key {key}")

            return True
        except Exception as e:
            logger.error(f"Failed to set memory cache key {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from memory cache."""
        try:
            if key in self.cache:
                del self.cache[key]
                self.access_order.remove(key)
            return True
        except Exception as e:
            logger.error(f"Failed to delete memory cache key {key}: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in memory cache."""
        return key in self.cache

    def clear(self) -> bool:
        """Clear all memory cache entries."""
        try:
            self.cache.clear()
            self.access_order.clear()
            return True
        except Exception as e:
            logger.error(f"Failed to clear memory cache: {e}")
            return False

    def get_info(self) -> Dict[str, Any]:
        """Get memory cache information and statistics."""
        return {
            "backend": "memory",
            "keys": len(self.cache),
            "max_size": self.max_size,
            "memory_usage": 0,  # Not tracked for memory cache
        }


class RedisCache(BaseCache):
    """Redis-based cache implementation."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        decode_responses: bool = True,
    ):
        """
        Initialize Redis cache.

        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            decode_responses: Whether to decode responses
        """
        if not REDIS_AVAILABLE:
            raise CacheError(
                "Redis library not available. Install with: pip install redis"
            )

        try:
            self.redis_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=decode_responses,
                socket_connect_timeout=5,
                socket_timeout=5,
            )

            # Test connection
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {host}:{port}")

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise CacheError(f"Redis connection failed: {e}")

    def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache."""
        try:
            value = self.redis_client.get(key)
            if value is None:
                return None

            # Try to deserialize as JSON first, then pickle
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                try:
                    return pickle.loads(value)
                except (pickle.PickleError, TypeError):
                    # Return as string if deserialization fails
                    return value

        except Exception as e:
            logger.error(f"Failed to get Redis key {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in Redis cache."""
        try:
            # Serialize value
            if isinstance(value, (dict, list, tuple)):
                serialized_value = json.dumps(value)
            elif isinstance(value, (str, int, float, bool)):
                serialized_value = json.dumps(value)
            else:
                # Use pickle for complex objects
                serialized_value = pickle.dumps(value)

            # Set with optional TTL
            if ttl:
                result = self.redis_client.setex(key, ttl, serialized_value)
            else:
                result = self.redis_client.set(key, serialized_value)

            return bool(result)

        except Exception as e:
            logger.error(f"Failed to set Redis key {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from Redis cache."""
        try:
            result = self.redis_client.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Failed to delete Redis key {key}: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in Redis cache."""
        try:
            return bool(self.redis_client.exists(key))
        except Exception as e:
            logger.error(f"Failed to check Redis key existence {key}: {e}")
            return False

    def clear(self) -> bool:
        """Clear all Redis cache entries."""
        try:
            result = self.redis_client.flushdb()
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to clear Redis cache: {e}")
            return False

    def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a counter in Redis."""
        try:
            return self.redis_client.incrby(key, amount)
        except Exception as e:
            logger.error(f"Failed to increment Redis key {key}: {e}")
            return None

    def expire(self, key: str, ttl: int) -> bool:
        """Set expiration time for a key."""
        try:
            return bool(self.redis_client.expire(key, ttl))
        except Exception as e:
            logger.error(f"Failed to set expiration for Redis key {key}: {e}")
            return False

    def get_info(self) -> Dict[str, Any]:
        """Get Redis cache information and statistics."""
        try:
            info = self.redis_client.info()
            return {
                "backend": "redis",
                "keys": self.redis_client.dbsize(),
                "memory_usage": info.get("used_memory", 0),
            }
        except Exception as e:
            logger.error(f"Failed to get Redis info: {e}")
            return {
                "backend": "redis",
                "keys": 0,
                "memory_usage": 0,
            }


class CacheManager:
    """High-level cache manager that handles different cache backends."""

    def __init__(self, cache_backend: Optional[BaseCache] = None):
        """
        Initialize cache manager.

        Args:
            cache_backend: Cache backend to use (auto-detects if None)
        """
        if cache_backend:
            self.cache = cache_backend
        else:
            self.cache = self._initialize_cache()

        logger.info(f"Cache manager initialized with {type(self.cache).__name__}")

    def _initialize_cache(self) -> BaseCache:
        """Initialize cache backend based on environment and availability."""
        # Try Redis first if available and configured
        redis_url = os.getenv("REDIS_URL")
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_password = os.getenv("REDIS_PASSWORD")

        if REDIS_AVAILABLE and (redis_url or redis_host):
            try:
                if redis_url:
                    # Parse Redis URL
                    import urllib.parse

                    parsed = urllib.parse.urlparse(redis_url)
                    return RedisCache(
                        host=parsed.hostname or "localhost",
                        port=parsed.port or 6379,
                        password=parsed.password,
                    )
                else:
                    return RedisCache(
                        host=redis_host, port=redis_port, password=redis_password
                    )
            except Exception as e:
                logger.warning(f"Failed to initialize Redis cache: {e}")
                logger.info("Falling back to memory cache")

        # Fallback to memory cache
        return MemoryCache()

    def cache_conversation(
        self,
        user_id: int,
        conversation_id: int,
        messages: List[Dict[str, Any]],
        ttl: int = 3600,
    ) -> bool:
        """
        Cache conversation messages.

        Args:
            user_id: User ID
            conversation_id: Conversation ID
            messages: List of message dictionaries
            ttl: Time to live in seconds

        Returns:
            bool: True if successful
        """
        key = f"conversation:{user_id}:{conversation_id}"
        return self.cache.set(key, messages, ttl)

    def get_cached_conversation(
        self, user_id: int, conversation_id: int
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached conversation messages.

        Args:
            user_id: User ID
            conversation_id: Conversation ID

        Returns:
            Optional[List[Dict[str, Any]]]: Cached messages or None
        """
        key = f"conversation:{user_id}:{conversation_id}"
        return self.cache.get(key)

    def cache_user_session(
        self, user_id: int, session_data: Dict[str, Any], ttl: int = 86400
    ) -> bool:
        """
        Cache user session data.

        Args:
            user_id: User ID
            session_data: Session data to cache
            ttl: Time to live in seconds (default 24 hours)

        Returns:
            bool: True if successful
        """
        key = f"session:{user_id}"
        return self.cache.set(key, session_data, ttl)

    def get_cached_session(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get cached user session data.

        Args:
            user_id: User ID

        Returns:
            Optional[Dict[str, Any]]: Cached session data or None
        """
        key = f"session:{user_id}"
        return self.cache.get(key)

    def cache_api_response(
        self, request_hash: str, response: Any, ttl: int = 300
    ) -> bool:
        """
        Cache API response to reduce duplicate calls.

        Args:
            request_hash: Hash of the request parameters
            response: API response to cache
            ttl: Time to live in seconds (default 5 minutes)

        Returns:
            bool: True if successful
        """
        key = f"api_response:{request_hash}"
        return self.cache.set(key, response, ttl)

    def get_cached_api_response(self, request_hash: str) -> Optional[Any]:
        """
        Get cached API response.

        Args:
            request_hash: Hash of the request parameters

        Returns:
            Optional[Any]: Cached response or None
        """
        key = f"api_response:{request_hash}"
        return self.cache.get(key)

    def invalidate_user_cache(self, user_id: int) -> bool:
        """
        Invalidate all cache entries for a user.

        Args:
            user_id: User ID

        Returns:
            bool: True if successful
        """
        try:
            # Delete session cache
            session_key = f"session:{user_id}"
            self.cache.delete(session_key)

            # For conversation cache, we'd need to track conversation IDs
            # This is a simplified implementation
            logger.info(f"Invalidated cache for user {user_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to invalidate cache for user {user_id}: {e}")
            return False

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict[str, Any]: Cache statistics
        """
        stats = {"backend": type(self.cache).__name__, "available": True}

        if isinstance(self.cache, RedisCache):
            try:
                info = self.cache.redis_client.info()
                stats.update(
                    {
                        "connected_clients": info.get("connected_clients", 0),
                        "used_memory": info.get("used_memory_human", "unknown"),
                        "keyspace_hits": info.get("keyspace_hits", 0),
                        "keyspace_misses": info.get("keyspace_misses", 0),
                    }
                )
            except Exception as e:
                logger.error(f"Failed to get Redis stats: {e}")
                stats["error"] = str(e)
        elif isinstance(self.cache, MemoryCache):
            stats.update(
                {"items_count": len(self.cache.cache), "max_size": self.cache.max_size}
            )

        return stats


# Global cache manager instance
cache_manager = CacheManager()


def get_cache() -> CacheManager:
    """Get the global cache manager instance."""
    return cache_manager


def hash_request(messages: List[Dict[str, Any]], model: str, temperature: float) -> str:
    """
    Create a hash for API request parameters to use as cache key.

    Args:
        messages: List of messages
        model: Model name
        temperature: Temperature parameter

    Returns:
        str: Hash of the request parameters
    """
    import hashlib

    # Create a deterministic string representation
    request_data = {"messages": messages, "model": model, "temperature": temperature}

    request_str = json.dumps(request_data, sort_keys=True)
    return hashlib.sha256(request_str.encode()).hexdigest()[:16]
