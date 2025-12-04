"""
Caching utilities for performance optimization
"""
from functools import lru_cache, wraps
from datetime import datetime, timedelta
import hashlib
import json
from flask import g, request

# In-memory cache with TTL
_cache = {}
_cache_ttl = {}

def cache_key(*args, **kwargs):
    """Generate a cache key from function arguments"""
    key_data = {
        'args': args,
        'kwargs': sorted(kwargs.items())
    }
    key_str = json.dumps(key_data, sort_keys=True, default=str)
    return hashlib.md5(key_str.encode()).hexdigest()

def cached_with_ttl(ttl_seconds=300):
    """
    Decorator to cache function results with TTL (Time To Live)
    
    Args:
        ttl_seconds: Time in seconds before cache expires (default: 5 minutes)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{func.__name__}:{cache_key(*args, **kwargs)}"
            
            # Check if cached and not expired
            if key in _cache:
                cached_time, cached_value = _cache[key]
                if datetime.now() - cached_time < timedelta(seconds=ttl_seconds):
                    return cached_value
                else:
                    # Expired, remove from cache
                    del _cache[key]
            
            # Call function and cache result
            result = func(*args, **kwargs)
            _cache[key] = (datetime.now(), result)
            
            return result
        return wrapper
    return decorator

def clear_cache(pattern=None):
    """
    Clear cache entries
    
    Args:
        pattern: If provided, only clear entries matching this pattern (function name)
    """
    if pattern:
        keys_to_remove = [k for k in _cache.keys() if k.startswith(f"{pattern}:")]
        for key in keys_to_remove:
            del _cache[key]
    else:
        _cache.clear()
        _cache_ttl.clear()

def get_cache_stats():
    """Get cache statistics"""
    return {
        'total_entries': len(_cache),
        'entries': list(_cache.keys())
    }

# Request-level cache (cleared after each request)
def get_request_cache():
    """Get or create request-level cache"""
    if not hasattr(g, 'request_cache'):
        g.request_cache = {}
    return g.request_cache

def cached_in_request(key):
    """
    Decorator to cache function results within a single request
    
    Args:
        key: Cache key (can be a function that takes args/kwargs)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_request_cache()
            
            # Generate cache key
            if callable(key):
                cache_key = key(*args, **kwargs)
            else:
                cache_key = f"{key}:{cache_key(*args, **kwargs)}"
            
            # Check cache
            if cache_key in cache:
                return cache[cache_key]
            
            # Call function and cache result
            result = func(*args, **kwargs)
            cache[cache_key] = result
            
            return result
        return wrapper
    return decorator

