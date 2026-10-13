"""
budget.py - Redis-backed daily LLM token budget tracker.

Redis key format: llm:usage:{user_id}:{date}  (e.g. llm:usage:alice:2026-10-11)
A 25-hour TTL is set on first write so stale keys expire automatically.
"""

import logging
from datetime import date, timedelta
from typing import Tuple

logger = logging.getLogger(__name__)

_redis_client = None


def _get_redis_client():
    """Return a shared Redis client, preferring the app-level pool if available."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    # 1. Try to reuse the app-level redis pool (from app.core.redis if it exists)
    try:
        from app.core.redis import get_redis  # type: ignore
        _redis_client = get_redis()
        return _redis_client
    except (ImportError, Exception):
        pass

    # 2. Fall back to a direct connection from env/settings
    try:
        import redis as redis_lib
        from app.core.config import settings
        _redis_client = redis_lib.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True,
            socket_connect_timeout=2,
        )
        _redis_client.ping()
    except (ImportError, Exception) as e:
        logger.debug(f"[Budget] Redis unavailable - budgeting disabled: {e}")
        _redis_client = None

    return _redis_client


def _budget_key(user_id: str) -> str:
    today = date.today().isoformat()
    return f"llm:usage:{user_id}:{today}"


def increment_daily_usage(user_id: str, token_delta: int) -> Tuple[bool, int]:
    """
    Atomically increment the daily token counter for *user_id* by *token_delta*.

    Returns (budget_ok, new_total):
        budget_ok - True if the budget has NOT been exceeded (or budgeting is off).
        new_total  - Current cumulative token count after increment.

    Never raises; if Redis is unavailable the call is allowed (budget_ok=True).
    """
    # Load budget limits from platform config
    try:
        from app.core.config import load_platform_settings
        cfg = load_platform_settings()
        budget_cfg = cfg.get("llm", {}).get("daily_budget", {})
        budget_enabled = bool(budget_cfg.get("enabled", True))
        max_tokens = int(budget_cfg.get("max_tokens", 100_000))
    except Exception:
        return True, 0  # config unavailable - allow the call

    if not budget_enabled:
        return True, 0

    r = _get_redis_client()
    if r is None:
        logger.debug("[Budget] Redis unavailable - skipping budget check")
        return True, 0

    key = _budget_key(user_id)
    try:
        pipe = r.pipeline()
        pipe.incrby(key, token_delta)
        pipe.expire(key, int(timedelta(hours=25).total_seconds()))
        results = pipe.execute()
        new_total: int = results[0]
    except Exception as e:
        logger.warning(f"[Budget] Redis error during budget increment: {e}")
        return True, 0

    budget_ok = new_total <= max_tokens
    if not budget_ok:
        logger.warning(
            f"[Budget] Daily token budget exceeded for user '{user_id}': "
            f"{new_total}/{max_tokens} tokens used today."
        )
    return budget_ok, new_total
