"""
agent_helpers.py - Shared LLM call wrapper for all SOC pipeline agents.

Centralises:
  - Token output capping (num_predict)
  - Per-user Redis daily budget enforcement
  - Fallback on budget-exhaustion or provider error
"""

import logging
from typing import Any, Optional, Tuple, Type

from pydantic import BaseModel

logger = logging.getLogger(__name__)


def call_llm(
    system: str,
    user_prompt: str,
    agent_name: str,
    user_id: str = "system",
    schema: Optional[Type[BaseModel]] = None,
) -> Tuple[bool, Any]:
    """Call the LLM with budget checking and token capping.

    Parameters
    ----------
    system      : System-role prompt.
    user_prompt : User-role prompt (the task description / data context).
    agent_name  : Human-readable agent name (for logging and metrics).
    user_id     : User identifier used as Redis budget key namespace.
                  Defaults to "system" when no request context is available.
    schema      : Optional Pydantic model class. When supplied the LLM is called
                  in structured-output mode; otherwise plain text is returned.

    Returns
    -------
    (success, result)
        success  - True if the LLM call succeeded and budget was not exceeded.
        result   - Generated text (str) or parsed Pydantic model on success;
                   error description string on failure.
    """
    from app.llm.client import get_llm_client
    from app.llm.budget import increment_daily_usage
    from app.core.config import load_platform_settings

    client = get_llm_client()
    if not client.is_available():
        logger.info(f"[{agent_name}] LLM provider unavailable – using fallback.")
        return False, "LLM provider unavailable"

    # --- Token output limit ---
    cfg = load_platform_settings()
    llm_cfg = cfg.get("llm", {})
    out_limit = int(llm_cfg.get("max_output_tokens", 300))
    opts: dict = {"num_predict": out_limit}

    # --- Daily budget check (rough 1 token ~ 4 chars) ---
    token_est = (len(system) + len(user_prompt)) // 4
    budget_ok, used = increment_daily_usage(user_id=user_id, token_delta=token_est)
    if not budget_ok:
        logger.warning(
            f"[{agent_name}] Daily LLM budget exceeded for user '{user_id}' "
            f"({used} tokens used) – using fallback."
        )
        return False, f"Daily LLM token budget exceeded ({used} tokens used today)"

    # --- LLM call ---
    try:
        if schema is None:
            result = client.generate(
                system=system,
                prompt=user_prompt,
                agent_name=agent_name,
                **opts,
            )
        else:
            result = client.generate_structured(
                system=system,
                prompt=user_prompt,
                schema=schema,
                agent_name=agent_name,
                **opts,
            )
        return True, result
    except Exception as exc:
        logger.exception(f"[{agent_name}] LLM generation failed: {exc}")
        return False, str(exc)
