"""
user_utils.py - Utilities for extracting caller identity from FastAPI requests.

Used by LLM agent_helpers to namespace per-user Redis daily token budgets.
"""

from typing import Optional


def get_current_user_id(request=None) -> str:
    """Extract a user identifier from a FastAPI Request.

    Strategy (first match wins):
      1. Decoded JWT ``sub`` claim if an Authorization: Bearer header is present.
      2. ``X-User-ID`` custom header (useful for internal service-to-service calls).
      3. Fall back to the string ``"system"`` so the budget is always tracked.

    Parameters
    ----------
    request : fastapi.Request | None
        The current HTTP request object.  Pass ``None`` in background jobs or
        tests that do not have a live request context.

    Returns
    -------
    str
        A non-empty string identifying the caller, e.g. ``"alice"``, ``"system"``.
    """
    if request is None:
        return "system"

    # 1. X-User-ID header (cheapest check)
    uid_header: Optional[str] = request.headers.get("x-user-id")
    if uid_header and uid_header.strip():
        return uid_header.strip()

    # 2. JWT sub claim from Authorization: Bearer <token>
    auth: Optional[str] = request.headers.get("authorization", "")
    if auth and auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        try:
            import base64, json as _json

            # Decode the payload segment (middle part) without verifying the
            # signature – we only need the sub claim for budget key namespacing,
            # not for authentication (auth is handled separately by the API layer).
            parts = token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1]
                # Add padding so base64 does not complain
                padding = 4 - len(payload_b64) % 4
                payload_b64 += "=" * (padding % 4)
                payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
                sub = payload.get("sub") or payload.get("user_id") or payload.get("email")
                if sub and str(sub).strip():
                    return str(sub).strip()
        except Exception:
            pass  # Malformed token - fall through to default

    return "system"
