import os
import re
import json
import time
import hashlib
import logging
from typing import Type, TypeVar, Optional, Dict, Any, Tuple
from pydantic import BaseModel
import httpx
import threading

logger = logging.getLogger(__name__)

# Mutex for Ollama to serialize GPU/CPU inference requests and prevent timeouts
_ollama_lock = threading.Lock()

T = TypeVar("T", bound=BaseModel)

# Default size limits
MAX_PROMPT_CHARS = 16000
DEFAULT_TIMEOUT_SEC = 120.0
MAX_CACHE_SIZE = 500


class LLMCallRecord(BaseModel):
    agent: str = "general"
    provider: str
    model: str
    latency_ms: float
    cache_hit: bool
    success: bool
    token_estimate: int = 0
    error: Optional[str] = None
    daily_token_usage: Optional[int] = None
    budget_exceeded: bool = False


class LLMResponse:
    def __init__(
        self,
        text: str,
        provider: str,
        model: str,
        latency_ms: float,
        cached: bool = False,
        token_estimate: int = 0
    ):
        self.text = text
        self.provider = provider
        self.model = model
        self.latency_ms = latency_ms
        self.cached = cached
        self.token_estimate = token_estimate


def _clean_json_markdown(text: str) -> str:
    """Strips Markdown fences like ```json ... ``` from model output."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


class LLMClient:
    """
    Provider-agnostic LLM Client abstraction supporting:
    - Gemini (Google AI Studio REST API)
    - OpenAI (Chat Completions REST API)
    - Ollama (Local REST API)
    - Anthropic (Messages REST API)
    Includes:
    - Timeouts & Exponential Backoff Retries
    - In-memory hash-keyed LRU caching
    - Prompt length truncation guardrail
    - Structured generation with Pydantic schema validation & parse retries
    - Observability and call metrics logging
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.2,
        enabled: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SEC
    ):
        self.provider = (provider or os.environ.get("LLM_PROVIDER", "gemini")).lower()
        self.model = model or os.environ.get("LLM_MODEL", self._default_model_for_provider(self.provider))
        self.temperature = temperature
        self.enabled = enabled
        self.timeout = timeout
        self.cache: Dict[str, Tuple[str, float]] = {}  # key -> (text, timestamp)
        self.recent_calls: list[LLMCallRecord] = []

    def _default_model_for_provider(self, provider: str) -> str:
        mapping = {
            "gemini": "gemini-2.5-flash",
            "openai": "gpt-4o-mini",
            "ollama": "llama3.2",
            "anthropic": "claude-3-5-haiku-20241022"
        }
        return mapping.get(provider, "gemini-1.5-flash")

    def _get_api_key(self) -> str:
        if self.provider == "gemini":
            return os.environ.get("GEMINI_API_KEY", "").strip()
        elif self.provider == "openai":
            return os.environ.get("OPENAI_API_KEY", "").strip()
        elif self.provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY", "").strip()
        elif self.provider == "ollama":
            return "ollama-local"
        return ""

    def is_available(self) -> bool:
        """Checks if the client is enabled and has the required credentials or local endpoints."""
        if not self.enabled:
            return False
        if self.provider == "ollama":
            return True
        key = self._get_api_key()
        return bool(key)

    def _cache_key(self, system: str, prompt: str, schema_name: str = "") -> str:
        combined = f"{self.provider}:{self.model}:{schema_name}::{system}::{prompt}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def _truncate_prompt(self, prompt: str) -> str:
        if len(prompt) > MAX_PROMPT_CHARS:
            logger.warning(f"Prompt exceeded {MAX_PROMPT_CHARS} chars ({len(prompt)}). Truncating.")
            half = MAX_PROMPT_CHARS // 2 - 100
            return prompt[:half] + "\n...[TRUNCATED FOR CONTEXT LIMIT]...\n" + prompt[-half:]
        return prompt

    def generate(
        self,
        system: str,
        prompt: str,
        agent_name: str = "general",
        **opts
    ) -> str:
        """
        Generates text completion using the configured provider.
        Catches errors, checks cache, enforces timeouts, and logs latency.
        """
        if not self.is_available():
            raise RuntimeError(f"LLM provider '{self.provider}' is disabled or has no API key configured.")

        safe_prompt = self._truncate_prompt(prompt)
        cache_k = self._cache_key(system, safe_prompt)

        # 1. Check in-memory cache
        if cache_k in self.cache:
            cached_text, _ = self.cache[cache_k]
            record = LLMCallRecord(
                agent=agent_name,
                provider=self.provider,
                model=self.model,
                latency_ms=0.0,
                cache_hit=True,
                success=True,
                token_estimate=len(safe_prompt) // 4
            )
            self.recent_calls.append(record)
            logger.info(f"[{agent_name}] LLM Cache hit for {self.provider}/{self.model}")
            return cached_text

        # 2. Execute with exponential backoff (0 retries for Ollama to avoid cascading timeout delays)
        last_exception = None
        max_retries = 0 if self.provider == "ollama" else 1
        for attempt in range(max_retries + 1):
            t0 = time.time()
            try:
                text = self._call_provider(system, safe_prompt, **opts)
                latency_ms = round((time.time() - t0) * 1000, 2)
                token_est = (len(safe_prompt) + len(text)) // 4

                # Store in cache
                if len(self.cache) >= MAX_CACHE_SIZE:
                    oldest_k = next(iter(self.cache))
                    self.cache.pop(oldest_k, None)
                self.cache[cache_k] = (text, time.time())

                record = LLMCallRecord(
                    agent=agent_name,
                    provider=self.provider,
                    model=self.model,
                    latency_ms=latency_ms,
                    cache_hit=False,
                    success=True,
                    token_estimate=token_est
                )
                self.recent_calls.append(record)
                logger.info(f"[{agent_name}] LLM Call success ({self.provider}/{self.model}) in {latency_ms}ms (~{token_est} tokens)")
                return text

            except Exception as e:
                last_exception = e
                latency_ms = round((time.time() - t0) * 1000, 2)
                logger.warning(f"[{agent_name}] LLM Call attempt {attempt + 1}/{max_retries + 1} failed: {e}")
                if attempt < max_retries:
                    backoff = 0.5 * (2 ** attempt)
                    time.sleep(backoff)

        # Log failed record
        record = LLMCallRecord(
            agent=agent_name,
            provider=self.provider,
            model=self.model,
            latency_ms=0.0,
            cache_hit=False,
            success=False,
            error=str(last_exception)
        )
        self.recent_calls.append(record)
        raise RuntimeError(f"LLM generation failed after {max_retries + 1} attempts: {last_exception}") from last_exception

    def generate_structured(
        self,
        system: str,
        prompt: str,
        schema: Type[T],
        agent_name: str = "general",
        **opts
    ) -> T:
        """
        Generates structured output validated against a Pydantic BaseModel schema.
        Uses clean instance templates and automatically unwraps nested property wrappers.
        """
        # Generate clean example template
        example_fields = {}
        if hasattr(schema, "model_fields"):
            for fname, ffield in schema.model_fields.items():
                ann = str(ffield.annotation).lower()
                if fname == "firewall_commands":
                    example_fields[fname] = [
                        {
                            "firewall_type": "iptables",
                            "command": "iptables -A INPUT -s <source_ip> -j DROP",
                            "description": "Block source IP"
                        }
                    ]
                elif "list" in ann:
                    example_fields[fname] = ["example_item"]
                elif "int" in ann or "float" in ann:
                    example_fields[fname] = 0
                elif "bool" in ann:
                    example_fields[fname] = True
                elif "dict" in ann:
                    example_fields[fname] = {}
                else:
                    example_fields[fname] = f"<{fname}>"
        example_json = json.dumps(example_fields, indent=2)

        system_with_schema = (
            f"{system}\n\n"
            f"You MUST output valid, parsable JSON with this exact key structure:\n"
            f"```json\n{example_json}\n```\n"
            f"Do not nest these keys inside 'properties', 'schema', or 'type'. "
            f"Return only the valid JSON object."
        )

        def _try_validate(data: Any) -> T:
            if not isinstance(data, dict):
                return schema.model_validate(data)
            # Direct validation
            try:
                return schema.model_validate(data)
            except Exception:
                pass

            # Unwrap common wrappers (e.g. {"properties": {...}}, {"data": {...}})
            target_keys = set(schema.model_fields.keys()) if hasattr(schema, "model_fields") else set()
            for wrap in ["properties", "data", "result", "response", "values"]:
                if wrap in data and isinstance(data[wrap], dict):
                    inner = data[wrap]
                    flattened = {}
                    for k, v in inner.items():
                        if isinstance(v, dict):
                            flattened[k] = v.get("value") or v.get("default") or v.get("description") or v
                        else:
                            flattened[k] = v
                    try:
                        return schema.model_validate(flattened)
                    except Exception:
                        pass
            return schema.model_validate(data)

        current_prompt = prompt
        parse_attempts = 2
        for attempt in range(parse_attempts + 1):
            raw_text = self.generate(system=system_with_schema, prompt=current_prompt, agent_name=agent_name, format="json", **opts)
            cleaned = _clean_json_markdown(raw_text)
            try:
                parsed_dict = json.loads(cleaned)
                return _try_validate(parsed_dict)
            except Exception as parse_err:
                logger.warning(f"[{agent_name}] JSON schema validation failed on attempt {attempt + 1}: {parse_err}")
                if attempt < parse_attempts:
                    current_prompt = (
                        f"{prompt}\n\n"
                        f"CRITICAL ERROR IN PREVIOUS ATTEMPT: {parse_err}\n"
                        f"Previous output was:\n{cleaned[:500]}\n"
                        f"Please return valid JSON with keys: {list(example_fields.keys())}."
                    )
                else:
                    raise ValueError(f"Failed to produce valid schema '{schema.__name__}' from LLM: {parse_err}") from parse_err

    # -------------------------------------------------------------
    # Provider Call Dispatcher
    # -------------------------------------------------------------
    def _call_provider(self, system: str, prompt: str, **opts) -> str:
        if self.provider == "gemini":
            return self._call_gemini(system, prompt, **opts)
        elif self.provider == "openai":
            return self._call_openai(system, prompt, **opts)
        elif self.provider == "ollama":
            with _ollama_lock:
                return self._call_ollama(system, prompt, **opts)
        elif self.provider == "anthropic":
            return self._call_anthropic(system, prompt, **opts)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def _call_gemini(self, system: str, prompt: str, **opts) -> str:
        api_key = self._get_api_key()
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        gen_cfg = {
            "temperature": opts.get("temperature", self.temperature),
            "maxOutputTokens": opts.get("num_predict") or opts.get("max_tokens", 2048)
        }
        if opts.get("format") == "json":
            gen_cfg["responseMimeType"] = "application/json"

        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"System Instructions:\n{system}\n\nUser Task:\n{prompt}"}]}
            ],
            "generationConfig": gen_cfg
        }

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("Gemini returned empty candidate list.")
            text_parts = candidates[0].get("content", {}).get("parts", [])
            return "".join(part.get("text", "") for part in text_parts).strip()

    def _call_openai(self, system: str, prompt: str, **opts) -> str:
        api_key = self._get_api_key()
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set.")

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ],
            "temperature": opts.get("temperature", self.temperature),
            "max_tokens": opts.get("num_predict") or opts.get("max_tokens", 2048)
        }
        if opts.get("format") == "json":
            payload["response_format"] = {"type": "json_object"}

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"OpenAI API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()

    def _call_ollama(self, system: str, prompt: str, **opts) -> str:
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        url = f"{base_url}/api/chat"
        headers = {"Content-Type": "application/json"}
        options = {
            "temperature": opts.get("temperature", self.temperature)
        }
        token_limit = opts.get("num_predict") or opts.get("max_tokens")
        if token_limit:
            options["num_predict"] = int(token_limit)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": options
        }
        if opts.get("format") == "json":
            payload["format"] = "json"

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Ollama API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            return data.get("message", {}).get("content", "").strip()

    def _call_anthropic(self, system: str, prompt: str, **opts) -> str:
        api_key = self._get_api_key()
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set.")

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": opts.get("max_tokens", 2048),
            "temperature": opts.get("temperature", self.temperature)
        }

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Anthropic API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            content_blocks = data.get("content", [])
            return "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text").strip()


# Singleton factory reading dynamically from platform settings
_llm_client_instance: Optional[LLMClient] = None

def get_llm_client(force_refresh: bool = False) -> LLMClient:
    global _llm_client_instance
    if _llm_client_instance is None or force_refresh:
        from app.core.config import load_platform_settings
        cfg = load_platform_settings().get("llm", {})
        provider = os.environ.get("LLM_PROVIDER") or cfg.get("provider", "gemini")
        model = os.environ.get("LLM_MODEL") or cfg.get("model", "")
        temp = float(cfg.get("temperature", 0.2))
        enabled = bool(cfg.get("enabled", True))
        _llm_client_instance = LLMClient(
            provider=provider,
            model=model if model else None,
            temperature=temp,
            enabled=enabled
        )
    return _llm_client_instance
