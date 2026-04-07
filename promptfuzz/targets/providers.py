"""Target adapters for LLM providers."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx
import litellm

from promptfuzz.core.base import BaseTarget

litellm.suppress_debug_info = True
litellm.drop_params = True

if TYPE_CHECKING:
    from promptfuzz.core.models import TargetConfig


class LiteLLMTarget(BaseTarget):
    """Unified target adapter using LiteLLM."""

    name = "litellm"

    async def send(
        self, prompt: str | list[dict[str, str]], system_prompt: str = ""
    ) -> tuple[str, float, int]:
        if not self.config:
            raise ValueError("TargetConfig is required")

        sys_prompt = system_prompt or self.config.system_prompt

        messages = []
        if sys_prompt:
            messages.append({"role": "system", "content": sys_prompt})
        
        if isinstance(prompt, str):
            messages.append({"role": "user", "content": prompt})
        elif isinstance(prompt, list):
            messages.extend(prompt)

        start = time.monotonic()
        try:
            resp = await litellm.acompletion(
                model=self.config.model,
                messages=messages,
                api_key=self.config.api_key or None,
                base_url=self.config.base_url or None,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
            latency = (time.monotonic() - start) * 1000
            text = resp.choices[0].message.content
            tokens = resp.usage.total_tokens
        except litellm.exceptions.BadRequestError as e:
            if "content management policy" in str(e).lower() or "filtered" in str(e).lower():
                latency = (time.monotonic() - start) * 1000
                text = "[FILTERED]"
                tokens = 0
            else:
                raise e
        return text, latency, tokens

    async def close(self) -> None:
        pass


class HTTPTarget(BaseTarget):
    """Generic HTTP target for any REST endpoint."""

    name = "http"

    def __init__(self, config: TargetConfig | None = None) -> None:
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    async def send(
        self, prompt: str | list[dict[str, str]], system_prompt: str = ""
    ) -> tuple[str, float, int]:
        if not self.config or not self.config.base_url:
            raise ValueError("HTTP target requires 'base_url' in config")

        client = await self._get_client()
        start = time.monotonic()
        resp = await client.post(
            self.config.base_url,
            headers=self.config.headers,
            json={"prompt": prompt, "system_prompt": system_prompt or self.config.system_prompt},
        )
        latency = (time.monotonic() - start) * 1000
        resp.raise_for_status()
        data = resp.json()

        # Try common response shapes
        text = (
            data.get("response")
            or data.get("text")
            or data.get("content")
            or data.get("output")
            or str(data)
        )
        return text, latency, 0

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
