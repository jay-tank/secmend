"""OpenAI provider. Uses the official `openai` SDK."""

from __future__ import annotations

import os
from typing import Optional

from .base import LLMProvider, ProviderError

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


class OpenAIProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        self.model = model or os.getenv("SECMEND_MODEL") or DEFAULT_OPENAI_MODEL

    def complete(self, system: str, user: str) -> str:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ProviderError(
                "The 'openai' package is required for the OpenAI provider. "
                "Install it with:  pip install 'secmend[openai]'"
            ) from exc

        client = OpenAI()  # resolves OPENAI_API_KEY
        try:
            resp = client.chat.completions.create(
                model=self.model,
                max_tokens=1024,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
        except Exception as exc:  # openai raises a family of errors
            raise ProviderError(f"OpenAI API error: {exc}") from exc

        return resp.choices[0].message.content or ""
