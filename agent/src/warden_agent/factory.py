"""Building a model adapter from command-line options. Keys come only from the
environment, never from flags."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

from .models import AnthropicModel, Model, OpenAICompatibleModel, ScriptModel

ADAPTERS = ("anthropic", "openai-compatible", "script")


def make_model(
    adapter: str,
    *,
    model: str | None = None,
    base_url: str | None = None,
    api_key_env: str = "OPENAI_API_KEY",
    script: Sequence[tuple[str, dict[str, Any]]] | None = None,
) -> Model:
    """A fresh model for one run. script is the call list for the script adapter."""
    if adapter == "script":
        if script is None:
            raise ValueError("the script adapter needs a scenario's calls")
        return ScriptModel(list(script))
    if not model:
        raise ValueError(f"adapter {adapter} needs a model name")
    if adapter == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ValueError("set ANTHROPIC_API_KEY in the environment")
        return AnthropicModel(model)
    if adapter != "openai-compatible":
        raise ValueError(f"unknown adapter {adapter}")
    key = os.environ.get(api_key_env)
    if not key:
        if not base_url:
            raise ValueError(f"set {api_key_env} in the environment, or give a base URL for a local endpoint")
        key = "unused"  # local servers such as Ollama ignore the key
    return OpenAICompatibleModel(model, base_url=base_url, api_key=key)
