"""Tokenizer abstraction for counting tokens across LLM families."""

from __future__ import annotations

from functools import lru_cache
from typing import Protocol


class Tokenizer(Protocol):
    def encode(self, text: str) -> list[int]: ...
    def decode(self, ids: list[int]) -> str: ...
    def count(self, text: str) -> int: ...


class TiktokenTokenizer:
    """Wraps OpenAI tiktoken; used as default/fallback."""

    def __init__(self, encoding: str = "cl100k_base") -> None:
        import tiktoken  # optional dependency
        self._enc = tiktoken.get_encoding(encoding)

    def encode(self, text: str) -> list[int]:
        return self._enc.encode(text)

    def decode(self, ids: list[int]) -> str:
        return self._enc.decode(ids)

    def count(self, text: str) -> int:
        return len(self.encode(text))


class HFTokenizer:
    """Wraps a HuggingFace tokenizers fast tokenizer."""

    def __init__(self, pretrained_name: str) -> None:
        from tokenizers import Tokenizer as _HFTok  # type: ignore
        self._tok = _HFTok.from_pretrained(pretrained_name)

    def encode(self, text: str) -> list[int]:
        return self._tok.encode(text).ids

    def decode(self, ids: list[int]) -> str:
        return self._tok.decode(ids)

    def count(self, text: str) -> int:
        return len(self.encode(text))


class SimpleCharTokenizer:
    """Rough approximation: 1 token ≈ 4 characters. Used when no tokenizer is available."""

    def encode(self, text: str) -> list[int]:
        return list(range(max(1, len(text) // 4)))

    def decode(self, ids: list[int]) -> str:
        return " " * (len(ids) * 4)

    def count(self, text: str) -> int:
        return max(1, len(text) // 4)


# Known tokenizer name → (class, init_arg)
_REGISTRY: dict[str, tuple[type, str]] = {
    "cl100k_base": (TiktokenTokenizer, "cl100k_base"),
    "o200k_base":  (TiktokenTokenizer, "o200k_base"),
    "llama3":      (HFTokenizer, "meta-llama/Meta-Llama-3-8B"),
    "qwen2":       (HFTokenizer, "Qwen/Qwen2-7B"),
    "gemma":       (HFTokenizer, "google/gemma-2b"),
    "mistral":     (HFTokenizer, "mistralai/Mistral-7B-v0.1"),
}


@lru_cache(maxsize=8)
def get_tokenizer(name: str = "cl100k_base") -> Tokenizer:
    if name not in _REGISTRY:
        return SimpleCharTokenizer()
    cls, arg = _REGISTRY[name]
    try:
        return cls(arg)
    except Exception:
        return SimpleCharTokenizer()


def count_tokens(text: str, tokenizer_name: str = "cl100k_base") -> int:
    return get_tokenizer(tokenizer_name).count(text)
