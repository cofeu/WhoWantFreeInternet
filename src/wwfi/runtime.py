from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LanguageAdapter:
    language: str
    runtime: str
    supports_tls: bool = True

    @staticmethod
    def supported_languages() -> list[str]:
        return ["python", "node", "rust", "go"]

    @staticmethod
    def build(language: str, runtime: str) -> "LanguageAdapter":
        if language not in LanguageAdapter.supported_languages():
            raise ValueError(f"Unsupported language: {language}")
        return LanguageAdapter(language=language, runtime=runtime, supports_tls=True)
