"""Abstract base classes for PromptFuzz's plugin architecture."""

from __future__ import annotations

from abc import ABC, abstractmethod

from promptfuzz.core.models import (
    AttackCategory,
    CampaignSummary,
    Severity,
    TargetConfig,
)


class BaseAttack(ABC):
    """Base class for all attack strategies.

    To create a custom attack, subclass this and implement `generate_prompts()`.

    Example:
        class MyAttack(BaseAttack):
            name = "my_custom_attack"
            category = AttackCategory.JAILBREAK
            severity = Severity.HIGH
            description = "A custom jailbreak technique"

            async def generate_prompts(self) -> list[str]:
                return ["Ignore all previous instructions and ..."]
    """

    name: str = ""
    category: AttackCategory = AttackCategory.JAILBREAK
    severity: Severity = Severity.HIGH
    description: str = ""
    tags: list[str] = []

    _registry: dict[str, type[BaseAttack]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            BaseAttack._registry[cls.name] = cls

    @abstractmethod
    async def generate_prompts(self) -> list[str | list[dict[str, str]]]:
        """Generate a list of adversarial prompts for this attack."""
        ...


class BaseTarget(ABC):
    """Base class for LLM target adapters."""

    name: str = ""

    _registry: dict[str, type[BaseTarget]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            BaseTarget._registry[cls.name] = cls

    def __init__(self, config: TargetConfig | None = None) -> None:
        self.config = config

    @abstractmethod
    async def send(
        self, prompt: str | list[dict[str, str]], system_prompt: str = ""
    ) -> tuple[str, float, int]:
        """Send a prompt and return (response_text, latency_ms, tokens_used)."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""
        ...


class BaseDetector(ABC):
    """Base class for attack success detectors."""

    name: str = ""

    _registry: dict[str, type[BaseDetector]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            BaseDetector._registry[cls.name] = cls

    @abstractmethod
    async def detect(
        self, prompt: str | list[dict[str, str]], response: str, attack: BaseAttack
    ) -> tuple[bool, float]:
        """Determine if an attack succeeded.

        Returns:
            (success: bool, confidence: float 0.0-1.0)
        """
        ...


class BaseMutator(ABC):
    """Base class for prompt mutators."""

    name: str = ""

    _registry: dict[str, type[BaseMutator]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            BaseMutator._registry[cls.name] = cls

    @abstractmethod
    async def mutate(self, prompt: str) -> list[str]:
        """Generate mutated variants of a prompt.

        Returns:
            List of mutated prompts.
        """
        ...


class BaseReporter(ABC):
    """Base class for result reporters."""

    name: str = ""

    _registry: dict[str, type[BaseReporter]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            BaseReporter._registry[cls.name] = cls

    @abstractmethod
    async def report(self, summary: CampaignSummary, output_dir: str) -> str | None:
        """Generate a report from campaign results.

        Returns:
            Path to generated report file, or None for console output.
        """
        ...
