"""Core data models for PromptFuzz."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackCategory(StrEnum):
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    EXTRACTION = "extraction"
    ENCODING = "encoding"
    MULTILINGUAL = "multilingual"
    MULTI_TURN = "multi_turn"


class AttackResult(BaseModel):
    """Result of a single attack attempt against a target."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    attack_name: str
    attack_category: AttackCategory
    prompt: str
    response: str
    target: str
    success: bool
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity = Severity.INFO
    detector: str = ""
    mutation_parent: str | None = None
    mutation_chain: list[str] = Field(default_factory=list)
    seed: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_ms: float = 0.0
    tokens_used: int = 0
    metadata: dict[str, str] = Field(default_factory=dict)

    @property
    def is_mutation(self) -> bool:
        return self.mutation_parent is not None


class CampaignSummary(BaseModel):
    """Summary statistics for a fuzzing campaign."""

    total_attacks: int = 0
    successful_attacks: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    targets_tested: list[str] = Field(default_factory=list)
    attack_categories_tested: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    findings: list[AttackResult] = Field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.successful_attacks / self.total_attacks

    def add_result(self, result: AttackResult) -> None:
        self.total_attacks += 1
        if result.success:
            self.successful_attacks += 1
            self.findings.append(result)
            match result.severity:
                case Severity.CRITICAL:
                    self.critical_count += 1
                case Severity.HIGH:
                    self.high_count += 1
                case Severity.MEDIUM:
                    self.medium_count += 1
                case Severity.LOW:
                    self.low_count += 1


class FuzzConfig(BaseModel):
    """Configuration for a fuzzing campaign."""

    targets: list[TargetConfig] = Field(default_factory=list)
    attacks: list[str] = Field(default_factory=lambda: ["all"])
    mutators: list[str] = Field(default_factory=lambda: ["synonym_swap", "role_play"])
    detectors: list[str] = Field(default_factory=lambda: ["keyword"])
    mutation_depth: int = Field(default=2, ge=0, le=5)
    mutation_breadth: int = Field(default=3, ge=1, le=10)
    max_concurrent: int = Field(default=5, ge=1, le=50)
    rate_limit_rps: float = Field(default=10.0, gt=0)
    seed: int | None = None
    preset: str | None = None
    output_format: list[str] = Field(default_factory=lambda: ["console"])
    output_dir: str = "./promptfuzz-results"


class TargetConfig(BaseModel):
    """Configuration for a single target LLM."""

    type: str = "litellm"
    model: str
    api_key: str = ""
    base_url: str = ""
    system_prompt: str = ""
    temperature: float = 0.0
    max_tokens: int = 1024
    headers: dict[str, str] = Field(default_factory=dict)
