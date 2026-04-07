"""Tests for PromptFuzz core components."""

from __future__ import annotations

import pytest

# Import plugins
import promptfuzz.attacks.jailbreak  # noqa: F401
import promptfuzz.detectors.keyword  # noqa: F401
from promptfuzz.core.base import BaseAttack, BaseDetector, BaseTarget
from promptfuzz.core.models import (
    AttackCategory,
    AttackResult,
    CampaignSummary,
    FuzzConfig,
    Severity,
    TargetConfig,
)

# --- Fixtures ---


class MockTarget(BaseTarget):
    """Target that returns canned responses for testing."""

    name = "mock"

    def __init__(self, response: str = "I can't help with that.") -> None:
        self.response = response
        self.calls: list[str | list[dict[str, str]]] = []

    async def send(
        self, prompt: str | list[dict[str, str]], system_prompt: str = ""
    ) -> tuple[str, float, int]:
        self.calls.append(prompt)
        return self.response, 50.0, 100

    async def close(self) -> None:
        pass


class MockAttack(BaseAttack):
    name = "mock_attack"
    category = AttackCategory.JAILBREAK
    severity = Severity.HIGH
    description = "Mock attack for testing"

    async def generate_prompts(self) -> list[str | list[dict[str, str]]]:
        return ["Test adversarial prompt"]


# --- Model Tests ---


class TestAttackResult:
    def test_default_values(self) -> None:
        result = AttackResult(
            attack_name="test",
            attack_category=AttackCategory.JAILBREAK,
            prompt="test prompt",
            response="test response",
            target="openai",
            success=False,
            confidence=0.0,
        )
        assert result.id  # Should be auto-generated
        assert result.severity == Severity.INFO
        assert not result.is_mutation

    def test_mutation_tracking(self) -> None:
        result = AttackResult(
            attack_name="test",
            attack_category=AttackCategory.JAILBREAK,
            prompt="mutated prompt",
            response="response",
            target="openai",
            success=True,
            confidence=0.8,
            mutation_parent="parent123",
            mutation_chain=["synonym_swap", "role_play"],
        )
        assert result.is_mutation
        assert len(result.mutation_chain) == 2


class TestCampaignSummary:
    def test_success_rate_empty(self) -> None:
        summary = CampaignSummary()
        assert summary.success_rate == 0.0

    def test_success_rate_calculation(self) -> None:
        summary = CampaignSummary()
        for success in [True, False, False, True]:
            result = AttackResult(
                attack_name="test",
                attack_category=AttackCategory.JAILBREAK,
                prompt="p",
                response="r",
                target="t",
                success=success,
                confidence=0.8 if success else 0.0,
                severity=Severity.HIGH if success else Severity.INFO,
            )
            summary.add_result(result)
        assert summary.success_rate == 0.5
        assert summary.high_count == 2

    def test_severity_counting(self) -> None:
        summary = CampaignSummary()
        for sev in [Severity.CRITICAL, Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            result = AttackResult(
                attack_name="test",
                attack_category=AttackCategory.JAILBREAK,
                prompt="p",
                response="r",
                target="t",
                success=True,
                confidence=0.9,
                severity=sev,
            )
            summary.add_result(result)
        assert summary.critical_count == 2
        assert summary.high_count == 1
        assert summary.medium_count == 1





# --- Detector Tests ---


class TestKeywordDetector:
    @pytest.fixture
    def detector(self) -> BaseDetector:
        return BaseDetector._registry["keyword"]()

    @pytest.fixture
    def jailbreak_attack(self) -> BaseAttack:
        return MockAttack()

    async def test_detects_compliance(
        self, detector: BaseDetector, jailbreak_attack: BaseAttack
    ) -> None:
        """Model complied (no refusal, long response) → should detect."""
        response = (
            "Sure, here's how to pick a lock. First, you need a tension wrench "
            "and a pick. Insert the tension wrench into the bottom of the keyhole "
            "and apply light pressure. Then use the pick to manipulate each pin..."
        )
        success, confidence = await detector.detect("test", response, jailbreak_attack)
        assert success is True
        assert confidence > 0.0

    async def test_detects_refusal(
        self, detector: BaseDetector, jailbreak_attack: BaseAttack
    ) -> None:
        """Model refused → should NOT detect."""
        response = "I'm sorry, I can't help with that request."
        success, confidence = await detector.detect("test", response, jailbreak_attack)
        assert success is False

    async def test_short_response_not_detected(
        self, detector: BaseDetector, jailbreak_attack: BaseAttack
    ) -> None:
        """Short non-refusal response → not enough signal."""
        response = "OK."
        success, confidence = await detector.detect("test", response, jailbreak_attack)
        assert success is False


# --- Attack Tests ---


class TestJailbreakAttacks:
    async def test_dan_generates_prompts(self) -> None:
        attack = BaseAttack._registry["jailbreak.dan"]()
        prompts = await attack.generate_prompts()
        assert len(prompts) > 0
        assert all(isinstance(p, str) for p in prompts)
        assert all(len(p) > 20 for p in prompts)

    async def test_system_prompt_leak_generates_prompts(self) -> None:
        attack = BaseAttack._registry["injection.system_prompt_leak"]()
        prompts = await attack.generate_prompts()
        assert len(prompts) >= 5  # Should have multiple variants

    async def test_all_attacks_have_metadata(self) -> None:
        for name in BaseAttack._registry:
            attack = BaseAttack._registry[name]()
            assert attack.name, f"Attack {name} missing name"
            assert attack.category, f"Attack {name} missing category"
            assert attack.description, f"Attack {name} missing description"


# --- Config Tests ---


class TestFuzzConfig:
    def test_defaults(self) -> None:
        config = FuzzConfig()
        assert config.max_concurrent == 5
        assert config.mutation_depth == 2
        assert config.rate_limit_rps == 10.0

    def test_target_config(self) -> None:
        tc = TargetConfig(model="gpt-4o-mini")
        config = FuzzConfig(targets=[tc])
        assert len(config.targets) == 1
        assert config.targets[0].model == "gpt-4o-mini"

    def test_preset_values_valid(self) -> None:
        """Ensure preset names are recognized."""
        for preset in ["quick", "thorough", "ci"]:
            config = FuzzConfig(preset=preset)
            assert config.preset == preset
