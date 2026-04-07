"""Tests for FuzzEngine."""

from unittest.mock import patch

import pytest

from promptfuzz.core.base import BaseAttack, BaseDetector, BaseMutator, BaseTarget
from promptfuzz.core.engine import FuzzEngine
from promptfuzz.core.models import (
    AttackCategory,
    FuzzConfig,
    Severity,
    TargetConfig,
)


class MockSuccessDetector(BaseDetector):
    name = "mock_detector"

    async def detect(
        self, prompt: str | list[dict[str, str]], response: str, attack: BaseAttack
    ) -> tuple[bool, float]:
        if "success" in response:
            return True, 0.9
        return False, 0.0


class MockAttack(BaseAttack):
    name = "mock_attack"
    category = AttackCategory.JAILBREAK
    severity = Severity.HIGH
    description = "test"

    async def generate_prompts(self) -> list[str | list[dict[str, str]]]:
        return ["test_prompt"]


class MockTarget(BaseTarget):
    name = "mock_target"

    def __init__(self, config: TargetConfig):
        self.config = config
        self.should_fail = False

    async def send(
        self, prompt: str | list[dict[str, str]], system_prompt: str = ""
    ) -> tuple[str, float, int]:
        if self.should_fail:
            raise ValueError("Target failed")
        if "test_prompt" in prompt:
            return "success response", 1.0, 10
        return "refusal response", 1.0, 10

    async def close(self) -> None:
        pass


class MockMutator(BaseMutator):
    name = "mock_mutator"
    description = "test"

    async def mutate(self, prompt: str) -> list[str]:
        return [f"{prompt}_mutated"]


@pytest.fixture
def config():
    tc = TargetConfig(type="mock_target", model="test")
    return FuzzConfig(
        targets=[tc],
        attacks=["mock_attack"],
        detectors=["mock_detector"],
        mutators=["mock_mutator"],
        mutation_breadth=1,
        mutation_depth=1,
    )


@pytest.mark.asyncio
async def test_engine_run_success_with_mutation(config):
    engine = FuzzEngine(config)

    with (
        patch.dict("promptfuzz.core.base.BaseAttack._registry", {"mock_attack": MockAttack}),
        patch.dict("promptfuzz.core.base.BaseTarget._registry", {"mock_target": MockTarget}),
        patch.dict(
            "promptfuzz.core.base.BaseDetector._registry", {"mock_detector": MockSuccessDetector}
        ),
        patch.dict("promptfuzz.core.base.BaseMutator._registry", {"mock_mutator": MockMutator}),
    ):

        summary = await engine.run()

        # We expect 1 successful base attack + 1 successful mutated attack
        assert summary.total_attacks >= 1
        assert summary.successful_attacks == 2

        findings = summary.findings
        assert findings[0].success is True
        assert findings[0].confidence == 0.9
        assert findings[0].prompt == "test_prompt"

        assert findings[1].success is True
        assert findings[1].prompt == "test_prompt_mutated"
        assert findings[1].mutation_parent == findings[0].id
        assert findings[1].mutation_chain == ["mock_mutator"]


@pytest.mark.asyncio
async def test_engine_target_exception(config):
    engine = FuzzEngine(config)

    class FailingTarget(MockTarget):
        async def send(
        self, prompt: str | list[dict[str, str]], system_prompt: str = ""
    ) -> tuple[str, float, int]:
            raise ValueError("Intentional target failure")

    with (
        patch.dict("promptfuzz.core.base.BaseAttack._registry", {"mock_attack": MockAttack}),
        patch.dict("promptfuzz.core.base.BaseTarget._registry", {"mock_target": FailingTarget}),
        patch.dict(
            "promptfuzz.core.base.BaseDetector._registry", {"mock_detector": MockSuccessDetector}
        ),
        patch.dict("promptfuzz.core.base.BaseMutator._registry", {"mock_mutator": MockMutator}),
        pytest.raises(RuntimeError, match="failed to process request: Intentional target failure"),
    ):
            await engine.run()


@pytest.mark.asyncio
async def test_engine_mutator_exception(config):
    # Tests resilient mutation errors if needed, but per code fatal mutation error raises
    engine = FuzzEngine(config)

    class FailingMutator(MockMutator):
        async def mutate(self, prompt: str) -> list[str]:
            raise ValueError("Intentional mutator failure")

    with (
        patch.dict("promptfuzz.core.base.BaseAttack._registry", {"mock_attack": MockAttack}),
        patch.dict("promptfuzz.core.base.BaseTarget._registry", {"mock_target": MockTarget}),
        patch.dict(
            "promptfuzz.core.base.BaseDetector._registry", {"mock_detector": MockSuccessDetector}
        ),
        patch.dict("promptfuzz.core.base.BaseMutator._registry", {"mock_mutator": FailingMutator}),
        pytest.raises(ValueError, match="Intentional mutator failure"),
    ):
            await engine.run()


@pytest.mark.asyncio
async def test_engine_no_successful_attacks(config):
    engine = FuzzEngine(config)

    class FailsDetector(MockSuccessDetector):
        async def detect(
            self, prompt: str | list[dict[str, str]], response: str, attack: BaseAttack
        ) -> tuple[bool, float]:
            return False, 0.0

    with (
        patch.dict("promptfuzz.core.base.BaseAttack._registry", {"mock_attack": MockAttack}),
        patch.dict("promptfuzz.core.base.BaseTarget._registry", {"mock_target": MockTarget}),
        patch.dict(
            "promptfuzz.core.base.BaseDetector._registry", {"mock_detector": FailsDetector}
        ),
        patch.dict("promptfuzz.core.base.BaseMutator._registry", {"mock_mutator": MockMutator}),
    ):

        summary = await engine.run()
        assert summary.successful_attacks == 0
        assert summary.total_attacks == 1
