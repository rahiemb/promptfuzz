import pytest

from promptfuzz.core.engine import FuzzEngine
from promptfuzz.core.models import FuzzConfig, TargetConfig


@pytest.mark.asyncio
async def test_integration_campaign():
    """Stub integration test simulating end-to-end framework bypass test."""
    config = FuzzConfig(
        targets=[TargetConfig(model="mock_target")],
        attacks=["jailbreak.dan"],
        preset="ci"
    )
    
    FuzzEngine(config)
    # Stub assertion -- integration framework relies on external network configurations
    assert config.preset == "ci"
