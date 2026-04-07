"""Configuration loader and preset management."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import click
import yaml

from promptfuzz.core.models import FuzzConfig, TargetConfig


def load_fuzz_config(
    model: str | None = None,
    api_key: str = "",
    base_url: str = "",
    attacks: str = "all",
    config_path: str | None = None,
    output: str = "console",
    seed: int | None = None,
    preset: str | None = None,
    system_prompt: str = "",
    rate_limit: float = 10.0,
    concurrency: int = 5,
) -> FuzzConfig:
    """Load configuration from file or arguments and apply preset overrides."""
    if config_path is None and not model:
        if Path("promptfuzz.yaml").exists():
            config_path = "promptfuzz.yaml"
        else:
            raise click.UsageError(
                "Missing parameter: requires --model, --config, or a promptfuzz.yaml file."
            )

    if config_path:
        with open(config_path) as f:
            raw = yaml.safe_load(f)
        if seed is not None:
            raw["seed"] = seed
        if preset is not None:
            raw["preset"] = preset
        fuzz_config = FuzzConfig(**raw)
    else:
        target_config = TargetConfig(
            model=model or "",
            api_key=api_key,
            base_url=base_url,
            system_prompt=system_prompt,
        )
        kwargs: dict[str, Any] = {
            "targets": [target_config],
            "output_format": output.split(","),
            "rate_limit_rps": rate_limit,
            "max_concurrent": concurrency,
        }
        if attacks != "all":
            kwargs["attacks"] = attacks.split(",")
        if seed is not None:
            kwargs["seed"] = seed
        if preset is not None:
            kwargs["preset"] = preset

        fuzz_config = FuzzConfig(**kwargs)

    # Apply preset overrides
    if fuzz_config.preset == "quick":
        fuzz_config.attacks = ["jailbreak.dan", "injection.system_prompt_leak"]
        fuzz_config.mutators = []
        fuzz_config.mutation_depth = 0
    elif fuzz_config.preset == "ci":
        fuzz_config.mutators = ["synonym_swap"]
        fuzz_config.mutation_depth = 1
    elif fuzz_config.preset == "thorough":
        fuzz_config.mutation_depth = 3
        
    return fuzz_config
