
with open('promptfuzz/cli.py') as f:
    lines = f.readlines()

new_prefix = """\"\"\"PromptFuzz CLI — Adversarial prompt fuzzing for LLM applications.\"\"\"

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import yaml
from dotenv import load_dotenv
from rich.console import Console

import promptfuzz.attacks.encoding  # noqa: F401
import promptfuzz.attacks.extraction  # noqa: F401
import promptfuzz.attacks.injection  # noqa: F401
import promptfuzz.attacks.jailbreak  # noqa: F401
import promptfuzz.detectors.keyword  # noqa: F401
import promptfuzz.mutators.transforms  # noqa: F401
import promptfuzz.reporters.outputs  # noqa: F401
import promptfuzz.targets.providers  # noqa: F401
from promptfuzz.core.base import BaseAttack, BaseDetector, BaseMutator, BaseReporter, BaseTarget
from promptfuzz.core.engine import FuzzEngine
from promptfuzz.core.models import FuzzConfig, TargetConfig
from promptfuzz.core.registry import registry

load_dotenv()
console = Console()
"""

body = False
with open('promptfuzz/cli.py', 'w') as f:
    f.write(new_prefix)
    for line in lines:
        if "@click.group()" in line:
            body = True
        if body:
            f.write(line)
