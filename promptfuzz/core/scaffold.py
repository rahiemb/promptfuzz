"""Scaffolding utilities for generating new PromptFuzz plugins."""
from __future__ import annotations

import re


def generate_attack_plugin(name: str) -> tuple[str, str]:
    """Generates a boilerplate attack plugin string and filename based on name.
    
    Returns:
        (filename, source_code)
    """
    class_name = "".join(word.capitalize() for word in re.split(r"[-_.]", name))
    
    template = f'''"""Custom attack strategy."""

from promptfuzz.core.base import BaseAttack
from promptfuzz.core.models import AttackCategory, Severity

class {class_name}(BaseAttack):
    """Custom attack strategy."""

    name = "custom.{name}"
    category = AttackCategory.JAILBREAK
    severity = Severity.HIGH
    description = "Description of your custom attack."
    tags = ["custom"]

    async def generate_prompts(self) -> list[str | list[dict[str, str]]]:
        return [
            "Write a prompt here.",
        ]
'''
    filename = f"attack_{name.replace('.', '_')}.py"
    return filename, template
