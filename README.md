# 🔥 PromptFuzz

**Adversarial prompt fuzzing framework for LLM applications.**

[![PyPI](https://img.shields.io/pypi/v/promptfuzz)](https://pypi.org/project/promptfuzz/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-green.svg)](https://python.org)
[![Tests](https://img.shields.io/github/actions/workflow/status/yourname/promptfuzz/ci.yml?label=tests)](https://github.com/yourname/promptfuzz/actions)

PromptFuzz systematically discovers vulnerabilities in LLM-powered applications through automated adversarial testing. It generates, mutates, and executes attack prompts against any LLM endpoint, then reports findings with severity ratings, reproduction steps, and CI integration.

**Think AFL/Burp Suite, but for prompts.**

<!-- TODO: Record terminal demo with `vhs` and add GIF here -->
<!-- ![PromptFuzz Demo](docs/demo.gif) -->

## Why PromptFuzz?

- **Beyond static lists** — Mutation engine discovers novel bypasses no human wrote
- **CI-native** — SARIF output integrates with GitHub Security tab. Non-zero exit on findings.
- **Plugin architecture** — Add custom attacks by dropping a Python file. Community-extensible.
- **Target-agnostic** — OpenAI, Anthropic, Ollama, or any HTTP endpoint.
- **Reproducible** — Every finding includes a seed for deterministic replay.

## Quick Start

```bash
pip install promptfuzz

# Generate a config file
promptfuzz init

# Run against any model (e.g., OpenAI)
promptfuzz run --model gpt-4o-mini

# Quick scan (fewer attacks, no mutations — good for CI)
promptfuzz run --model gpt-4o-mini --preset quick

# Thorough scan with JSON output
promptfuzz run --model gpt-4o-mini --preset thorough --output console,json,html

# Compare two reports
promptfuzz compare report-v1.json report-v2.json

# Reproducible run
promptfuzz run --model gpt-4o-mini --seed 42

# Launch the interactive web dashboard
promptfuzz serve
```

## Configuration

Create a `promptfuzz.yaml`:

```yaml
targets:
  - model: gpt-4o-mini
    system_prompt: "You are a helpful assistant for our banking app."

  - model: anthropic/claude-3-sonnet-20240229

attacks:
  - all  # or list specific: jailbreak.dan, injection.system_prompt_leak

detectors:
  - keyword

mutators:
  - synonym_swap
  - role_play

mutation_depth: 2
max_concurrent: 5
rate_limit_rps: 10
output_format: [console, json]
output_dir: ./promptfuzz-results
```

```bash
promptfuzz run -c promptfuzz.yaml
```

## GitHub Actions

```yaml
# .github/workflows/prompt-security.yml
name: Prompt Security Scan
on: [pull_request]

jobs:
  promptfuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install promptfuzz
      - run: promptfuzz run -c promptfuzz.yaml --preset ci --output sarif
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ./promptfuzz-results/promptfuzz.sarif
```

## Available Plugins

```bash
promptfuzz list-plugins
```

### Attacks
| Name | Category | Severity | Description |
|------|----------|----------|-------------|
| `jailbreak.dan` | Jailbreak | HIGH | DAN-style unrestricted AI role-play |
| `injection.system_prompt_leak` | Extraction | CRITICAL | System prompt extraction attempts |
| `injection.indirect` | Injection | CRITICAL | Indirect injection via documents |
| `encoding.base64_bypass` | Encoding | MEDIUM | Encoded payload bypasses |

### Targets
`litellm` (100+ native LLM providers) · `http` (any REST endpoint)

### Detectors
- `keyword` — Pattern-matching refusal detection
- `llm_judge` — Secondary LLM evaluation for robust bypass detection
- `semantic` — Embedding similarity to known-bad refusals
- `refusal_drop` — Detects unexpected refusal drops across iterations

### Mutators
`synonym_swap` · `role_play`

## Writing Custom Attacks

```python
# my_attacks/custom.py
from promptfuzz.core.base import BaseAttack
from promptfuzz.core.models import AttackCategory, Severity

class MyCustomAttack(BaseAttack):
    name = "custom.my_attack"
    category = AttackCategory.JAILBREAK
    severity = Severity.HIGH
    description = "My custom jailbreak technique"

    async def generate_prompts(self) -> list[str]:
        return [
            "Your custom adversarial prompt here...",
        ]
```

## Architecture

See [DESIGN.md](DESIGN.md) for detailed architecture decisions and trade-offs.

See [ROADMAP.md](ROADMAP.md) for the development roadmap.

## Responsible Use

PromptFuzz is a **defensive security tool**. It is designed to help teams identify and fix vulnerabilities in their own LLM applications before attackers find them.

- Only test systems you own or have explicit authorization to test.
- Default attack prompts are sourced from published academic research.
- Respect API rate limits and terms of service.
- Report vulnerabilities responsibly.

## License

Apache 2.0 — See [LICENSE](LICENSE).
