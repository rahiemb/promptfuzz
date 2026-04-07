# PromptFuzz — Design Document

## 1. Problem Statement

As LLM-powered applications move into production, teams have no standardized way to test their systems against adversarial inputs. Current approaches are manual (copy-pasting jailbreaks from Reddit), inconsistent (no regression tracking), and incomplete (testing one attack type while ignoring others).

**PromptFuzz** is a fuzzing framework purpose-built for LLM applications. It systematically generates, mutates, and executes adversarial prompts against any LLM endpoint, then reports vulnerabilities with severity ratings, reproduction steps, and remediation guidance.

Think of it as **AFL/Burp Suite, but for prompts.**

## 2. Design Goals

| Priority | Goal | Rationale |
|----------|------|-----------|
| P0 | **Extensible attack plugins** | New jailbreak techniques emerge weekly. The framework must be trivially extensible. |
| P0 | **Target-agnostic** | Must work against OpenAI, Anthropic, local models, and arbitrary HTTP endpoints. |
| P0 | **CI-friendly** | Must exit with non-zero codes on findings and output machine-readable reports (SARIF, JUnit XML). |
| P1 | **Mutation-based fuzzing** | Beyond static prompt lists — mutate successful attacks to discover novel bypasses. |
| P1 | **Deterministic reproduction** | Every finding must include a seed and config that reproduces it exactly. |
| P2 | **Dashboard UI** | Optional web UI for exploring results. Not required for core functionality. |

## 3. Architecture

```
┌─────────────────────────────────────────────────────┐
│                   CLI / API Layer                    │
│              (Click CLI + FastAPI optional)          │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│                  Fuzzing Engine                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────────────┐  │
│  │  Scheduler│ │  Runner   │ │  Result Collector  │  │
│  │ (async)   │ │ (parallel)│ │  (dedup + score)   │  │
│  └─────┬─────┘ └─────┬─────┘ └────────┬──────────┘  │
│        │              │                │             │
│  ┌─────▼─────────────▼────────────────▼──────────┐  │
│  │              Campaign Manager                  │  │
│  │  (orchestrates attacks × targets × mutators)   │  │
│  └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
        │                │                │
┌───────▼──────┐ ┌───────▼──────┐ ┌──────▼───────┐
│   Attacks    │ │   Targets    │ │  Reporters   │
│  (plugins)   │ │  (adapters)  │ │  (outputs)   │
├──────────────┤ ├──────────────┤ ├──────────────┤
│ jailbreak    │ │ litellm      │ │ json         │
│ injection    │ │ http         │ │ sarif        │
│ extraction   │ │              │ │ html         │
│ encoding     │ │              │ │ junit_xml    │
│ multilingual │ │              │ │ console      │
└──────────────┘ └──────────────┘ └──────────────┘
        │
┌───────▼──────┐ ┌──────────────┐
│  Mutators    │ │  Detectors   │
│ (transforms) │ │ (classifiers)│
├──────────────┤ ├──────────────┤
│ synonym_swap │ │ keyword      │
│ encoding     │ │ llm_judge    │
│ role_play    │ │ regex        │
│ lang_switch  │ │ semantic     │
│ token_split  │ │ refusal_drop │
└──────────────┘ └──────────────┘
```

## 4. Key Design Decisions

### 4.1 Why Python (not Rust/Go)?

**Decision:** Python 3.11+ with async throughout.

**Reasoning:** The bottleneck in prompt fuzzing is **network I/O** (waiting for LLM API responses), not CPU. Python's asyncio handles thousands of concurrent requests efficiently. Choosing Rust would optimize the wrong thing and shrink the contributor pool. Every AI engineer already has Python — zero friction to adopt.

**Trade-off accepted:** Slower CLI startup time (~200ms). Acceptable for a tool that runs campaigns lasting minutes to hours.

### 4.2 Why plugin-based attacks (not a monolithic attack list)?

**Decision:** Each attack category is a Python class implementing `BaseAttack`. Users can add attacks by dropping a `.py` file in a directory or installing a pip package.

**Reasoning:** Jailbreak techniques evolve weekly. A static list becomes stale immediately. The plugin architecture lets the community contribute attacks without touching core code, and lets enterprises add proprietary attacks privately.

**Trade-off accepted:** Slightly more complex onboarding for contributors vs. a simple JSON file of prompts. Worth it for long-term maintainability.

### 4.3 Why mutation-based fuzzing (not just static lists)?

**Decision:** After a successful attack, apply mutators (synonym swaps, encoding tricks, language switching) to generate variants. Track lineage so mutations can be traced back to their parent.

**Reasoning:** Static prompt lists test known attacks. Mutation discovers **novel bypasses** — prompts that no human wrote. This is what makes PromptFuzz a fuzzer rather than a test suite. It's also what will generate the most interesting findings for blog posts and conference talks.

**Trade-off accepted:** Mutation increases runtime and can produce false positives. Mitigated by configurable mutation depth and LLM-judge verification.

### 4.4 Why SARIF output?

**Decision:** Support SARIF (Static Analysis Results Interchange Format) as a first-class output format.

**Reasoning:** SARIF integrates directly with GitHub's Security tab, VS Code's SARIF Viewer, and enterprise security dashboards. This single decision makes PromptFuzz feel like a mature security tool rather than a hobby project. It also means findings appear alongside CodeQL and Dependabot results.

### 4.5 Why LLM-as-judge for detection?

**Decision:** Use a secondary LLM call to classify whether an attack succeeded, in addition to keyword/regex matchers.

**Reasoning:** Keyword detection ("I can't help with that") has high false-negative rates — models refuse in dozens of different phrasings. An LLM judge can semantically assess whether a response constitutes a policy violation, regardless of phrasing.

**Trade-off accepted:** Additional API cost and latency for detection. Configurable — users can disable LLM judge and rely on keyword/regex only for cost-sensitive runs.

## 5. Data Model

```python
@dataclass
class AttackResult:
    id: str                    # Unique result ID
    attack_name: str           # e.g., "jailbreak.dan"
    attack_category: str       # e.g., "jailbreak"
    prompt: str                # The exact prompt sent
    response: str              # The model's response
    target: str                # e.g., "openai:gpt-4"
    success: bool              # Did the attack bypass guardrails?
    confidence: float          # 0.0-1.0 detection confidence
    severity: Severity         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    detector: str              # Which detector flagged it
    mutation_parent: str|None  # ID of parent if this is a mutation
    mutation_chain: list[str]  # Sequence of mutators applied
    seed: int                  # Random seed for reproduction
    timestamp: datetime
    latency_ms: float
    tokens_used: int
    metadata: dict             # Extensible metadata
```

## 6. Security Considerations

- **No credential storage.** API keys are read from environment variables or a `.env` file that `.gitignore` excludes by default.
- **Rate limiting.** Built-in configurable rate limits per target to avoid API bans and respect ToS.
- **Responsible disclosure.** The README includes a responsible use policy. Attack prompts in the default library are sourced from published research only.
- **Output redaction.** Reports can optionally redact the exact attack prompts (showing only categories and success rates) for sharing with non-security stakeholders.

## 7. Future Directions (Post v1.0)

- **Attack sharing hub:** Anonymized, opt-in sharing of successful attack patterns across the community (with ethical review).
- **Distributed Fuzzing:** Scale fuzzing campaigns across a cluster of worker nodes for massive concurrency.
- **Agentic Target Adapters:** Fuzz multi-step autonomous agents, measuring how far they can be manipulated to deviate from their instructions.
- **Custom Guardrail Training:** Automatically generate fine-tuning datasets from successful bypasses to train custom guardrail models.
