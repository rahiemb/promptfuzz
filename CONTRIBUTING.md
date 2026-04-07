# Contributing to PromptFuzz

Thank you for your interest in contributing to PromptFuzz! 

## Implementing New Attacks

All attacks inherit from `BaseAttack` in `promptfuzz.core.base`. 
We've made building a new attack incredibly simple:

1. Scaffold your attack using the CLI:
   ```bash
   promptfuzz create-attack my-new-attack
   ```
2. Open the generated file and implement the `generate_prompts` async function.
3. Test it using `promptfuzz run -m gpt-4o-mini -a custom.my-new-attack`.

## Contributing Community Plugins

PromptFuzz dynamically discovers plugins from packages prefixed with `promptfuzz_`. To release your attacks to the broader community:
1. Initialize a generic python project (e.g. `promptfuzz_sql_injection`).
2. Have your package import elements from `promptfuzz`.
3. Publish to PyPI. PromptFuzz users can simply `pip install promptfuzz-sql-injection` and your plugin will instantly be available in the `--attacks` flag!
