"""PromptFuzz CLI — Adversarial prompt fuzzing for LLM applications."""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import sys

import click
import yaml
from dotenv import load_dotenv
from rich.console import Console

import promptfuzz.attacks.encoding  # noqa: F401
import promptfuzz.attacks.extraction  # noqa: F401
import promptfuzz.attacks.injection  # noqa: F401
import promptfuzz.attacks.jailbreak  # noqa: F401
import promptfuzz.attacks.multi_turn  # noqa: F401
import promptfuzz.attacks.rag  # noqa: F401
import promptfuzz.detectors.keyword  # noqa: F401
import promptfuzz.detectors.llm_judge  # noqa: F401
import promptfuzz.detectors.refusal_drop  # noqa: F401
import promptfuzz.detectors.semantic  # noqa: F401
import promptfuzz.mutators.transforms  # noqa: F401
import promptfuzz.reporters.outputs  # noqa: F401
import promptfuzz.targets.providers  # noqa: F401
from promptfuzz import __version__
from promptfuzz.core.base import BaseAttack, BaseDetector, BaseMutator, BaseReporter, BaseTarget
from promptfuzz.core.config import load_fuzz_config
from promptfuzz.core.engine import FuzzEngine
from promptfuzz.core.scaffold import generate_attack_plugin


def load_plugins() -> None:
    for _, name, _ in pkgutil.iter_modules():
        if name.startswith("promptfuzz_"):
            try:
                importlib.import_module(name)
            except Exception:
                console.print_exception(show_locals=False)
                console.print(f"[bold red]Failed to load plugin module {name}[/bold red]")

load_plugins()

load_dotenv()
console = Console()
async def execute_campaign(fuzz_config):
    engine = FuzzEngine(fuzz_config)
    summary = await engine.run()
    for fmt in fuzz_config.output_format:
        reporter_cls = BaseReporter._registry.get(fmt)
        if reporter_cls:
            reporter = reporter_cls()
            await reporter.report(summary, fuzz_config.output_dir)
    return summary

@click.group()
@click.version_option(version=__version__, prog_name="promptfuzz")
def main() -> None:
    """PromptFuzz — Adversarial prompt fuzzing for LLM applications."""
    pass


@main.command()
@click.option(
    "--model",
    "-m",
    required=False,
    help="Model name (e.g., gpt-4o-mini, anthropic/claude-3-sonnet-20240229)",
)
@click.option(
    "--api-key",
    "-k",
    envvar="LITELLM_API_KEY",
    default="",
    help="API key (or set LITELLM_API_KEY env var)",
)
@click.option(
    "--base-url",
    "-u",
    envvar="LITELLM_BASE_URL",
    default="",
    help="Base URL (or set LITELLM_BASE_URL env var)",
)
@click.option("--attacks", "-a", default="all", help="Comma-separated attack names, or 'all'")
@click.option("--config", "-c", default=None, type=click.Path(exists=True), help="YAML config file")
@click.option("--output", "-o", default="console", help="Output format: console, json")
@click.option("--seed", "-s", default=None, type=int, help="Random seed for reproducible runs")
@click.option("--preset", "-p", default=None, help="Preset: quick, thorough, ci")
@click.option("--system-prompt", default="", help="System prompt for the target")
@click.option("--rate-limit", default=10.0, type=float, help="Max requests per second")
@click.option("--concurrency", default=5, type=int, help="Max concurrent requests")
def run(
    model: str,
    api_key: str,
    base_url: str,
    attacks: str,
    config: str | None,
    output: str,
    seed: int | None,
    preset: str | None,
    system_prompt: str,
    rate_limit: float,
    concurrency: int,
) -> None:
    """Run a fuzzing campaign against an LLM target."""

    fuzz_config = load_fuzz_config(
        model=model,
        api_key=api_key,
        base_url=base_url,
        attacks=attacks,
        config_path=config,
        output=output,
        seed=seed,
        preset=preset,
        system_prompt=system_prompt,
        rate_limit=rate_limit,
        concurrency=concurrency,
    )

    summary = asyncio.run(execute_campaign(fuzz_config))
    if summary.successful_attacks > 0:
        sys.exit(1)
    else:
        sys.exit(0)


@main.command()
@click.option("--model", "-m", required=False, help="Model name (e.g., gpt-4o-mini)")
@click.option("--api-key", "-k", envvar="LITELLM_API_KEY", default="", help="API key")
@click.option("--base-url", "-u", envvar="LITELLM_BASE_URL", default="", help="Base URL")
@click.option("--config", "-c", default=None, type=click.Path(exists=True), help="YAML config file")
@click.pass_context
def scan(
    ctx: click.Context,
    model: str,
    api_key: str,
    base_url: str,
    config: str | None,
) -> None:
    """Quick preset for CI — fast, essential attacks only."""
    ctx.invoke(
        run,
        model=model,
        api_key=api_key,
        base_url=base_url,
        attacks="all",
        config=config,
        output="console,sarif",
        seed=None,
        preset="ci",
        system_prompt="",
        rate_limit=10.0,
        concurrency=5,
    )


@main.command()
def list_plugins() -> None:
    """List all available attacks, targets, detectors, and mutators."""
    console.print("\n[bold]Attacks:[/bold]")
    for name, attack_cls in sorted(BaseAttack._registry.items()):
        attack = attack_cls()
        console.print(f"  [green]{name}[/green] — {attack.description}")

    console.print("\n[bold]Targets:[/bold]")
    for name in sorted(BaseTarget._registry.keys()):
        console.print(f"  [blue]{name}[/blue]")

    console.print("\n[bold]Detectors:[/bold]")
    for name in sorted(BaseDetector._registry.keys()):
        console.print(f"  [yellow]{name}[/yellow]")

    console.print("\n[bold]Mutators:[/bold]")
    for name in sorted(BaseMutator._registry.keys()):
        console.print(f"  [cyan]{name}[/cyan]")

    console.print()


@main.command()
@click.argument("output", default="promptfuzz.yaml")
def init(output: str) -> None:
    """Generate a starter config file."""
    starter = {
        "targets": [
            {
                "model": "gpt-4o-mini",
                "api_key": "${LITELLM_API_KEY}",
                "base_url": "",
                "system_prompt": "You are a helpful assistant.",
            }
        ],
        "attacks": ["all"],
        "detectors": ["keyword"],
        "mutators": ["synonym_swap", "role_play"],
        "mutation_depth": 2,
        "mutation_breadth": 3,
        "max_concurrent": 5,
        "rate_limit_rps": 10,
        "output_format": ["console", "json"],
        "output_dir": "./promptfuzz-results",
    }

    with open(output, "w") as f:
        yaml.dump(starter, f, default_flow_style=False, sort_keys=False)

    console.print(f"[green]✓[/green] Config written to {output}")
    console.print("[dim]Edit the file, then run: promptfuzz run -c promptfuzz.yaml[/dim]")


@main.command()
@click.argument("run_old", type=click.Path(exists=True))
@click.argument("run_new", type=click.Path(exists=True))
def compare(run_old: str, run_new: str) -> None:
    """Compare two JSON reports to find regressions."""
    from promptfuzz.reporters.outputs import compare_reports
    compare_reports(run_old, run_new)


@main.group()
def dev() -> None:
    """Development and plugin utilities."""
    pass


@dev.command(name="create-attack")
@click.argument("name")
def create_attack(name: str) -> None:
    """Scaffold a new attack plugin."""
    filename, template = generate_attack_plugin(name)
    with open(filename, "w") as f:
        f.write(template)
    
    console.print(f"[green]✓[/green] Attack plugin scaffolded in {filename}")


@main.command()
@click.option(
    "--config", "-c", default="promptfuzz.yaml", type=click.Path(exists=True), 
    help="YAML config file"
)
@click.option("--interval", "-i", default=3600, type=int, help="Interval between runs in seconds")
@click.pass_context
def watch(ctx: click.Context, config: str, interval: int) -> None:
    """Run fuzzing campaigns continuously on a schedule."""
    from promptfuzz.core.daemon import run_continuous_fuzzing
    asyncio.run(run_continuous_fuzzing(config, interval, execute_campaign))


@main.command()
@click.option("--port", "-p", default=8000, type=int, help="Port to listen on")
def serve(port: int) -> None:
    """Run the FastAPI dashboard backend."""
    from promptfuzz.dashboard import run_dashboard
    console.print(f"[bold green]Starting PromptFuzz Dashboard on port {port}...[/bold green]")
    run_dashboard(port)


@main.command()
@click.option(
    "--models", default="gpt-4o-mini", help="Comma-separated model names to benchmark against."
)
@click.option("--attacks", default="all", help="Attacks to test")
def benchmark(models: str, attacks: str) -> None:
    """Run standardized benchmarking across configured targets."""
    from promptfuzz.core.engine import print_benchmark_results, run_benchmark
    
    model_list = models.split(",")
    console.print(f"[bold blue]Starting Benchmark across {len(model_list)} models...[/bold blue]")

    results = asyncio.run(run_benchmark(model_list, attacks))
    print_benchmark_results(results)


if __name__ == "__main__":
    main()
