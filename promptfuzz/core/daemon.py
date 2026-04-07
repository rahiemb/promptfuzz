"""Daemon for running campaigns continuously."""

import asyncio
from collections.abc import Callable
from typing import Any

from rich.console import Console

from promptfuzz.core.config import load_fuzz_config
from promptfuzz.core.models import FuzzConfig

console = Console()


async def run_continuous_fuzzing(
    config_path: str, interval: int, execute_callback: Callable[[FuzzConfig], Any]
) -> None:
    """Run fuzzing campaigns continuously on a schedule.

    Args:
        config_path (str): The file path to the YAML configuration to execute.
        interval (int): The sleep duration between consecutive fuzzing runs in seconds.
        execute_callback (Callable[[FuzzConfig], Any]): The orchestrator function
            (synchronous or asynchronous) invoked per loop iteration loaded with the config.

    Raises:
        ValueError: Raised implicitly if the provided `interval` is <= 0 to prevent crashes.
    """
    if interval <= 0:
        raise ValueError(f"Interval must be a positive integer, got {interval}")

    console.print(
        f"[bold blue]Starting continuous mode via config: {config_path}[/bold blue] "
        f"(interval: {interval}s)"
    )
    while True:
        try:
            fuzz_config = load_fuzz_config(config_path=config_path)
            # Await the callback if it is a coroutine, otherwise run it directly
            result = execute_callback(fuzz_config)
            if asyncio.iscoroutine(result):
                await result

            console.print(f"[dim]Run finished. Sleeping for {interval}s...[/dim]")
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            console.print("[dim]Daemon cancelled, shutting down...[/dim]")
            break
        except KeyboardInterrupt:
            console.print("[dim]Keyboard interrupt received, stopping...[/dim]")
            break
        except Exception as e:
            console.print(f"[bold red]Daemon error[/bold red]: {e}")
            console.print_exception()
            try:
                await asyncio.sleep(interval)
            except (asyncio.CancelledError, KeyboardInterrupt):
                console.print("[dim]Daemon cancelled during error recovery, shutting down...[/dim]")
                break
