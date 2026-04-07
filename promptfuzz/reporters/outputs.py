"""Report generators for fuzzing results."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from promptfuzz import __version__
from promptfuzz.core.base import BaseReporter
from promptfuzz.core.models import CampaignSummary, Severity

console = Console()


class ConsoleReporter(BaseReporter):
    """Rich-formatted terminal output."""

    name = "console"

    async def report(self, summary: CampaignSummary, output_dir: str) -> str | None:
        console.print()

        if summary.successful_attacks > 0:
            console.print(
                Panel(
                    f"[bold red]✗ {summary.successful_attacks} vulnerabilities found[/bold red]",
                    title="PromptFuzz Results",
                    border_style="red",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold green]✓ No vulnerabilities found[/bold green]",
                    title="PromptFuzz Results",
                    border_style="green",
                )
            )

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="dim")
        table.add_column("Value")
        table.add_row("Total attacks", str(summary.total_attacks))
        table.add_row(
            "Successful",
            f"[red]{summary.successful_attacks}[/red]" if summary.successful_attacks else "0",
        )
        table.add_row("Success rate", f"{summary.success_rate:.1%}")
        table.add_row("Duration", f"{summary.duration_seconds:.1f}s")
        table.add_row("Targets", ", ".join(summary.targets_tested))
        table.add_row("Categories", ", ".join(summary.attack_categories_tested))
        console.print(table)

        if summary.successful_attacks > 0:
            console.print()
            sev_table = Table(title="Severity Breakdown", show_lines=False)
            sev_table.add_column("Severity", justify="center")
            sev_table.add_column("Count", justify="center")

            if summary.critical_count:
                sev_table.add_row("[bold red]CRITICAL[/bold red]", str(summary.critical_count))
            if summary.high_count:
                sev_table.add_row("[red]HIGH[/red]", str(summary.high_count))
            if summary.medium_count:
                sev_table.add_row("[yellow]MEDIUM[/yellow]", str(summary.medium_count))
            if summary.low_count:
                sev_table.add_row("[dim]LOW[/dim]", str(summary.low_count))

            console.print(sev_table)

            console.print("\n[bold]Findings:[/bold]\n")
            for _i, finding in enumerate(summary.findings, 1):
                severity_style = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "dim",
                    Severity.INFO: "dim",
                }[finding.severity]

                console.print(
                    f"  [{severity_style}]{finding.severity.value.upper()}[/{severity_style}] "
                    f"[bold]{finding.attack_name}[/bold] → {finding.target}"
                )
                console.print(
                    f"    Confidence: {finding.confidence:.0%} | Detector: {finding.detector}"
                )

                prompt_preview = finding.prompt[:120].replace("\n", " ")
                console.print(f"    Prompt: [dim]{prompt_preview}...[/dim]")

                if finding.is_mutation:
                    chain = " → ".join(finding.mutation_chain)
                    console.print(f"    Mutation: [cyan]{chain}[/cyan]")

                console.print()

        return None


class FileReporter(BaseReporter):
    """Base class for file-based reporters."""

    filename: str

    def generate_content(self, summary: CampaignSummary) -> str:
        raise NotImplementedError

    async def report(self, summary: CampaignSummary, output_dir: str) -> str | None:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        report_file = output_path / self.filename

        content = self.generate_content(summary)
        report_file.write_text(content, encoding="utf-8")

        console.print(f"\n[dim]{self.name.upper()} report saved to {report_file}[/dim]")
        return str(report_file)


class JSONReporter(FileReporter):
    """JSON file output."""

    name = "json"
    filename = "promptfuzz-report.json"

    def generate_content(self, summary: CampaignSummary) -> str:
        report_data = {
            "version": __version__,
            "summary": {
                "total_attacks": summary.total_attacks,
                "successful_attacks": summary.successful_attacks,
                "success_rate": summary.success_rate,
                "severity_counts": {
                    "critical": summary.critical_count,
                    "high": summary.high_count,
                    "medium": summary.medium_count,
                    "low": summary.low_count,
                },
                "targets_tested": summary.targets_tested,
                "attack_categories": summary.attack_categories_tested,
                "duration_seconds": summary.duration_seconds,
            },
            "findings": [finding.model_dump(mode="json") for finding in summary.findings],
        }
        return json.dumps(report_data, indent=2, default=str)


class SARIFReporter(FileReporter):
    """SARIF format output for GitHub Security tab integration."""

    name = "sarif"
    filename = "promptfuzz.sarif"

    def generate_content(self, summary: CampaignSummary) -> str:
        rules = {}
        results = []

        for finding in summary.findings:
            if not finding.success:
                continue

            rule_id = finding.attack_name
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f"LLM Vulnerability: {rule_id}"},
                    "fullDescription": {"text": f"Category: {finding.attack_category.value}"},
                    "defaultConfiguration": {
                        "level": "error"
                        if finding.severity.value in ["critical", "high"]
                        else "warning"
                    },
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "message": {"text": f"Target '{finding.target}' is vulnerable to {rule_id}."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"target:{finding.target}"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            )

        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PromptFuzz",
                            "informationUri": "https://github.com/promptfuzz",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif_data, indent=2)


def compare_reports(run_old: str, run_new: str) -> None:
    """Compare two JSON reports to find regressions and output them to the console."""
    with open(run_old) as f:
        old_data = json.load(f)
    with open(run_new) as f:
        new_data = json.load(f)
    
    old_findings = {f["prompt"]: f for f in old_data.get("findings", [])}
    new_findings = {f["prompt"]: f for f in new_data.get("findings", [])}
    
    regressions = []
    for prompt, finding in new_findings.items():
        if prompt not in old_findings:
            regressions.append(finding)
            
    if not regressions:
        console.print("[green]No regressions found.[/green]")
    else:
        console.print(f"\n[bold red]Found {len(regressions)} new regressions![/bold red]")
        for req in regressions:
            console.print(f"  - [red]{req.get('attack_name')}[/red] -> {req.get('target')}")
            console.print(
                f"    Confidence: {req.get('confidence')} | Severity: {req.get('severity')}"
            )
            prompt_preview = req.get("prompt", "")[:120].replace("\n", " ")
            console.print(f"    Prompt: [dim]{prompt_preview}...[/dim]\n")
