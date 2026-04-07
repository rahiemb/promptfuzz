"""Tests for CLI module."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from promptfuzz.cli import main
from promptfuzz.core.models import CampaignSummary


def test_list_plugins():
    runner = CliRunner()
    result = runner.invoke(main, ["list-plugins"])
    assert result.exit_code == 0
    assert "Attacks:" in result.output
    assert "Targets:" in result.output
    assert "Detectors:" in result.output
    assert "Mutators:" in result.output


def test_init_command(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        assert "Config written to promptfuzz.yaml" in result.output
        assert Path("promptfuzz.yaml").exists()

        with open("promptfuzz.yaml") as f:
            data = yaml.safe_load(f)
            assert "targets" in data
            assert data["targets"][0]["model"] == "gpt-4o-mini"


def test_init_command_custom_output(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init", "custom.yaml"])
        assert result.exit_code == 0
        assert Path("custom.yaml").exists()


@patch("promptfuzz.cli.FuzzEngine")
@patch.dict("promptfuzz.core.base.BaseReporter._registry")
def test_run_command_flags(mock_engine, tmp_path):
    runner = CliRunner()

    mock_instance = mock_engine.return_value
    summary = CampaignSummary()

    # It takes a mock coro because it's called using asyncio.run
    async def mock_run():
        return summary

    mock_instance.run.return_value = mock_run()

    mock_reporter = MagicMock()

    async def mock_report(s, d):
        pass

    mock_reporter.report.return_value = mock_report(summary, "")
    import promptfuzz.core.base
    mock_reporter_cls = MagicMock()
    mock_reporter_cls.return_value = mock_reporter
    promptfuzz.core.base.BaseReporter._registry["console"] = mock_reporter_cls

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["run", "--model", "gpt-4"])
        assert result.exit_code == 0
        mock_engine.assert_called_once()
        config_passed = mock_engine.call_args[0][0]
        assert config_passed.targets[0].model == "gpt-4"


def test_run_command_missing_model_and_config(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["run"])
        assert result.exit_code == 2
        assert (
            "Missing parameter: requires --model, --config, or a promptfuzz.yaml file."
            in result.output
        )


@patch("promptfuzz.cli.FuzzEngine")
@patch.dict("promptfuzz.core.base.BaseReporter._registry")
def test_run_command_implicit_yaml(mock_engine, tmp_path):
    runner = CliRunner()

    mock_instance = mock_engine.return_value
    summary = CampaignSummary()

    async def mock_run():
        return summary

    mock_instance.run.return_value = mock_run()

    mock_reporter = MagicMock()

    async def mock_report(s, d):
        pass

    mock_reporter.report.return_value = mock_report(summary, "")
    import promptfuzz.core.base
    mock_reporter_cls = MagicMock()
    mock_reporter_cls.return_value = mock_reporter
    promptfuzz.core.base.BaseReporter._registry["console"] = mock_reporter_cls

    with runner.isolated_filesystem(temp_dir=tmp_path):
        # Create a promptfuzz.yaml
        yaml_content = {"targets": [{"model": "yaml-model"}]}
        with open("promptfuzz.yaml", "w") as f:
            yaml.dump(yaml_content, f)

        # Run without parameters, should load promptfuzz.yaml
        result = runner.invoke(main, ["run", "--seed", "42"])
        assert result.exit_code == 0
        mock_engine.assert_called_once()
        config_passed = mock_engine.call_args[0][0]
        assert config_passed.targets[0].model == "yaml-model"
        assert config_passed.seed == 42  # Seed overwritten


@patch("promptfuzz.cli.FuzzEngine")
@patch.dict("promptfuzz.core.base.BaseReporter._registry")
def test_run_command_presets(mock_engine, tmp_path):
    runner = CliRunner()
    mock_instance = mock_engine.return_value
    summary = CampaignSummary()

    async def mock_run():
        return summary

    mock_instance.run.return_value = mock_run()

    mock_reporter_cls = MagicMock()
    mock_reporter = mock_reporter_cls.return_value

    async def mock_report(s, d):
        pass

    mock_reporter.report.return_value = mock_report(summary, "")
    import promptfuzz.core.base
    promptfuzz.core.base.BaseReporter._registry["console"] = mock_reporter_cls
    promptfuzz.core.base.BaseReporter._registry["sarif"] = mock_reporter_cls

    with runner.isolated_filesystem(temp_dir=tmp_path):
        runner.invoke(main, ["run", "--model", "test-model", "--preset", "quick"])

        mock_engine.assert_called()
        config_passed = mock_engine.call_args[0][0]
        assert config_passed.preset == "quick"
        assert "jailbreak.dan" in config_passed.attacks
        assert config_passed.mutation_depth == 0

        # Run with ci preset
        runner.invoke(main, ["run", "--model", "test-model", "--preset", "ci"])
        config_passed = mock_engine.call_args[0][0]
        assert config_passed.preset == "ci"
        assert config_passed.mutation_depth == 1

        # Run with thorough preset
        runner.invoke(main, ["run", "--model", "test-model", "--preset", "thorough"])
        config_passed = mock_engine.call_args[0][0]
        assert config_passed.preset == "thorough"
        assert config_passed.mutation_depth == 3


@patch("promptfuzz.cli.FuzzEngine")
@patch.dict("promptfuzz.core.base.BaseReporter._registry")
def test_run_command_failure_exit_code(mock_engine, tmp_path):
    runner = CliRunner()
    mock_instance = mock_engine.return_value
    summary = CampaignSummary()
    summary.successful_attacks = 1  # Force failure

    async def mock_run():
        return summary

    mock_instance.run.return_value = mock_run()

    mock_reporter_cls = MagicMock()
    mock_reporter = mock_reporter_cls.return_value

    async def mock_report(s, d):
        pass

    mock_reporter.report.return_value = mock_report(summary, "")
    import promptfuzz.core.base
    promptfuzz.core.base.BaseReporter._registry["console"] = mock_reporter_cls

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["run", "--model", "test-model"])
        assert result.exit_code == 1  # Exits 1 if findings present
