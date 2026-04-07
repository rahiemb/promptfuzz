import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptfuzz.core.daemon import run_continuous_fuzzing


@pytest.mark.asyncio
async def test_daemon_interval_validation():
    """Test that the daemon properly validates interval inputs."""
    with pytest.raises(ValueError, match="Interval must be a positive integer, got 0"):
        await run_continuous_fuzzing(
            config_path="dummy.yaml",
            interval=0,
            execute_callback=lambda x: None
        )

    with pytest.raises(ValueError, match="Interval must be a positive integer, got -5"):
        await run_continuous_fuzzing(
            config_path="dummy.yaml",
            interval=-5,
            execute_callback=lambda x: None
        )


@pytest.mark.asyncio
@patch("promptfuzz.core.daemon.asyncio.sleep")
@patch("promptfuzz.core.daemon.load_fuzz_config")
async def test_daemon_graceful_exit_keyboard(mock_load, mock_sleep):
    """Test that KeyboardInterrupt stops the daemon gracefully."""
    mock_load.return_value = MagicMock()
    mock_sleep.side_effect = KeyboardInterrupt()

    callback_mock = MagicMock()
    
    # Run the daemon
    await run_continuous_fuzzing("dummy.yaml", 5, callback_mock)
    
    callback_mock.assert_called_once()


@pytest.mark.asyncio
@patch("promptfuzz.core.daemon.asyncio.sleep")
@patch("promptfuzz.core.daemon.load_fuzz_config")
async def test_daemon_graceful_exit_cancelled(mock_load, mock_sleep):
    """Test that asyncio.CancelledError stops the daemon gracefully."""
    mock_load.return_value = MagicMock()
    mock_sleep.side_effect = asyncio.CancelledError()

    callback_mock = AsyncMock()
    
    # Run the daemon
    await run_continuous_fuzzing("dummy.yaml", 5, callback_mock)
    
    callback_mock.assert_called_once()


@pytest.mark.asyncio
@patch("promptfuzz.core.daemon.Console.print_exception")
@patch("promptfuzz.core.daemon.Console.print")
@patch("promptfuzz.core.daemon.asyncio.sleep")
@patch("promptfuzz.core.daemon.load_fuzz_config")
async def test_daemon_exception_recovery(mock_load, mock_sleep, mock_print, mock_print_exception):
    """Test that an internal exception is caught and gracefully logged."""
    mock_load.return_value = MagicMock()
    
    # Make sleep raise CancelledError immediately on its first call to break the loop after 1 crash
    mock_sleep.side_effect = [asyncio.CancelledError()]
    
    async def crash_callback(config):
        raise RuntimeError("simulated crash inside callback")

    await run_continuous_fuzzing("dummy.yaml", 2, crash_callback)
    
    # It should have printed the exception using rich traceback
    mock_print_exception.assert_called_once()
    
    # Verify the specific error message text was emitted
    crashed_msg = mock_print.call_args_list[-2].args[0]
    assert "Daemon error" in crashed_msg
    assert "simulated crash inside callback" in crashed_msg
