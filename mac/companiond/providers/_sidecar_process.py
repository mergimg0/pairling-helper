from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import BinaryIO


def close_owned_process(
    process: subprocess.Popen[bytes],
    *,
    reader: threading.Thread | None = None,
    process_group: bool = False,
    terminate_timeout: float = 1.5,
    kill_timeout: float = 1.0,
    reader_join_timeout: float = 1.0,
) -> None:
    """Close one owned child and its pipes without waiting on the reader first."""

    _close_stream(process.stdin)
    try:
        if process.poll() is None:
            _signal_process(process, signal.SIGTERM, process_group=process_group)
        try:
            process.wait(timeout=terminate_timeout)
        except subprocess.TimeoutExpired:
            _signal_process(process, signal.SIGKILL, process_group=process_group)
            try:
                process.wait(timeout=kill_timeout)
            except (OSError, subprocess.TimeoutExpired):
                pass
        except OSError:
            pass
    finally:
        _close_stream(process.stdout)
        _close_stream(process.stderr)
        if reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=reader_join_timeout)


def _signal_process(
    process: subprocess.Popen[bytes],
    signal_number: int,
    *,
    process_group: bool,
) -> None:
    try:
        if process_group:
            os.killpg(process.pid, signal_number)
        elif signal_number == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
        return
    except (OSError, ProcessLookupError):
        pass

    try:
        if signal_number == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except OSError:
        pass


def _close_stream(stream: BinaryIO | None) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except (OSError, ValueError):
        pass
