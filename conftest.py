"""
Root conftest.

tests/tools-invocation/ runs the console scripts as subprocesses, and coverage does not
follow those on its own: without what is set up here the five wa*.py entry points report 0%
no matter how much those tests exercise them.

coverage ships a .pth file that calls coverage.process_startup() in every Python process
that starts while COVERAGE_PROCESS_START names a config file, so each subprocess measures
itself; "parallel = true" in .coveragerc keeps their data files apart and pytest-cov
combines them at the end. The only missing piece is the environment variable, and it has to
be set before any test spawns anything -- so it is set here rather than in CI, and a plain
"python -m pytest --cov" is enough.
"""

from __future__ import annotations

import os
from pathlib import Path


def pytest_configure(config):
    # Only when coverage is actually being collected: otherwise every subprocess of every
    # test run would start coverage and litter the working directory with .coverage.* files.
    if getattr(config.option, "cov_source", None):
        os.environ["COVERAGE_PROCESS_START"] = str(Path(__file__).parent / ".coveragerc")
