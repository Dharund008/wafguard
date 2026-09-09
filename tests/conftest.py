"""Pytest fixtures for offline WafGuard tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from helpers import FIXTURES, make_config


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def basic_config():
    return make_config()
