"""
tests/conftest.py - Pytest global configuration and fixtures.
"""

import os
import pytest


@pytest.fixture(autouse=True)
def isolate_blacklist_file(tmp_path, monkeypatch):
    """
    Isolates BLACKLIST_FILE to a temporary directory for every test.
    Ensures that test suites never read, mutate, or delete the user's
    persistent blacklist.txt database.
    """
    temp_bl = str(tmp_path / "blacklist.txt")
    monkeypatch.setattr("cafe_chameleon.config.BLACKLIST_FILE", temp_bl)
    monkeypatch.setattr("cafe_chameleon.utils.blacklist.BLACKLIST_FILE", temp_bl)
    yield temp_bl
    if os.path.exists(temp_bl):
        try:
            os.remove(temp_bl)
        except OSError:
            pass
