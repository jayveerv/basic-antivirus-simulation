import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from av.samples import create_samples  # noqa: E402
from av.scanner import Scanner  # noqa: E402


@pytest.fixture(scope="session")
def scanner():
    return Scanner()


@pytest.fixture
def samples(tmp_path):
    folder = tmp_path / "samples"
    create_samples(str(folder))
    return folder
