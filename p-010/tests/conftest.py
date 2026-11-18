from pathlib import Path

import pytest

from p010.demo import run
from p010.safety import ROOT
from p010.store import Workspace


@pytest.fixture
def example(tmp_path: Path) -> Workspace:
    workspace = Workspace(tmp_path / "demo")
    run(workspace, p008=ROOT / "fixtures/p008-export.json")
    return workspace
