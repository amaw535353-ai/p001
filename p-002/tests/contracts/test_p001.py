import importlib.util
from pathlib import Path
import pytest
from p002.adapters.transport import ENDPOINTS

P001 = Path(__file__).resolve().parents[3]


def test_actual_p001_source_contract():
    if not (P001 / "services/common/app.py").exists():
        pytest.skip("P-001 source absent; offline core is standalone")
    spec = importlib.util.spec_from_file_location("p001_contract", P001 / "services/common/app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.object_key("fixture-p002-abcdef123") == "fixture-p002-abcdef123"
    with pytest.raises(ValueError):
        module.object_key("../arbitrary")
    assert module.authorized("Bearer p001-fixture-tenant-a", "tenant-a")
    assert not module.authorized("Bearer p001-fixture-tenant-b", "tenant-a")
    assert ENDPOINTS["p001"][0] == "http://127.0.0.1:8081"
    text = (P001 / "services/common/app.py").read_text()
    assert "P001-SYNTHETIC-ONLY" in text and "p001-" in text
