import json
import pytest
from p002.generators import generate
from p002.scenarios import write_dataset, load_dataset, seed, reset, verify_files, validate_overlay, catalog
from p002.models import Scenario


@pytest.fixture
def owned(tmp_path, monkeypatch):
    import p002.scenarios as s

    monkeypatch.setattr(s, "GENERATED", tmp_path / "generated")
    return tmp_path / "generated" / "baseline"


@pytest.mark.parametrize("id", [f"S{i:02}" for i in range(1, 13)])
def test_seed_diff_reset_repeat(id, owned):
    d = generate(4, "tiny")
    write_dataset(d, owned)
    before = verify_files(owned)
    scenario = next(s for s in catalog() if s.id == id)
    if scenario.unsafe:
        with pytest.raises(ValueError, match="unsafe-scenario"):
            seed(id, owned)
    first = seed(id, owned, unsafe=True)
    assert first == seed(id, owned, unsafe=True)
    assert validate_overlay(id)["status"] == "SEEDED"
    if id in ["S02", "S03", "S04", "S05", "S06", "S07", "S10", "S11"]:
        assert first["case"]["expected"] == "DENY"
    assert verify_files(owned) == before and load_dataset(owned) == d
    assert reset(id)["status"] == "reset-owned-snapshot"
    assert reset(id)["status"] == "already-reset"
    assert load_dataset(owned) == d


def test_baseline_tamper(owned):
    write_dataset(generate(2, "tiny"), owned)
    (owned / "dataset.json").write_text("{}")
    with pytest.raises(ValueError, match="hash"):
        seed("S01", owned)


def test_non_owned_cleanup_and_paths(owned):
    from p002.scenarios import owned_path

    with pytest.raises(ValueError, match="unsafe path"):
        owned_path("/tmp/unrelated")
    with pytest.raises(ValueError):
        reset("../../other")
    owned.mkdir(parents=True)
    (owned / "user-file").write_text("keep")
    with pytest.raises((ValueError, OSError)):
        write_dataset(generate(2, "tiny"), owned)
    assert (owned / "user-file").read_text() == "keep"


def test_strict_scenario_input():
    s = catalog()[0].model_dump()
    s["steps"][0]["operation"] = "shell"
    with pytest.raises(ValueError):
        Scenario.model_validate(s)
    with pytest.raises(ValueError):
        Scenario.model_validate_json("not: [valid YAML")


def test_integrity_artifacts_are_measurable_and_never_executed(owned):
    write_dataset(generate(1, "tiny"), owned)
    from p002.scenarios import overlay_path

    seed("S08", owned, True)
    text = (overlay_path("S08") / "untrusted-document.txt").read_text()
    assert "INERT UNTRUSTED TEXT" in text and "=HYPERLINK" in text
    reset("S08")
    seed("S09", owned, True)
    citation = json.loads((overlay_path("S09") / "citation-index.json").read_text())
    assert citation["canonical_source"] != citation["claimed_source"] and not citation["trusted"]
    reset("S09")
    seed("S12", owned, True)
    annotation = json.loads((overlay_path("S12") / "annotation-divergence.json").read_text())
    assert annotation["canonical_label"] != annotation["derived_label"]
    reset("S12")
