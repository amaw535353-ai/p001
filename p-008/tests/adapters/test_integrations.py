import jsonschema
import pytest

from p008.adapters import capability
from p008.integrations import import_p007, siblings
from p008.pipeline import make_plan, execute
from p008.safety import REPO, canonical, load, write_new


def actual_tool(registry, tool):
    assert capability(tool)["status"] == "PASS", "Live tool dependency unavailable: BLOCKED, never PASS"
    run = execute(registry, make_plan(registry, tool=tool, family="authorization").plan_id)
    assert run.status == "PASS" and run.metrics.executed == 8
    return run, load(registry.path("runs", run.run_id) / "tool-metadata.json")


@pytest.mark.live
def test_I01_actual_inspect_task_executes(registry):
    run, metadata = actual_tool(registry, "inspect_ai")
    assert metadata["native"]["status"] == "success"
    assert (registry.path("runs", run.run_id) / "inspect-logs").is_dir()


@pytest.mark.live
def test_I02_actual_inspect_evals_task_import_and_conversion(registry):
    run, metadata = actual_tool(registry, "inspect_evals")
    assert metadata["native"]["task"] == "strong_reject"
    assert metadata["native"]["upstream_benchmark_samples_executed"] == 0
    assert metadata["native"]["upstream_benchmark_status"] == "NOT_TESTED"
    raw = load(registry.path("runs", run.run_id) / "tool-output.json")
    assert all(r["upstream_sample_id"].startswith("strong_reject") for r in raw["samples"])


@pytest.mark.live
def test_I03_actual_agentdojo_local_environment(registry):
    run, metadata = actual_tool(registry, "agentdojo")
    raw = load(registry.path("runs", run.run_id) / "tool-output.json")
    assert metadata["native"]["suite"] == "p008-isolated-memory-v1"
    assert all(r["native_utility"] for r in raw["samples"])
    assert all(not r["native_attacker_success"] for r in raw["samples"])
    assert sum(r["server_applied_count"] for r in raw["samples"]) == 4


@pytest.mark.live
def test_I04_actual_promptfoo_assertions_retained(registry):
    run, metadata = actual_tool(registry, "promptfoo")
    assert len(metadata["assertions"]) == 8
    assert all(r["grading"]["pass"] for r in metadata["assertions"])
    assert all(r.original_status == "True" for r in run.results)


def test_I05_p007_actual_schema_valid_import_and_bad_version(tmp_path):
    source = REPO / "p-007/examples/report-export.example.json"
    before = source.read_bytes()
    imported = import_p007(source)
    assert imported.original_run_id == load(source)["run_id"]
    assert imported.report == load(source) and source.read_bytes() == before
    value = load(source)
    value["schema_version"] = "9.0"
    file = tmp_path / "invalid.json"
    write_new(file, canonical(value))
    with pytest.raises(ValueError, match="P007-INCOMPATIBLE"):
        import_p007(file)
    value["schema_version"] = "1.0"
    value["results"][0]["status"] = "SUCCESS"
    file.write_bytes(canonical(value))
    with pytest.raises(jsonschema.ValidationError):
        import_p007(file)


def test_I06_absent_p006_blocked_and_merged_p007_explicit():
    results = {x["project"]: x for x in siblings()}
    assert results["P-006"]["status"] == "BLOCKED"
    assert results["P-007"]["status"] == "PASS" and results["P-007"]["result_count"] == 11
    assert results["P-009"]["status"] == results["P-010"]["status"] == "NOT_TESTED"
