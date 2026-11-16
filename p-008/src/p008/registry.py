"""Write-once dataset versions, plans and runs with independently stored anchors."""

from pathlib import Path
import shutil

from p008.generation import bundle_digest
from p008.models import Artifact, Bundle, DatasetManifest, EvaluationPlan, EvaluationRun
from p008.quality import require_quality
from p008.safety import (
    PROJECT,
    Invalid,
    canonical,
    digest,
    identifier,
    load,
    read_bytes,
    safe_path,
    write_new,
)


class Registry:
    def __init__(self, root: Path | None = None):
        self.root = safe_path(root or PROJECT / ".runtime")

    def path(self, kind: str, *ids: str) -> Path:
        if kind not in ("datasets", "drafts", "plans", "runs", "anchors", "exports", "lab", "imports"):
            raise Invalid("UNKNOWN-REGISTRY")
        return safe_path(self.root, kind, *(identifier(x) for x in ids))

    def anchor(self, key: str, raw: bytes) -> None:
        write_new(self.path("anchors", key + ".sha256"), digest(raw).encode())

    def anchored(self, key: str, path: Path) -> bytes:
        raw = read_bytes(path)
        if read_bytes(self.path("anchors", key + ".sha256")).decode() != digest(raw):
            raise Invalid("ANCHOR-DIGEST-MISMATCH:" + key)
        return raw

    def save_draft(self, bundle: Bundle) -> Path:
        require_quality(bundle)
        path = self.path("drafts", bundle.card.dataset_id + "-" + bundle.card.version + ".json")
        write_new(path, canonical(bundle))
        return path

    def freeze(self, bundle: Bundle) -> DatasetManifest:
        require_quality(bundle)
        bundle = bundle.model_copy(update={"card": bundle.card.model_copy(update={"status": "frozen"})})
        bundle = bundle.model_copy(
            update={"card": bundle.card.model_copy(update={"manifest_digest": bundle_digest(bundle)})}
        )
        folder = self.path("datasets", bundle.card.dataset_id, bundle.card.version)
        folder.mkdir(parents=True, exist_ok=False, mode=0o700)
        payload = bundle.model_dump(mode="json")
        outcomes = payload.pop("outcomes")
        files = {
            "dataset.json": canonical(payload),
            "private/outcomes.json": canonical(outcomes),
            "model-inputs.json": canonical(
                {s.sample_id: s.input.model_dump(mode="json") for s in bundle.samples}
            ),
            "splits.json": canonical([s.model_dump(mode="json") for s in bundle.splits]),
        }
        artifacts = []
        for name, raw in files.items():
            write_new(safe_path(folder, name), raw)
            artifacts.append(Artifact(path=name, size=len(raw), sha256=digest(raw)))
        manifest = DatasetManifest(
            dataset_id=bundle.card.dataset_id,
            version=bundle.card.version,
            generator_source_hash=bundle.card.provenance.source_sha256,
            sample_ids=[s.sample_id for s in bundle.samples],
            sample_hashes={s.sample_id: s.content_digest for s in bundle.samples},
            split_hash=digest([s.model_dump(mode="json") for s in bundle.splits]),
            bundle_digest=bundle.card.manifest_digest,
            artifacts=artifacts,
        )
        raw = canonical(manifest)
        write_new(folder / "manifest.json", raw)
        self.anchor("dataset-" + bundle.card.dataset_id + "-" + bundle.card.version, raw)
        return manifest

    def dataset(self, dataset_id="synthetic-core", version="1.0.0") -> tuple[Bundle, DatasetManifest]:
        folder = self.path("datasets", dataset_id, version)
        self.anchored("dataset-" + dataset_id + "-" + version, folder / "manifest.json")
        manifest = DatasetManifest.model_validate(load(folder / "manifest.json"))
        if (manifest.dataset_id, manifest.version) != (dataset_id, version):
            raise Invalid("MANIFEST-IDENTITY-MISMATCH")
        verify_artifacts(folder, manifest.artifacts)
        value = load(folder / "dataset.json")
        value["outcomes"] = load(folder / "private/outcomes.json")
        bundle = Bundle.model_validate(value)
        require_quality(bundle)
        if manifest.bundle_digest != bundle_digest(bundle):
            raise Invalid("MANIFEST-BUNDLE-MISMATCH")
        if manifest.sample_ids != [s.sample_id for s in bundle.samples] or manifest.sample_hashes != {
            s.sample_id: s.content_digest for s in bundle.samples
        }:
            raise Invalid("MANIFEST-SAMPLE-RECONCILIATION")
        if load(folder / "model-inputs.json") != {
            s.sample_id: s.input.model_dump(mode="json") for s in bundle.samples
        }:
            raise Invalid("MODEL-INPUT-PROJECTION-MISMATCH")
        if manifest.split_hash != digest([s.model_dump(mode="json") for s in bundle.splits]):
            raise Invalid("SPLIT-HASH-MISMATCH")
        return bundle, manifest

    def save_plan(self, plan: EvaluationPlan) -> None:
        raw = canonical(plan)
        write_new(self.path("plans", plan.plan_id + ".json"), raw)
        self.anchor(plan.plan_id, raw)

    def plan(self, plan_id: str) -> EvaluationPlan:
        path = self.path("plans", plan_id + ".json")
        self.anchored(plan_id, path)
        result = EvaluationPlan.model_validate(load(path))
        if result.plan_id != plan_id:
            raise Invalid("PLAN-ID-MISMATCH")
        return result

    def save_run(self, run: EvaluationRun, folder: Path) -> None:
        raw = canonical(run)
        write_new(folder / "run.json", raw)
        self.anchor(run.run_id, raw)

    def run(self, run_id: str) -> EvaluationRun:
        folder = self.path("runs", run_id)
        self.anchored(run_id, folder / "run.json")
        run = EvaluationRun.model_validate(load(folder / "run.json"))
        if run.run_id != run_id:
            raise Invalid("RUN-ID-MISMATCH")
        if run.plan_digest != digest(run.plan):
            raise Invalid("RUN-PLAN-MISMATCH")
        if digest(self.plan(run.plan.plan_id)) != run.plan_digest:
            raise Invalid("RECORDED-PLAN-DRIFT")
        verify_artifacts(folder, run.artifacts)
        return run

    def cleanup(self, run_id: str, confirm: str) -> None:
        if confirm != "p008-owned-artifacts":
            raise Invalid("CLEANUP-CONFIRMATION-REQUIRED")
        run = self.run(run_id)
        if run.owner != "p008" or run.baseline:
            raise Invalid("PROTECTED-BASELINE-OR-FOREIGN-RESOURCE")
        folder = self.path("runs", run_id)
        for path in folder.rglob("*"):
            safe_path(folder, str(path.relative_to(folder)))
        shutil.rmtree(folder)
        self.path("anchors", run_id + ".sha256").unlink()


def verify_artifacts(folder: Path, artifacts: list[Artifact]) -> None:
    if len({a.path for a in artifacts}) != len(artifacts):
        raise Invalid("DUPLICATE-ARTIFACT")
    for artifact in artifacts:
        path = safe_path(folder, artifact.path)
        if not path.is_file():
            raise Invalid("MISSING-ARTIFACT:" + artifact.path)
        raw = read_bytes(path)
        if len(raw) != artifact.size or digest(raw) != artifact.sha256:
            raise Invalid("MODIFIED-ARTIFACT:" + artifact.path)
