import copy

import pytest

from p008.generation import bundle_digest, generate, sample_digest
from p008.models import Bundle
from p008.pipeline import execute, make_plan
from p008.registry import Registry


@pytest.fixture(scope="session")
def bundle():
    return generate()


@pytest.fixture
def data(bundle):
    return copy.deepcopy(bundle.model_dump(mode="json"))


@pytest.fixture
def registry(tmp_path, bundle):
    result = Registry(tmp_path / "owned")
    result.freeze(bundle)
    return result


@pytest.fixture
def run(registry):
    return execute(registry, make_plan(registry).plan_id, baseline=True)


def refresh(data):
    for sample in data["samples"]:
        sample["content_digest"] = sample_digest(sample)
    candidate = Bundle.model_validate(data)
    return candidate.model_copy(
        update={"card": candidate.card.model_copy(update={"manifest_digest": bundle_digest(candidate)})}
    )


def move_split(data, index=0):
    sample = data["samples"][index]
    old = sample["split"]
    new = next(s["name"] for s in data["splits"] if s["name"] != old)
    sample["split"] = new
    for split in data["splits"]:
        if split["name"] == old:
            split["sample_ids"].remove(sample["sample_id"])
        elif split["name"] == new:
            split["sample_ids"].append(sample["sample_id"])
    return data
