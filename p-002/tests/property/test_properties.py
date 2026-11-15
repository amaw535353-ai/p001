from hypothesis import given, settings, strategies as st
from p002.generators import generate
from p002.exporters import canonical
from p002.models import Dataset
from p002.policies import evaluate


@given(st.integers(min_value=0, max_value=2**32 - 1))
@settings(max_examples=12, deadline=None)
def test_seed_invariants(seed):
    d = generate(seed, "tiny")
    assert Dataset.model_validate_json(canonical(d.model_dump(mode="json"))) == d
    assert len({x.id for rows in d.tables().values() for x in rows}) == sum(
        len(x) for x in d.tables().values()
    )
    assert all(
        evaluate(d, "p002:tenant-b:hr:u0", "read", r.id)[0] == "DENY"
        for r in d.resources
        if r.tenant_id == "p002:tenant-a"
    )
