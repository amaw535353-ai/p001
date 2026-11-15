"""Only verify running owned labs; unavailable adapters remain counted as BLOCKED."""

import argparse
from p002.adapters import adapter
from p002.adapters.transport import ENDPOINTS, owned_container
from p002.scenarios import load_dataset, GENERATED
from p002.operations import record_run


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", choices=list(ENDPOINTS))
    a = p.parse_args()
    d = load_dataset(GENERATED / "standard")
    rows = []
    fail = False
    names = [a.name] if a.name else list(ENDPOINTS)
    for name in names:
        if not owned_container(ENDPOINTS[name][1]):
            rows.append(
                {
                    "id": name + ":availability",
                    "status": "BLOCKED",
                    "expected": "running owned lab",
                    "observed": "lab not running; no enforcement tested",
                    "platform": name,
                }
            )
            continue
        try:
            obj = adapter(name, d, "docker")
            obj.seed()
            obj.seed()
            actual = obj.verify()
            rows.extend(actual)
            fail |= any(x["status"] == "FAIL" for x in actual)
        except (ValueError, RuntimeError) as e:
            rows.append(
                {
                    "id": name + ":integration",
                    "status": "FAIL",
                    "expected": "idempotent import and native roundtrip",
                    "observed": str(e),
                    "platform": name,
                }
            )
            fail = True
    out = record_run(
        "integrations", rows, d, args="make integration-test" + (" --name " + a.name if a.name else "")
    )
    print(out)
    from collections import Counter

    print(dict(Counter(x["status"] for x in rows)))
    return 1 if fail else (2 if any(x["status"] == "BLOCKED" for x in rows) else 0)


if __name__ == "__main__":
    raise SystemExit(main())
