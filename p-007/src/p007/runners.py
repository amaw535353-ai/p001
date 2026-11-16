"""Shared discovery, bounded subprocess execution and deterministic offline runner."""

from dataclasses import dataclass
import importlib.metadata
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time

from p007.models import Adapter, ErrorClass, Limits, RunnerResult, TestCase
from p007.safety import PROJECT, Blocked, read_bytes
from p007.synthetic import respond

PINS = {
    "offline": "builtin-1.0",
    "promptfoo": "0.125.1",
    "inspect_ai": "0.3.290",
    "zap": "2.17.0",
    "playwright": "1.65.2",
    "p006": "contract-only-v1",
}


@dataclass(frozen=True)
class Capability:
    adapter: str
    available: bool
    version: str
    executable: str | None
    reason: str


def environment(directory: Path) -> dict[str, str]:
    # No provider credentials, proxy credentials or arbitrary env values cross this boundary.
    result = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
    result.update(
        PYTHONPATH=str(PROJECT / "src"),
        XDG_CACHE_HOME=str(directory / "cache"),
        XDG_CONFIG_HOME=str(directory / "config"),
        XDG_DATA_HOME=str(directory / "data"),
        XDG_STATE_HOME=str(directory / "state"),
        TMPDIR=str(directory),
        PROMPTFOO_CONFIG_DIR=str(directory / "promptfoo"),
        PROMPTFOO_DISABLE_TELEMETRY="1",
        PROMPTFOO_DISABLE_UPDATE="1",
        DO_NOT_TRACK="1",
        INSPECT_EVAL_LOG_DIR=str(directory / "inspect-logs"),
        NODE_OPTIONS="--max-old-space-size=768",
        HF_HUB_OFFLINE="1",
        JAVA_TOOL_OPTIONS="-Xmx768m",
    )
    return result


def bounds(limits: Limits):
    def apply():
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        # Tool databases/add-on extraction need more space than retained evidence.
        # Stdout and evidence remain separately bounded by output_bytes.
        resource.setrlimit(resource.RLIMIT_FSIZE, (67_108_864, 67_108_864))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # V8/Chromium/JVM reserve large virtual address ranges: RSS enforcement needs
        # cgroup delegation. Their own heap limits apply; this gap is disclosed.

    return apply


def execute(argv: list[str], directory: Path, limits: Limits) -> tuple[int | None, bytes, ErrorClass]:
    if not Path(argv[0]).is_absolute():
        raise Blocked("EXPLICIT-EXECUTABLE-PATH-REQUIRED")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryFile(dir=directory) as output:
        process = subprocess.Popen(
            argv,
            cwd=directory,
            env=environment(directory),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            preexec_fn=bounds(limits),
        )
        try:
            deadline = time.monotonic() + limits.timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    return None, b"WALL-CLOCK-BUDGET", "timeout"
                rss, cpu = process_group_usage(process.pid)
                if rss > limits.memory_mb * 1048576 or cpu > limits.cpu_seconds:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    return None, b"PROCESS-GROUP-MEMORY-OR-CPU-BUDGET", "resource"
                if os.fstat(output.fileno()).st_size > limits.output_bytes:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    return None, b"STDOUT-SIZE-BUDGET", "resource"
                time.sleep(0.05)
            code = process.returncode
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        output.seek(0)
        data = output.read(limits.output_bytes + 1)
        if len(data) > limits.output_bytes:
            return code, b"", "invalid"
        return code, data, "none"


def process_group_usage(group: int) -> tuple[int, float]:
    """Linux sampled group budget; shared RSS is conservatively counted per process."""
    rss, cpu = 0, 0.0
    pages, ticks = os.sysconf("SC_PAGE_SIZE"), os.sysconf("SC_CLK_TCK")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                rss += max(0, int(fields[21])) * pages
                cpu += (int(fields[11]) + int(fields[12])) / ticks
        except (OSError, ValueError, IndexError):
            continue  # exited/unrelated process; owned children stay in our group
    return rss, cpu


def discover(adapter: str) -> Capability:
    if adapter == "offline":
        return Capability(adapter, True, PINS[adapter], sys.executable, "deterministic synthetic policy")
    if adapter == "p006":
        return Capability(adapter, False, "absent", None, "P-006 implementation absent; no target verified")
    if adapter == "inspect_ai":
        executable = PROJECT / ".tools/inspect/bin/python"
        if not executable.exists():
            return Capability(adapter, False, "absent", None, "isolated Inspect environment missing")
        command = [
            str(executable),
            "-c",
            "from importlib.metadata import version; print(version('inspect-ai'))",
        ]
        code, output, error = execute(command, PROJECT / ".runtime/discovery/inspect", Limits())
        version = output.decode(errors="replace").strip()
        return Capability(
            adapter,
            code == 0 and error == "none" and version == PINS[adapter],
            version,
            str(executable),
            "isolated pinned Python worker",
        )
    if adapter == "playwright":
        package = "playwright"
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return Capability(adapter, False, "absent", None, "optional package missing")
        return Capability(adapter, version == PINS[adapter], version, sys.executable, "pinned Python worker")
    executable = PROJECT / (
        ".tools/node/node_modules/.bin/promptfoo" if adapter == "promptfoo" else ".tools/ZAP_2.17.0/zap.sh"
    )
    if not executable.is_file():
        return Capability(adapter, False, "absent", None, "optional executable missing")
    discovery_root = PROJECT / ".runtime/discovery"
    discovery_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Concurrent doctor and run commands must not share tool databases/locks.
    with tempfile.TemporaryDirectory(prefix=adapter + "-", dir=discovery_root) as temporary:
        directory = Path(temporary)
        command = (
            [str(executable), "--version"]
            if adapter == "promptfoo"
            else [str(executable), "-Xmx768m", "-dir", str(directory / "zap-home"), "-version"]
        )
        code, output, error = execute(command, directory, Limits(timeout_seconds=30))
    version = PINS[adapter]
    available = code == 0 and error == "none" and version in output.decode(errors="replace")
    return Capability(
        adapter,
        available,
        version if available else "unverified",
        str(executable),
        "executed version discovery" if available else f"version discovery exit={code}, outcome={error}",
    )


def blocked(
    adapter: Adapter, reason: str, version: str = "absent", error: ErrorClass = "dependency"
) -> RunnerResult:
    return RunnerResult(
        adapter=adapter,
        executed=False,
        original_status=reason,
        exit_code=None,
        error_class=error,
        tool_version=version,
    )


def offline(test: TestCase, fixtures: dict) -> RunnerResult:
    if test.fixture_ref not in fixtures["cases"]:
        return blocked("offline", "FIXTURE-MISSING", PINS["offline"], "unsupported")
    samples = [
        respond(fixtures["cases"][test.fixture_ref], fixtures["policy"], n) for n in range(test.repetitions)
    ]
    return RunnerResult(
        adapter="offline",
        executed=True,
        original_status="COMPLETE",
        exit_code=0,
        observed=samples[0],
        samples=samples,
        tool_version=PINS["offline"],
        metadata={
            "model": "p007-policy-simulator-v1",
            "seed": 7,
            "temperature": 0,
            "sample_count": len(samples),
            "minimum_pass_rate": test.minimum_pass_rate,
            "fixture_version": fixtures["fixture_version"],
            "empirical_only": True,
        },
    )


def bounded_result(path: Path, limits: Limits):
    import json

    return json.loads(read_bytes(path, limits.output_bytes))
