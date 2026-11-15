from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import pytest
from p002.adapters.transport import validate_target, Client, ENDPOINTS


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://localhost:8781",
        "http://127.0.0.1:80",
        "http://127.0.0.1:8781/",
        "http://user:pass@127.0.0.1:8781",
        "http://127.0.0.1:8781?x=1",
        "http://[::1]:8781",
        "file:///tmp/x",
        "http://127.0.0.1:8781#x",
    ],
)
def test_target_rejection(url):
    with pytest.raises(ValueError):
        validate_target("nextcloud", url, "lab")


def test_confirmation_required():
    with pytest.raises(ValueError):
        validate_target("nextcloud", ENDPOINTS["nextcloud"][0], None)


@pytest.mark.parametrize(
    "path", ["https://example.test", "//external", "/../x", "/%2e%2e/a", "/x\r\nX-Test:bad", "/x\\other"]
)
def test_request_path_rejection(path):
    c = Client("nextcloud", "lab")
    with pytest.raises(ValueError):
        c.request("GET", path)


def test_no_redirect_and_no_ambient_proxy(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://example.test/forbidden")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Test-specific fixed allowlist, no arbitrary user endpoint option exists.
    endpoint = "http://127.0.0.1:" + str(server.server_port)
    monkeypatch.setitem(ENDPOINTS, "test", (endpoint, "test", 80))
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    try:
        with pytest.raises(ValueError, match="redirect refused"):
            Client("test", "lab").request("GET", "/")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_journal_conflicts_and_private_secrets(tmp_path, monkeypatch):
    import p002.adapters as a

    monkeypatch.setattr(a, "RUNTIME", tmp_path)
    j = a.Journal("nextcloud", "a" * 64)
    j.put("p002:a", "file", "local")
    assert a.Journal("nextcloud", "a" * 64).get("p002:a")["external_id"] == "local"
    assert j.path.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="conflict"):
        a.Journal("nextcloud", "b" * 64)
    j.path.unlink()
    j.path.symlink_to(tmp_path / "user-file")
    with pytest.raises(ValueError, match="symlink"):
        a.Journal("nextcloud", "a" * 64)


def test_missing_adapter_is_blocked():
    # A deliberately nonexistent fixed owned container must never become a PASS.
    from p002.adapters.transport import owned_container

    assert not owned_container("p002-test-nonexistent")
