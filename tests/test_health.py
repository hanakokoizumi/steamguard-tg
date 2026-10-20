import os
import time

from healthcheck import healthy


def test_health_requires_a_recent_successful_probe(tmp_path, monkeypatch):
    path = tmp_path / "heartbeat"
    monkeypatch.setenv("HEALTHCHECK_PATH", str(path))
    assert not healthy()
    path.touch()
    assert healthy()
    old = time.time() - 121
    os.utime(path, (old, old))
    assert not healthy()
