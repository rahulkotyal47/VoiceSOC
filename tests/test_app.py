"""Phase 1 tests: health route and dashboard page."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app


def test_health_route():
    client = app.test_client()
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json() == {"status": "ok"}


def test_dashboard_has_command_box_and_banner():
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert 'id="command"' in html
    assert 'id="run"' in html
    assert "Scan only machines you own." in html
