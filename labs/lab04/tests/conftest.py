import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload():
    """Нова копія синтетичної відповіді для кожного тесту."""
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
