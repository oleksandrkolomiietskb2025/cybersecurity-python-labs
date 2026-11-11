import json

import pytest

from labs.lab04 import api_client
from labs.lab04 import main as cli
from labs.lab04.tests.conftest import SAMPLE_PATH

CVE = "CVE-2099-10001"
INPUT = ["--cve", CVE, "--input", str(SAMPLE_PATH)]


@pytest.fixture
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("мережевий запит у локальному режимі")

    monkeypatch.setattr(cli.api_client, "fetch_response", forbidden)


def test_local_run_prints_single_json(no_network, capsys):
    assert cli.main(INPUT) == 0
    out = capsys.readouterr()
    report = json.loads(out.out)
    assert out.err == ""
    assert report["cve_id"] == CVE
    assert report["variant"] == 12
    assert report["decision"] == "other"
    assert report["observed"] == "HIGH"


def test_local_run_other_variant(no_network, capsys, monkeypatch):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", 1)
    assert cli.main(INPUT) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["variant"] == 1
    assert report["decision"] == "review"


def test_local_not_found_exit_zero(no_network, capsys, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")
    assert cli.main(["--cve", CVE, "--input", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_non_ascii_not_escaped(no_network, capsys, tmp_path, sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Опис ✓"
    path = tmp_path / "ua.json"
    path.write_text(json.dumps(sample_payload, ensure_ascii=False), encoding="utf-8")
    assert cli.main(["--cve", CVE, "--input", str(path)]) == 0
    assert "Опис ✓" in capsys.readouterr().out


def test_invalid_json_file(no_network, capsys, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert cli.main(["--cve", CVE, "--input", str(path)]) == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err.strip()
    assert "Traceback" not in out.err


def test_missing_file(no_network, capsys, tmp_path):
    assert cli.main(["--cve", CVE, "--input", str(tmp_path / "nope.json")]) == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err.strip()


def test_non_utf8_file(no_network, capsys, tmp_path):
    path = tmp_path / "latin.json"
    path.write_bytes(b"\xff\xfe\x00")
    assert cli.main(["--cve", CVE, "--input", str(path)]) == 1
    assert capsys.readouterr().err.strip()


def test_data_validation_error(no_network, capsys):
    assert cli.main(["--cve", "CVE-2099-99999", "--input", str(SAMPLE_PATH)]) == 1
    out = capsys.readouterr()
    assert out.out == "" and "cve.id" in out.err


def test_network_mode_uses_client(monkeypatch, capsys, sample_payload):
    calls = []

    def fake_fetch(cve_id):
        calls.append(cve_id)
        return sample_payload

    monkeypatch.setattr(cli.api_client, "fetch_response", fake_fetch)
    assert cli.main(["--cve", CVE]) == 0
    assert calls == [CVE]
    assert json.loads(capsys.readouterr().out)["decision"] == "other"


def test_network_error_exit_one(monkeypatch, capsys):
    def failing(cve_id):
        raise api_client.FetchError("NVD API повернув HTTP-помилку (статус 404).")

    monkeypatch.setattr(cli.api_client, "fetch_response", failing)
    assert cli.main(["--cve", CVE]) == 1
    out = capsys.readouterr()
    assert out.out == "" and "404" in out.err


@pytest.mark.parametrize(
    "cve",
    [
        "cve-2099-10001",
        "CVE-99-10001",
        "CVE-2099-123",
        "CVE-2099-10001 ",
        "CVE-2099-10001\n",
        "CVE-٢٠٩٩-10001",
        "",
    ],
)
def test_invalid_cve_exit_two(no_network, capsys, cve):
    with pytest.raises(SystemExit) as info:
        cli.main(["--cve", cve])
    assert info.value.code == 2
    assert capsys.readouterr().out == ""


def test_missing_cve_exit_two(no_network):
    with pytest.raises(SystemExit) as info:
        cli.main([])
    assert info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "12", 12.0, None])
def test_invalid_variant_exit_two(no_network, capsys, monkeypatch, variant):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", variant)
    assert cli.main(INPUT) == 2
    out = capsys.readouterr()
    assert out.out == "" and out.err.strip()
