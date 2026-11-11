from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE = "CVE-2099-10001"


def make_response(status=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.json.return_value = payload if payload is not None else {}
    return response


def patch_get(monkeypatch, **kwargs):
    fake_get = Mock(**kwargs)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload=payload)
    fake_get = patch_get(monkeypatch, return_value=response)
    assert api_client.fetch_response(CVE) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_headers_blank_key_ignored(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_key_stripped(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_key_sent_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    fake_get = patch_get(monkeypatch, return_value=make_response())
    api_client.fetch_response(CVE)
    args, kwargs = fake_get.call_args
    assert kwargs["headers"]["apiKey"] == "fake-key-123"
    assert args == (URL,)
    assert "fake-key-123" not in str(kwargs["params"])


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.ReadTimeout("secret"),
        requests.exceptions.ConnectTimeout("secret"),
        requests.exceptions.ConnectionError("secret"),
        requests.exceptions.RequestException("secret"),
    ],
)
def test_network_errors_become_fetch_error(monkeypatch, exc):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    patch_get(monkeypatch, side_effect=exc)
    with pytest.raises(api_client.FetchError) as info:
        api_client.fetch_response(CVE)
    assert "secret" not in str(info.value)
    assert "fake-key-123" not in str(info.value)


@pytest.mark.parametrize("status", [404, 500])
def test_http_error_message_has_status_only(monkeypatch, status):
    response = make_response(status=status)
    response.text = "SECRET BODY"
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "SECRET TEXT", response=response
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(api_client.FetchError) as info:
        api_client.fetch_response(CVE)
    assert str(status) in str(info.value)
    assert "SECRET" not in str(info.value)
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [201, 204, 302])
def test_unexpected_status(monkeypatch, status):
    response = make_response(status=status)
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(api_client.FetchError) as info:
        api_client.fetch_response(CVE)
    assert str(status) in str(info.value)
    response.json.assert_not_called()


def test_invalid_json(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(api_client.FetchError):
        api_client.fetch_response(CVE)


def test_import_has_no_side_effects():
    # імпорт модуля вже відбувся під забороною Session.request; ключ читається під час виклику
    assert api_client.build_headers()["Accept"] == "application/json"
