"""Клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = (3.05, 10)


class FetchError(Exception):
    """Помилка отримання даних від NVD API (повідомлення безпечне для виведення)."""


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту; apiKey додається лише за непорожнього NVD_API_KEY."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD і повертає декодований JSON.

    Піднімає FetchError з безпечним повідомленням (без ключа, заголовків і тіла відповіді).
    """
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout:
        raise FetchError("Перевищено час очікування відповіді NVD API.") from None
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        raise FetchError(f"NVD API повернув HTTP-помилку (статус {status}).") from None
    except requests.exceptions.ConnectionError:
        raise FetchError("Не вдалося встановити з'єднання з NVD API.") from None
    except requests.exceptions.RequestException:
        raise FetchError("Помилка виконання запиту до NVD API.") from None

    if response.status_code != 200:
        raise FetchError(
            f"Неочікуваний статус відповіді NVD API: {response.status_code}."
        )

    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        raise FetchError("Відповідь NVD API не є коректним JSON.") from None
