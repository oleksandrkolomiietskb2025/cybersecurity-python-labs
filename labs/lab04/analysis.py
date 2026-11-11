"""Перевірка відповіді NVD і правило аналізу за варіантом."""

import math
from copy import deepcopy
from typing import Any

SUPPORTED_VERSION = "3.1"


class DataError(ValueError):
    """Порушення контракту даних (підклас ValueError)."""


ALLOWED_VALUES: dict[str, tuple[str, ...]] = {
    "attackVector": ("NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"),
    "attackComplexity": ("LOW", "HIGH"),
    "privilegesRequired": ("NONE", "LOW", "HIGH"),
    "userInteraction": ("NONE", "REQUIRED"),
    "scope": ("UNCHANGED", "CHANGED"),
    "confidentialityImpact": ("NONE", "LOW", "HIGH"),
    "integrityImpact": ("NONE", "LOW", "HIGH"),
    "availabilityImpact": ("NONE", "LOW", "HIGH"),
}

# варіант: (поріг, поле, очікуване значення)
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


def _optional_str(container: dict, key: str, where: str) -> str | None:
    """Повертає None, якщо ключа немає; інакше вимагає непорожній рядок."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or value == "":
        raise DataError(f"{where}: поле {key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict) -> str | None:
    """Перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise DataError("descriptions має бути списком")
    result = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise DataError("елемент descriptions має бути об'єктом")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise DataError("lang і value в descriptions мають бути рядками")
        if result is None and lang == "en" and value != "":
            result = value
    return result


def _select_entry(cve: dict) -> dict | None:
    """Вибирає оцінку v3.1: перша Primary, інакше перша; None, якщо оцінок немає."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise DataError("metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    entries = metrics["cvssMetricV31"]
    if not isinstance(entries, list):
        raise DataError("cvssMetricV31 має бути списком")
    if not entries:
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise DataError("елементи cvssMetricV31 мають бути об'єктами")
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0]


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None (запис не знайдено).

    Формат запису (словник):
        cve_id: запитаний ідентифікатор;
        status: vulnStatus або None;
        description: англійський опис або None;
        score, source, version, vector: дані вибраної оцінки v3.1 або None;
        cvss_data: глибока копія cvssData вибраної оцінки або None
            (None також для Rejected, відсутнього статусу й відсутніх оцінок).

    Порушення контракту даних -> ValueError. payload не змінюється.
    """
    if not isinstance(payload, dict):
        raise DataError("відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise DataError("vulnerabilities має бути списком")
    if len(vulnerabilities) == 0:
        return None
    if len(vulnerabilities) > 1:
        raise DataError("очікувано не більше одного елемента vulnerabilities")
    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise DataError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise DataError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_str(cve, "vulnStatus", "cve")
    record: dict[str, Any] = {
        "cve_id": cve_id,
        "status": status,
        "description": _english_description(cve),
        "score": None,
        "source": None,
        "version": None,
        "vector": None,
        "cvss_data": None,
    }
    if status is None or status == "Rejected":
        return record

    entry = _select_entry(cve)
    if entry is None:
        return record
    cvss_data = entry.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise DataError("cvssData має бути об'єктом")
    score = cvss_data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise DataError("baseScore має бути скінченним числом від 0 до 10")

    version = _optional_str(cvss_data, "version", "cvssData")
    if version is not None and version != SUPPORTED_VERSION:
        raise DataError(f"підтримується лише CVSS {SUPPORTED_VERSION}")
    record.update(
        score=score,
        source=_optional_str(entry, "source", "оцінка"),
        version=version,
        vector=_optional_str(cvss_data, "vectorString", "cvssData"),
        cvss_data=deepcopy(cvss_data),
    )
    return record


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта (score >= T і field == expected) і формує звіт."""
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise DataError("номер варіанта має бути цілим числом")
    if variant not in VARIANT_RULES:
        raise DataError("номер варіанта має бути від 1 до 15")
    threshold, field, expected = VARIANT_RULES[variant]

    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["status"]
    if record["status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    report["decision"] = "insufficient_data"
    if record["status"] is None or record["cvss_data"] is None:
        return report

    report["cvss_version"] = record["version"]
    report["score"] = record["score"]
    report["score_source"] = record["source"]
    report["vector"] = record["vector"]
    cvss_data = record["cvss_data"]
    if field not in cvss_data:
        return report

    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise DataError(f"недопустиме значення поля {field}")
    report["observed"] = observed
    matches = record["score"] >= threshold and observed == expected
    report["decision"] = "review" if matches else "other"
    return report
