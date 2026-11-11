import copy

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE = "CVE-2099-10001"
VARIANT = 12  # score >= 6.0 і confidentialityImpact == LOW


def entry(payload, index=0):
    return payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][index]


def decide(payload, variant=VARIANT):
    return build_report(extract_record(payload, CVE), CVE, variant)


@pytest.mark.parametrize(
    "score, impact, expected",
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (6.1, "LOW", "review"),
        (10, "LOW", "review"),
        (9.8, "HIGH", "other"),
        (6.0, "NONE", "other"),
        (0, "LOW", "other"),
    ],
)
def test_threshold_and_field(sample_payload, score, impact, expected):
    data = entry(sample_payload)["cvssData"]
    data["baseScore"] = score
    data["confidentialityImpact"] = impact
    report = decide(sample_payload)
    assert report["decision"] == expected
    assert report["observed"] == impact


def test_sample_gives_other_for_variant_12(sample_payload):
    report = decide(sample_payload)
    assert report == {
        "cve_id": CVE,
        "variant": 12,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
        "observed": "HIGH",
        "decision": "other",
    }


@pytest.mark.parametrize(
    "variant, expected", [(1, "review"), (7, "review"), (8, "other")]
)
def test_sample_other_variants(sample_payload, variant, expected):
    assert decide(sample_payload, variant)["decision"] == expected


def test_not_found():
    report = build_report(extract_record({"vulnerabilities": []}, CVE), CVE, VARIANT)
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE and report["variant"] == VARIANT
    assert report["rule"]["field"] == "confidentialityImpact"
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score(sample_payload):
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cve["vulnStatus"] = "Rejected"
    entry(sample_payload)["cvssData"]["confidentialityImpact"] = "LOW"
    report = decide(sample_payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None and report["observed"] is None


def test_missing_status_is_insufficient(sample_payload):
    del sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"]
    report = decide(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] is not None
    assert report["score"] is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda cve: cve.pop("metrics"),
        lambda cve: cve["metrics"].pop("cvssMetricV31"),
        lambda cve: cve["metrics"].update(cvssMetricV31=[]),
        lambda cve: (
            cve["metrics"].update(cvssMetricV2=[])
            or cve["metrics"].pop("cvssMetricV31")
        ),
    ],
)
def test_missing_score_is_insufficient(sample_payload, mutate):
    mutate(sample_payload["vulnerabilities"][0]["cve"])
    report = decide(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None and report["observed"] is None


def test_missing_variant_field_is_insufficient(sample_payload):
    del entry(sample_payload)["cvssData"]["confidentialityImpact"]
    report = decide(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("value", [None, "MEDIUM", "low", 5, ["LOW"]])
def test_bad_variant_field_raises(sample_payload, value):
    entry(sample_payload)["cvssData"]["confidentialityImpact"] = value
    with pytest.raises(ValueError):
        decide(sample_payload)


def test_primary_beats_earlier_secondary(sample_payload):
    primary = entry(sample_payload)
    secondary = copy.deepcopy(primary)
    secondary["type"] = "Secondary"
    secondary["source"] = "other@example.invalid"
    secondary["cvssData"]["baseScore"] = 3.0
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary,
        primary,
    ]
    report = decide(sample_payload)
    assert report["score"] == 9.8
    assert report["score_source"] == "nvd@nist.gov"


def test_first_entry_when_no_primary(sample_payload):
    first = entry(sample_payload)
    first["type"] = "Secondary"
    first["source"] = "first@example.invalid"
    second = copy.deepcopy(first)
    second["source"] = "second@example.invalid"
    second["cvssData"]["baseScore"] = 1.0
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        first,
        second,
    ]
    report = decide(sample_payload)
    assert report["score_source"] == "first@example.invalid"
    assert report["score"] == 9.8


def test_description_first_non_empty_english(sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "es", "value": "hola"},
        {"lang": "en", "value": ""},
        {"lang": "en", "value": "second"},
        {"lang": "en", "value": "third"},
    ]
    assert decide(sample_payload)["description"] == "second"


def test_no_english_description_is_none(sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "es", "value": "hola"}
    ]
    assert decide(sample_payload)["description"] is None


def test_optional_fields_absent_become_none(sample_payload):
    entry_ = entry(sample_payload)
    del entry_["source"]
    del entry_["cvssData"]["version"]
    del entry_["cvssData"]["vectorString"]
    report = decide(sample_payload)
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "other"


def bad_payloads():
    def make(fn):
        def build(p):
            fn(p)
            return p

        return build

    cve = lambda p: p["vulnerabilities"][0]["cve"]
    data = lambda p: p["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    return {
        "payload_list": lambda p: [],
        "no_vulnerabilities": lambda p: {},
        "vulns_not_list": lambda p: {"vulnerabilities": {}},
        "two_items": lambda p: {"vulnerabilities": p["vulnerabilities"] * 2},
        "item_not_dict": lambda p: {"vulnerabilities": ["x"]},
        "no_cve": lambda p: {"vulnerabilities": [{}]},
        "wrong_id": make(lambda p: cve(p).update(id="CVE-2099-99999")),
        "status_empty": make(lambda p: cve(p).update(vulnStatus="")),
        "status_null": make(lambda p: cve(p).update(vulnStatus=None)),
        "descriptions_not_list": make(lambda p: cve(p).update(descriptions="x")),
        "description_item_bad": make(
            lambda p: cve(p).update(descriptions=[{"lang": "en"}])
        ),
        "metrics_null": make(lambda p: cve(p).update(metrics=None)),
        "metrics_list": make(lambda p: cve(p).update(metrics=[])),
        "v31_null": make(lambda p: cve(p)["metrics"].update(cvssMetricV31=None)),
        "v31_dict": make(lambda p: cve(p)["metrics"].update(cvssMetricV31={})),
        "entry_not_dict": make(lambda p: cve(p)["metrics"].update(cvssMetricV31=["x"])),
        "cvssdata_missing": make(
            lambda p: cve(p)["metrics"]["cvssMetricV31"][0].pop("cvssData")
        ),
        "score_missing": make(lambda p: data(p).pop("baseScore")),
        "score_string": make(lambda p: data(p).update(baseScore="9.8")),
        "score_true": make(lambda p: data(p).update(baseScore=True)),
        "score_null": make(lambda p: data(p).update(baseScore=None)),
        "score_nan": make(lambda p: data(p).update(baseScore=float("nan"))),
        "score_inf": make(lambda p: data(p).update(baseScore=float("inf"))),
        "score_high": make(lambda p: data(p).update(baseScore=10.1)),
        "score_negative": make(lambda p: data(p).update(baseScore=-0.1)),
        "version_30": make(lambda p: data(p).update(version="3.0")),
        "version_null": make(lambda p: data(p).update(version=None)),
        "vector_empty": make(lambda p: data(p).update(vectorString="")),
        "source_number": make(
            lambda p: cve(p)["metrics"]["cvssMetricV31"][0].update(source=1)
        ),
    }


@pytest.mark.parametrize("name", list(bad_payloads()))
def test_invalid_payload_raises(sample_payload, name):
    payload = bad_payloads()[name](sample_payload)
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


def test_functions_do_not_mutate_payload(sample_payload):
    before = copy.deepcopy(sample_payload)
    decide(sample_payload)
    assert sample_payload == before


@pytest.mark.parametrize("variant", [0, 16, -1, True, 12.0, "12", None])
def test_invalid_variant_raises(variant):
    with pytest.raises(ValueError):
        build_report(None, CVE, variant)
