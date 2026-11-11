# ЛР №4 — Web API NVD і тестування на pytest (варіант 12)

Утиліта шукає CVE в NVD CVE API 2.0 (або читає локальний JSON) і формує JSON-звіт.

**Правило варіанта 12:** `baseScore >= 6.0` і `cvssData.confidentialityImpact == "LOW"`
в одній і тій самій вибраній оцінці CVSS v3.1 → `review`, інакше `other`.

## Встановлення

```bash
python -m venv .venv
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
pip install requests pytest ruff
pip freeze > requirements.txt  # або додайте версії вручну, зберігши попередні пакети
```

## Запуск

Локально (без мережі):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Один ручний запит до NVD (необов'язковий ключ — змінна середовища `NVD_API_KEY`):

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Коди завершення: `0` — звіт сформовано (зокрема `not_found`, `insufficient_data`),
`1` — помилка отримання/читання/перевірки даних, `2` — неправильні аргументи чи номер варіанта.

## Формат звіту

Ключі: `cve_id`, `variant`, `description`, `vuln_status`, `cvss_version`, `score`,
`score_source`, `vector`, `rule {threshold, field, expected}`, `observed`, `decision`
(`not_found` / `rejected` / `insufficient_data` / `review` / `other`). Відсутні значення — `null`.

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```
