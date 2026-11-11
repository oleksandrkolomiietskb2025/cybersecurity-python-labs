"""CLI: перегляд запису CVE в NVD за правилом варіанта."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def _cve_id(value: str) -> str:
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(f"некоректний ідентифікатор CVE: {value!r}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="labs.lab04.main", description=__doc__)
    parser.add_argument("--cve", required=True, type=_cve_id, help="ідентифікатор CVE")
    parser.add_argument("--input", help="шлях до локальної відповіді NVD (без мережі)")
    return parser


def load_response(path: str | Path) -> Any:
    """Читає UTF-8 JSON-файл (винятки OSError/ValueError обробляє main)."""
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def main(argv: list[str] | None = None) -> int:
    """Повертає код завершення: 0 — звіт сформовано, 1 — помилка даних, 2 — аргументи."""
    variant = VARIANT_NUMBER
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not 1 <= variant <= 15
    ):
        print(
            "Помилка: номер варіанта має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    args = build_parser().parse_args(argv)

    try:
        if args.input:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)
    except api_client.FetchError as exc:
        print(f"Помилка отримання даних: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print(f"Помилка: не вдалося прочитати файл {args.input}.", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print("Помилка: файл не є коректним UTF-8.", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("Помилка: файл не містить коректного JSON.", file=sys.stderr)
        return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, variant)
    except ValueError as exc:
        print(f"Помилка перевірки даних: {exc}.", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
