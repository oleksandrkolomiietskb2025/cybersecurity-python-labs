"""Точка входу ЛР2: команди 'demo' (Завдання 1) та 'analyze' (Завдання 2).

Запуск:
    python -m labs.lab02.main demo
    python -m labs.lab02.main analyze --mail-log data/data_v12/mail_headers.log \
        --suspicious-keywords data/data_v12/suspicious_keywords.txt \
        --out-csv data/data_v12/phishing_report.csv
"""

import argparse

from labs.lab02 import task1, task2


def build_arg_parser() -> argparse.ArgumentParser:
    """Створює головний парсер із підкомандами demo та analyze."""
    parser = argparse.ArgumentParser(
        description="ЛР2: ООП-модель та аналізатор фішингу."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "demo", help="Демонстрація класів User/Admin/Session/UserAccount"
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="Аналіз заголовків пошти на ознаки фішингу (Завдання 2)"
    )
    analyze_parser.add_argument(
        "--mail-log", required=True, help="Шлях до файлу логу пошти"
    )
    analyze_parser.add_argument(
        "--suspicious-keywords", required=True, help="Шлях до словника стоп-слів"
    )
    analyze_parser.add_argument("--out-csv", help="Шлях для збереження CSV-звіту")
    analyze_parser.add_argument(
        "--debug", action="store_true", help="DEBUG-рівень логування"
    )

    return parser


def main() -> None:
    """Розбирає команду та викликає відповідний обробник."""
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "demo":
        task1.demo()
    elif args.command == "analyze":
        task2.run_analysis(args)


if __name__ == "__main__":
    main()
