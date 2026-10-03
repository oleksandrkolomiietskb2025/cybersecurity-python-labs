"""Завдання 2 (Варіант 12): Аналізатор заголовків пошти та фішингових індикаторів.

Розбирає дамп заголовків листів, порівнює домени From/Return-Path/Reply-To,
шукає стоп-слова в темі листа та рахує кількість проміжних вузлів Received.
Формує CSV-звіт з оцінкою підозрілості (risk score) кожного листа.

Запуск окремо:
    python -m labs.lab02.task2 --mail-log data/data_v12/mail_headers.log \
        --suspicious-keywords data/data_v12/suspicious_keywords.txt \
        --out-csv data/data_v12/phishing_report.csv
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger("phishing_audit")

# Високий ризик для листа з кількістю ретрансляцій (Received) понад це число.
ABNORMAL_HOP_COUNT = 4

FROM_PATTERN = re.compile(r"^From:\s*(?P<display>.*)$", re.IGNORECASE)
RETURN_PATH_PATTERN = re.compile(r"^Return-Path:\s*(?P<value>.*)$", re.IGNORECASE)
REPLY_TO_PATTERN = re.compile(r"^Reply-To:\s*(?P<value>.*)$", re.IGNORECASE)
SUBJECT_PATTERN = re.compile(r"^Subject:\s*(?P<value>.*)$", re.IGNORECASE)
RECEIVED_PATTERN = re.compile(r"^Received:", re.IGNORECASE)
MESSAGE_ID_PATTERN = re.compile(r"^Message-ID:\s*(?P<value>.*)$", re.IGNORECASE)
EMAIL_ADDRESS_PATTERN = re.compile(r"[\w.+-]+@([\w.-]+)")


@dataclass
class EmailRecord:
    """Структурований результат аналізу одного листа."""

    message_id: str
    subject: str
    from_domain: str
    return_path_domain: str
    reply_to_domain: str
    sender_mismatch: bool
    reply_to_mismatch: bool
    hop_count: int
    stopwords_found: list = field(default_factory=list)
    risk_score: int = 0

    @property
    def risk_label(self) -> str:
        """Текстова категорія ризику за числовим risk_score."""
        if self.risk_score >= 70:
            return "CRITICAL PHISHING SUSPECT"
        if self.risk_score >= 40:
            return "SUSPICIOUS"
        return "LOW RISK"


def extract_domain(raw_value: str) -> str:
    """Дістає домен email-адреси з рядка на кшталт 'Ім'я <user@domain.com>'."""
    match = EMAIL_ADDRESS_PATTERN.search(raw_value)
    return match.group(1).lower() if match else ""


def load_suspicious_keywords(path: Path) -> list:
    """Завантажує словник стоп-слів (по одному на рядок)."""
    try:
        with open(path, encoding="utf-8") as keywords_file:
            return [line.strip().lower() for line in keywords_file if line.strip()]
    except FileNotFoundError:
        logger.error("Файл стоп-слів не знайдено: %s", path)
        return []
    except OSError as error:
        logger.error("Помилка читання файлу стоп-слів %s: %s", path, error)
        return []


def parse_mail_log(path: Path) -> list:
    """Розбирає файл-дамп заголовків на окремі блоки листів."""
    try:
        with open(path, encoding="utf-8") as log_file:
            raw_text = log_file.read()
    except FileNotFoundError:
        logger.error("Файл логу пошти не знайдено: %s", path)
        return []
    except OSError as error:
        logger.error("Помилка читання файлу логу %s: %s", path, error)
        return []

    blocks = [
        block.strip() for block in raw_text.split("--- MESSAGE ---") if block.strip()
    ]
    logger.debug("Знайдено %d блоків повідомлень", len(blocks))
    return blocks


def analyze_message(block: str, suspicious_keywords: list) -> EmailRecord:
    """Аналізує один блок заголовків листа і повертає EmailRecord з оцінкою ризику."""
    message_id = ""
    from_domain = ""
    return_path_domain = ""
    reply_to_domain = ""
    subject = ""
    hop_count = 0

    for line in block.splitlines():
        if match := MESSAGE_ID_PATTERN.match(line):
            message_id = match.group("value").strip()
        elif match := FROM_PATTERN.match(line):
            from_domain = extract_domain(match.group("display"))
        elif match := RETURN_PATH_PATTERN.match(line):
            return_path_domain = extract_domain(match.group("value"))
        elif match := REPLY_TO_PATTERN.match(line):
            reply_to_domain = extract_domain(match.group("value"))
        elif match := SUBJECT_PATTERN.match(line):
            subject = match.group("value").strip()
        elif RECEIVED_PATTERN.match(line):
            hop_count += 1

    sender_mismatch = bool(return_path_domain) and from_domain != return_path_domain
    reply_to_mismatch = bool(reply_to_domain) and from_domain != reply_to_domain

    subject_lower = subject.lower()
    stopwords_found = [word for word in suspicious_keywords if word in subject_lower]

    risk_score = 0
    if sender_mismatch:
        risk_score += 40
    if reply_to_mismatch:
        risk_score += 20
    risk_score += min(len(stopwords_found) * 10, 20)
    if hop_count > ABNORMAL_HOP_COUNT:
        risk_score += 20
    risk_score = min(risk_score, 100)

    return EmailRecord(
        message_id=message_id,
        subject=subject,
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        sender_mismatch=sender_mismatch,
        reply_to_mismatch=reply_to_mismatch,
        hop_count=hop_count,
        stopwords_found=stopwords_found,
        risk_score=risk_score,
    )


def print_report(records: list) -> None:
    """Друкує звіт аудиту фішингу у консоль у форматі, подібному до методички."""
    print("=== Phishing & Spoofing Audit Results ===")
    for record in records:
        if record.risk_score < 40:
            continue
        print(
            f'[{record.risk_label}] {record.message_id} | Subject: "{record.subject}"'
        )
        if record.sender_mismatch:
            print(
                f"  - Sender Mismatch : From domain '{record.from_domain}' "
                f"vs Return-Path domain '{record.return_path_domain}'"
            )
        if record.reply_to_mismatch:
            print(f"  - Reply-To Mismatch: domain '{record.reply_to_domain}'")
        if record.stopwords_found:
            print(f"  - Stopwords Found : {record.stopwords_found}")
        print(f"  - Hop Count : {record.hop_count} intermediate relays")
        print(f"  - Risk Score : {record.risk_score}/100 ({record.risk_label})\n")


def save_csv_report(records: list, output_path: Path) -> None:
    """Зберігає детальний звіт у CSV-файл."""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(
                [
                    "message_id",
                    "subject",
                    "from_domain",
                    "return_path_domain",
                    "reply_to_domain",
                    "sender_mismatch",
                    "reply_to_mismatch",
                    "hop_count",
                    "stopwords_found",
                    "risk_score",
                    "risk_label",
                ]
            )
            for record in records:
                writer.writerow(
                    [
                        record.message_id,
                        record.subject,
                        record.from_domain,
                        record.return_path_domain,
                        record.reply_to_domain,
                        record.sender_mismatch,
                        record.reply_to_mismatch,
                        record.hop_count,
                        ";".join(record.stopwords_found),
                        record.risk_score,
                        record.risk_label,
                    ]
                )
        logger.info("Phishing audit summary exported to %s", output_path)
    except OSError as error:
        logger.error("Не вдалося записати CSV-звіт %s: %s", output_path, error)


def configure_logging(debug: bool) -> None:
    """Налаштовує рівень логування залежно від прапорця --debug."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def run_analysis(args: argparse.Namespace) -> None:
    """Запускає повний цикл аналізу заголовків пошти з переданими аргументами."""
    configure_logging(args.debug)

    print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}\n")

    mail_log_path = Path(args.mail_log)
    keywords_path = Path(args.suspicious_keywords)

    logger.info("Analyzing email headers dump from %s...", mail_log_path)
    suspicious_keywords = load_suspicious_keywords(keywords_path)
    blocks = parse_mail_log(mail_log_path)

    records = [analyze_message(block, suspicious_keywords) for block in blocks]
    logger.info("Total emails inspected: %d.", len(records))

    print_report(records)

    if args.out_csv:
        save_csv_report(records, Path(args.out_csv))


def build_arg_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка для утиліти."""
    parser = argparse.ArgumentParser(
        description="Аналізатор заголовків електронної пошти на ознаки фішингу."
    )
    parser.add_argument(
        "--mail-log", required=True, help="Шлях до файлу з дампом заголовків листів"
    )
    parser.add_argument(
        "--suspicious-keywords",
        required=True,
        help="Шлях до словника підозрілих слів (по одному на рядок)",
    )
    parser.add_argument("--out-csv", help="Шлях для збереження CSV-звіту")
    parser.add_argument(
        "--debug", action="store_true", help="Увімкнути DEBUG-рівень логування"
    )
    return parser


def main() -> None:
    """Точка входу при запуску task2.py окремим модулем."""
    parser = build_arg_parser()
    args = parser.parse_args()
    run_analysis(args)


if __name__ == "__main__":
    main()
