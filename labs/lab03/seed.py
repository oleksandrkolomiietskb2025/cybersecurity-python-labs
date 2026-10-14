"""Початкове заповнення бази з data/seed.json."""

import json
import sqlite3
import sys
from contextlib import closing
from typing import Any

from pydantic import ValidationError

from .database import BASE_DIR, get_connection, initialize_database
from .schemas import CategoryCreate, RecordCreate

SEED_PATH = BASE_DIR / "data" / "seed.json"
EXPECTED_CATEGORIES = 3
EXPECTED_RECORDS = 8


def load_seed() -> dict[str, Any]:
    """Прочитати й перевірити JSON із початковими даними."""
    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    categories, records = data["categories"], data["records"]
    if len(categories) != EXPECTED_CATEGORIES or len(records) != EXPECTED_RECORDS:
        raise ValueError("Очікується 3 категорії та 8 записів")
    ids = [item["id"] for item in categories]
    if len(set(ids)) != len(ids) or any(not isinstance(i, int) or i <= 0 for i in ids):
        raise ValueError("Некоректні або повторювані id категорій")
    for item in categories:
        CategoryCreate.model_validate({"name": item["name"]})
    for item in records:
        RecordCreate.model_validate(item)
        if item["category_id"] not in ids:
            raise ValueError(f"Невідома категорія у записі {item['code']}")
    return data


def seed_database() -> str:
    """Заповнити порожню базу в одній транзакції."""
    data = load_seed()
    initialize_database()
    with closing(get_connection()) as connection:
        non_empty = connection.execute(
            "SELECT (SELECT COUNT(*) FROM categories) + (SELECT COUNT(*) FROM records)"
        ).fetchone()[0]
        if non_empty:
            return "База не порожня: початкове заповнення пропущено."
        with connection:
            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                [(c["id"], c["name"]) for c in data["categories"]],
            )
            connection.executemany(
                "INSERT INTO records (code, title, category_id, value, status) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (r["code"], r["title"], r["category_id"], r["value"], r["status"])
                    for r in data["records"]
                ],
            )
    return "Додано 3 категорії та 8 записів."


def main() -> int:
    """Точка входу."""
    try:
        print(seed_database())
    except (OSError, KeyError, ValueError, ValidationError, sqlite3.Error) as exc:
        print(f"Помилка початкового заповнення, зміни скасовано: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
