"""Параметризовані SQL-запити. Модуль не залежить від FastAPI."""

import sqlite3
from contextlib import closing
from typing import Any

from .database import get_connection

_RECORD_SELECT = """
SELECT r.id, r.code, r.title, r.category_id,
       c.name AS category_name, r.value, r.status
FROM records AS r
JOIN categories AS c ON c.id = r.category_id
"""


class NotFoundError(Exception):
    """Запис або категорію не знайдено."""


class ConflictError(Exception):
    """Порушення унікальності або цілісності зв'язків."""


def _is_unique_error(exc: sqlite3.IntegrityError) -> bool:
    return "UNIQUE constraint failed" in str(exc)


def _fetch_record(
    connection: sqlite3.Connection, record_id: int
) -> dict[str, Any] | None:
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        _RECORD_SELECT + " WHERE r.id = ?", (record_id,)
    ).fetchone()
    return dict(row) if row else None


def _ensure_category(connection: sqlite3.Connection, category_id: int) -> None:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("Категорію не знайдено")


def _insert_record(connection: sqlite3.Connection, data: dict[str, Any]) -> int:
    cursor = connection.execute(
        "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
        (
            data["code"],
            data["title"],
            data["category_id"],
            data["value"],
            data["status"],
        ),
    )
    return int(cursor.lastrowid)


# ---------- Категорії ----------


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
        except sqlite3.IntegrityError as exc:
            if _is_unique_error(exc):
                raise ConflictError("Категорія з такою назвою вже існує") from exc
            raise
        return {"id": cursor.lastrowid, "name": name}


def list_categories() -> list[dict[str, Any]]:
    """Отримати категорії за зростанням id."""
    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                _ensure_category(connection, category_id)
                used = connection.execute(
                    "SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)
                ).fetchone()[0]
                if used:
                    raise ConflictError("Категорія містить записи")
                connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Категорія містить записи") from exc


# ---------- Записи ----------


def create_record(data: dict[str, Any]) -> dict[str, Any]:
    """Додати запис і повернути його разом з category_name."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                _ensure_category(connection, data["category_id"])
                record_id = _insert_record(connection, data)
                record = _fetch_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            if _is_unique_error(exc):
                raise ConflictError("Запис з таким code вже існує") from exc
            raise
        return record  # type: ignore[return-value]


def get_record(record_id: int) -> dict[str, Any]:
    """Отримати запис за id."""
    with closing(get_connection()) as connection:
        record = _fetch_record(connection, record_id)
    if record is None:
        raise NotFoundError("Запис не знайдено")
    return record


def list_records(
    *,
    category_id: int | None,
    status: str | None,
    min_value: float | None,
    q: str | None,
    limit: int,
    offset: int,
) -> list[dict[str, Any]]:
    """Список записів з фільтрами (AND) і пагінацією, сортування за id."""
    conditions: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = _RECORD_SELECT
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)  # лише фіксовані фрагменти
    sql += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]


def replace_record(record_id: int, data: dict[str, Any]) -> dict[str, Any]:
    """Повністю замінити змінювані поля запису (id незмінний)."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                if _fetch_record(connection, record_id) is None:
                    raise NotFoundError("Запис не знайдено")
                _ensure_category(connection, data["category_id"])
                connection.execute(
                    "UPDATE records SET code = ?, title = ?, category_id = ?, "
                    "value = ?, status = ? WHERE id = ?",
                    (
                        data["code"],
                        data["title"],
                        data["category_id"],
                        data["value"],
                        data["status"],
                        record_id,
                    ),
                )
                record = _fetch_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            if _is_unique_error(exc):
                raise ConflictError("Запис з таким code вже існує") from exc
            raise
        return record  # type: ignore[return-value]


def delete_record(record_id: int) -> None:
    """Видалити запис."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def create_records_bulk(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Атомарно додати пакет записів в одній транзакції."""
    codes = [item["code"] for item in items]
    if len(set(codes)) != len(codes):
        raise ConflictError("Пакет містить дублікати code")

    with closing(get_connection()) as connection:
        try:
            with connection:  # один commit для всього пакета
                for category_id in {item["category_id"] for item in items}:
                    _ensure_category(connection, category_id)
                ids = [_insert_record(connection, item) for item in items]
                records = [_fetch_record(connection, record_id) for record_id in ids]
        except sqlite3.IntegrityError as exc:
            if _is_unique_error(exc):
                raise ConflictError("Один із code вже існує в базі") from exc
            raise
        return records  # type: ignore[return-value]
