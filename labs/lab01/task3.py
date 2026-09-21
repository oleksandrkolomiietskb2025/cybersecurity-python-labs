"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування (Варіант 12).

Алгоритм хешування: MD5. Мінімальна довжина пароля: 8.
"""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 8
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)  # "00012" для варіанту 12

USERS_TO_REGISTER = (
    ("alice", "Str0ngP@ssword"),
    ("bob", "AnotherP@ss1"),
    ("carol", "SecureC@rol9"),
    ("dave", "D4ve!Secure"),
    ("eve", "Eve$trongPass1"),
    ("frank", "Fr@nk12345"),
    ("grace", "Gr@ce#2024"),
    ("heidi", "Heidi!Pass99"),
    ("ivan", "Iv@nSecure7"),
    ("judy", "Judy#Pass2024"),
)


class ValidationError(Exception):
    """Власний виняток для помилок валідації вхідних даних."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує шістнадцятковий MD5-хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)"
        )

    combined = (password + salt).encode("utf-8")
    return hashlib.md5(combined).hexdigest()


def create_user(username: str, password: str) -> tuple:
    """Створює запис користувача (логін, хеш пароля)."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple) -> None:
    """Створює CSV-базу користувачів у data/users.csv."""
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        for username, password in users_list:
            try:
                login, hash_value = create_user(username, password)
                writer.writerow([login, hash_value])
            except (ValueError, ValidationError) as error:
                print(f"Пропущено користувача {username}: {error}")


def read_users_db() -> list:
    """Зчитує CSV-базу користувачів у список кортежів (логін, хеш)."""
    users_db = []
    with open(USERS_CSV_PATH, mode="r", newline="", encoding="utf-8") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))
    return users_db


def print_users_db(users_db: list) -> None:
    """Виводить базу користувачів у вигляді структурованої таблиці."""
    print(f"{'Логін':<15} | {'Хеш пароля':<32}")
    print("-" * 50)
    for login, hash_value in users_db:
        print(f"{login:<15} | {hash_value:<32}")


def log_event(func):
    """Декоратор, що записує кожну спробу входу у файл log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        username = args[0] if args else kwargs.get("username", "unknown")

        entry = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # noqa: DTZ005
            "args": [],
            "kwargs": {},
        }

        os.makedirs(DATA_DIR, exist_ok=True)
        events = []
        if os.path.exists(LOG_JSON_PATH):
            try:
                with open(LOG_JSON_PATH, "r", encoding="utf-8") as log_file:
                    events = json.load(log_file)
            except (OSError, json.JSONDecodeError):
                events = []

        events.append(entry)
        with open(LOG_JSON_PATH, "w", encoding="utf-8") as log_file:
            json.dump(events, log_file, ensure_ascii=False, indent=2)

        return result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін та пароль користувача проти бази у CSV."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми")

    users_db = read_users_db()
    expected_hash = generate_hash(password, PERSONAL_SALT)

    for login_name, stored_hash in users_db:
        if login_name == username and stored_hash == expected_hash:
            return True
    return False


def main() -> None:
    """Точка входу для завдання 3."""
    print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}\n")

    try:
        create_users(USERS_TO_REGISTER)
        users_db = read_users_db()
        print_users_db(users_db)

        print("\nСпроби автентифікації:")
        test_cases = [
            ("alice", "Str0ngP@ssword"),
            ("bob", "WrongPassword"),
            ("unknown_user", "SomePassword1"),
        ]
        for username, password in test_cases:
            success = login(username, password)
            status = "успішно" if success else "невдало"
            print(f"  {username}: {status}")

    except FileNotFoundError as error:
        print(f"Файл не знайдено: {error}")
    except PermissionError as error:
        print(f"Немає прав доступу до файлу: {error}")
    except OSError as error:
        print(f"Помилка вводу/виводу: {error}")
    except ValidationError as error:
        print(f"Помилка валідації: {error}")
    except ValueError as error:
        print(f"Некоректні дані: {error}")


if __name__ == "__main__":
    main()
