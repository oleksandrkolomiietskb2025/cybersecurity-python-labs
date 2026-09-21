"""Завдання 1: Комплексний аналізатор надійності паролів (Варіант 12).

Оцінює надійність кожного пароля зі списку за категоріями:
Заборонений -> Слабкий -> Середній -> Сильний -> Дуже сильний.
"""

import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для варіанту 12
PASSWORDS = [
    "SIEM@An4lysis",
    "easy123",
    "S0C@Analyst",
    "observer",
    "Threat@Hunt1ng",
    "viewer",
    "Incid3nt@Handle",
    "monitor",
    "Log@An4lysis",
    "watcher",
]

CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"easy123", "observer", "viewer", "monitor", "watcher", "admin"}


def has_digit(password: str) -> bool:
    """Перевіряє, чи містить пароль хоча б одну цифру."""
    return any(char.isdigit() for char in password)


def has_upper(password: str) -> bool:
    """Перевіряє, чи містить пароль хоча б одну велику літеру."""
    return any(char.isupper() for char in password)


def has_lower(password: str) -> bool:
    """Перевіряє, чи містить пароль хоча б одну малу літеру."""
    return any(char.islower() for char in password)


def has_special(password: str) -> bool:
    """Перевіряє, чи містить пароль хоча б один спеціальний символ."""
    return any(not char.isalnum() for char in password)


def simulate_password_reuse(passwords: list, count: int = 3) -> list:
    """Додає у кінець списку дублікати кількох випадкових паролів.

    Імітує повторне використання паролів користувачами.
    """
    extended = passwords.copy()
    random_indexes = [random.randrange(len(passwords)) for _ in range(count)]
    for index in random_indexes:
        extended.append(passwords[index])
    return extended


def classify_password(password: str, all_passwords: list) -> str:
    """Визначає категорію надійності одного пароля."""
    if password in FORBIDDEN_PASSWORDS or len(password) < CRITERIA["min_length"]:
        return "Заборонений"

    required_met = sum(
        [
            has_digit(password) if CRITERIA["require_digits"] else True,
            has_upper(password) if CRITERIA["require_upper"] else True,
            has_special(password) if CRITERIA["require_special"] else True,
        ]
    )

    if required_met < 3:
        any_group_met = required_met > 0 or has_lower(password)
        if required_met >= 1:
            return "Середній"
        return "Слабкий" if any_group_met else "Заборонений"

    # Усі обов'язкові критерії виконано - перевіряємо довжину та унікальність.
    is_long_enough = len(password) >= CRITERIA["min_length"] + 4
    is_unique = all_passwords.count(password) == 1

    if is_long_enough and is_unique:
        return "Дуже сильний"
    return "Сильний"


def analyze_passwords(passwords: list) -> list:
    """Аналізує весь список паролів і повертає список результатів."""
    results = []
    for password in passwords:
        category = classify_password(password, passwords)
        results.append((password, category))
    return results


def print_results(results: list) -> None:
    """Виводить результати аналізу у табличному форматі."""
    print(f"{'Пароль':<20} | {'Категорія':<15}")
    print("-" * 38)
    for password, category in results:
        print(f"{password:<20} | {category:<15}")


def main() -> None:
    """Точка входу для завдання 1."""
    print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}\n")
    extended_passwords = simulate_password_reuse(PASSWORDS)
    results = analyze_passwords(extended_passwords)
    print_results(results)


if __name__ == "__main__":
    main()
