"""Завдання 2: Багаторівнева система контролю доступу (Варіант 12)."""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для варіанту 12
USERS = {
    "devsecops_lead": {
        "role": "devsecops",
        "clearance": 4,
        "department": "DevSecOps",
        "active": True,
    },
    "security_engineer": {
        "role": "security_engineer",
        "clearance": 3,
        "department": "Security Engineering",
        "active": True,
    },
    "automation_tech": {
        "role": "automation",
        "clearance": 2,
        "department": "Automation",
        "active": True,
    },
    "api_developer": {
        "role": "api_developer",
        "clearance": 2,
        "department": "API",
        "active": True,
    },
    "sandbox_env": {
        "role": "sandbox",
        "clearance": 1,
        "department": "Testing",
        "active": False,
    },
}

RESOURCES = [
    ("security_pipelines", 4),
    ("secure_coding_standards", 3),
    ("automation_scripts", 2),
    ("api_specifications", 2),
    ("threat_models", 4),
    ("testing_frameworks", 1),
    ("security_gates", 3),
    ("vulnerability_scans", 4),
    ("integration_tests", 2),
    ("mock_services", 1),
]

SECURITY_LEVELS = ("Sandbox", "Development", "Secure", "Production Critical")

BLOCKED_USERS = {"sandbox_env", "pipeline_breach", "automation_fail"}


def print_resources(resources: list, security_levels: tuple) -> None:
    """Виводить ресурси системи з текстовою назвою рівня безпеки."""
    print("Ресурси системи:")
    for name, level in resources:
        level_name = security_levels[level - 1]
        print(f"  {name} -> {level_name}")
    print()


def check_access(username: str, resource_name: str, required_level: int) -> tuple:
    """Перевіряє доступ користувача до конкретного ресурсу.

    Повертає кортеж (рішення, причина).
    """
    if username not in USERS:
        return "DENY", "User not found"

    if username in BLOCKED_USERS:
        return "DENY", "User is blocked"

    user = USERS[username]

    if not user["active"]:
        return "DENY", "Account inactive"

    if user["clearance"] >= required_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def run_access_checks(users: dict, resources: list) -> None:
    """Перевіряє доступ кожного користувача до кожного ресурсу і виводить результат."""
    for username in users:
        for resource_name, required_level in resources:
            decision, reason = check_access(username, resource_name, required_level)
            if decision == "ALLOW":
                print(f"user={username} resource={resource_name} -> ALLOW")
            else:
                print(f"user={username} resource={resource_name} -> DENY ({reason})")


def main() -> None:
    """Точка входу для завдання 2."""
    print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}\n")
    print_resources(RESOURCES, SECURITY_LEVELS)
    run_access_checks(USERS, RESOURCES)


if __name__ == "__main__":
    main()
