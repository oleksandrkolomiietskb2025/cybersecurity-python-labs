"""Завдання 1: Модель користувача, сесії та аудиту (ООП).

Демонструє інкапсуляцію (User), наслідування (Admin(User)) та композицію
(UserAccount, яка об'єднує User, Session та AuditLog).
"""

import hashlib
import hmac
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

sys.path.append(str(Path(__file__).resolve().parents[2]))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

EMAIL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]+$")
PBKDF2_ITERATIONS = 200_000
SESSION_TIMEOUT_SEC = 900


class User:
    """Базовий клас користувача з інкапсульованим паролем та email."""

    def __init__(self, username: str, email: str, role: str = "user") -> None:
        self.username = username
        self._email = ""
        self.email = email  # проходить через property-валідацію
        self.role = role
        self.active = True
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        """Повертає email користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Встановлює email лише якщо він відповідає очікуваному формату."""
        if not EMAIL_PATTERN.match(value):
            raise ValueError(f"Некоректний формат email: {value!r}")
        self._email = value

    def set_password(self, password: str) -> None:
        """Генерує сіль і зберігає PBKDF2-хеш пароля. Сам пароль не зберігається."""
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль, порівнюючи хеші через безпечне порівняння."""
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(candidate_hash, self.__password_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        status = "активний" if self.active else "неактивний"
        return f"User({self.username}, {self.email}, роль={self.role}, {status})"


class Admin(User):
    """Адміністратор — User з набором дозволів (наслідування, Is-A)."""

    def __init__(
        self, username: str, email: str, permissions: set | None = None
    ) -> None:
        super().__init__(username, email, role="administrator")
        # Не можна задавати змінювану колекцію типовим аргументом (мутабельний default).
        self.permissions: set = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Надає адміністратору новий дозвіл."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Забирає в адміністратора дозвіл, якщо він був."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє, чи має адміністратор конкретний дозвіл."""
        return permission in self.permissions

    def __str__(self) -> str:
        status = "активний" if self.active else "неактивний"
        perms = ", ".join(sorted(self.permissions)) or "немає"
        return f"Admin({self.username}, {self.email}, {status}, дозволи: {perms})"


class Session:
    """Сесія користувача з контролем часу неактивності (timeout)."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        """Оновлює час останньої активності до поточного моменту (UTC)."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи сесія ще дійсна відносно часу неактивності."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним числом")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed < timedelta(seconds=timeout_sec)


@dataclass
class AuditLogEntry:
    """Один запис у журналі аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій автентифікації (без збереження паролів)."""

    def __init__(self) -> None:
        self.records: list[AuditLogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Додає запис про подію з поточним часом UTC."""
        entry = AuditLogEntry(datetime.now(timezone.utc), username, action)
        self.records.append(entry)

    def show_all(self) -> None:
        """Друкує всі записи журналу аудиту."""
        for entry in self.records:
            time_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"  [{time_str}] {entry.username}: {entry.action}")


class UserAccount:
    """Об'єднує User, Session та AuditLog (композиція, Has-A)."""

    ALLOWED_KEYS: ClassVar[set] = {"username", "email", "role", "active", "ip"}

    def __init__(self, user: User, audit_log: AuditLog | None = None) -> None:
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Перевіряє логін/пароль і створює сесію лише після успіху."""
        if username != self.user.username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        if not self.user.check_password(password):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевіряє наявність активної (не протермінованої) сесії."""
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершує сесію та фіксує подію в журналі аудиту."""
        if self.session is not None:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        """Дозволяє account["email"] тощо; хеш/сіль пароля недоступні."""
        if key not in self.ALLOWED_KEYS:
            raise KeyError(f"Недозволений ключ: {key!r}")
        if key == "ip":
            return self.session.ip if self.session else None
        return getattr(self.user, key)

    def __setitem__(self, key: str, value) -> None:
        """Дозволяє account["role"] = "admin" тощо з перевіркою типу."""
        if key not in self.ALLOWED_KEYS:
            raise KeyError(f"Недозволений ключ: {key!r}")
        if key == "active" and not isinstance(value, bool):
            raise TypeError("active має бути bool")
        if key in {"username", "email", "role", "ip"} and not isinstance(value, str):
            raise TypeError(f"{key} має бути рядком")

        if key == "ip":
            if self.session is not None:
                self.session.ip = value
            return
        setattr(self.user, key, value)


def demo() -> None:
    """Демонстрація роботи класів: вхід, помилка пароля, email, права, вихід."""
    print("=== Демонстрація ЛР2, Завдання 1 ===")
    print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}\n")

    admin = Admin("ivan_admin", "ivan@example.com", permissions={"view_logs"})
    admin.set_password("StrongPassw0rd!")
    account = UserAccount(admin)

    print("1. Успішний вхід:")
    success = account.login("ivan_admin", "StrongPassw0rd!", "192.168.1.10")
    print(f"   Результат: {success}, автентифіковано: {account.is_authenticated()}\n")

    print("2. Невдалий вхід (неправильний пароль):")
    failure = account.login("ivan_admin", "WrongPassword", "192.168.1.10")
    print(f"   Результат: {failure}\n")

    print("3. Зміна email з валідацією:")
    try:
        admin.email = "invalid-email"
    except ValueError as error:
        print(f"   Відхилено некоректний email: {error}")
    admin.email = "ivan_admin2@example.com"
    print(f"   Email оновлено: {admin.email}\n")

    print("4. Права адміністратора:")
    admin.grant_permission("manage_users")
    print(f"   has_permission('manage_users') = {admin.has_permission('manage_users')}")
    admin.revoke_permission("view_logs")
    print(f"   {admin}\n")

    print("5. Завершення сесії за таймаутом (симуляція):")
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print(
        f"   is_authenticated() після імітації простою: {account.is_authenticated()}\n"
    )

    print("6. Вихід із системи:")
    account.login("ivan_admin", "StrongPassw0rd!", "192.168.1.10")
    account.logout()
    print(f"   Сесія активна після logout: {account.is_authenticated()}\n")

    print("7. Доступ через __getitem__ / __setitem__:")
    print(f"   account['role'] = {account['role']}")
    account["role"] = "senior_administrator"
    print(f"   Після зміни: account['role'] = {account['role']}")
    try:
        account["__password_hash"]
    except KeyError as error:
        print(f"   Доступ до хешу пароля заборонено: {error}\n")

    print("8. Журнал аудиту:")
    account.audit_log.show_all()


if __name__ == "__main__":
    demo()
