"""FastAPI-застосунок: облік використання сховищ (варіант 12)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared import student

from .config import DOMAIN, THRESHOLD, UNIT
from .database import initialize_database
from .routers import categories, records
from .schemas import StudentInfo


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску (дані не змінюються)."""
    initialize_database()
    yield


app = FastAPI(
    title="Облік використання сховищ",
    description=(
        f"{DOMAIN}. Категорія — тип сховища (logs, backups, archive); "
        f"value — частка зайнятого простору, одиниця: {UNIT} (0–100); "
        f"поріг: {THRESHOLD}; status — стан перевірки вимірювання."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["service"], summary="Перевірка доступності")
def ping() -> dict[str, str]:
    """Повернути {"status": "ok"}."""
    return {"status": "ok"}


@app.get(
    "/student", response_model=StudentInfo, tags=["service"], summary="Дані студента"
)
def get_student() -> StudentInfo:
    """Повернути ПІБ, групу та номер варіанта."""
    return StudentInfo(
        student_name=student.STUDENT_NAME,
        group_name=student.GROUP_NAME,
        variant_number=student.VARIANT_NUMBER,
    )
