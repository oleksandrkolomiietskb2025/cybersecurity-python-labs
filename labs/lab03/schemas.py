"""Pydantic-моделі запитів і відповідей."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import VALUE_MAX, VALUE_MIN

Status = Literal["new", "in_progress", "done"]


class StudentInfo(BaseModel):
    """Дані студента з shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int


class CategoryCreate(BaseModel):
    """Створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія у відповіді."""

    id: int


class RecordCreate(BaseModel):
    """Створення запису (id задає база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0, strict=True)
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        strict=True,
        description="Частка використання сховища, %",
    )
    status: Status


class RecordReplace(RecordCreate):
    """Повна заміна змінюваних полів запису (PUT)."""


class RecordRead(RecordCreate):
    """Запис у відповіді."""

    id: int
    category_name: str
