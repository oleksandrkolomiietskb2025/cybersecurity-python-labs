"""Маршрути записів."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response

from .. import repository
from ..config import VALUE_MAX, VALUE_MIN
from ..schemas import RecordCreate, RecordRead, RecordReplace, Status
from .errors import api_errors

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису")]
NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Дублікат code"}}


@router.get("", response_model=list[RecordRead], summary="Список записів")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи категорії")
    ] = None,
    status: Annotated[
        Status | None, Query(description="Лише записи з цим статусом")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="value >= min_value",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Підрядок у title (з урахуванням регістру)",
        ),
    ] = None,
    limit: Annotated[
        int, Query(ge=1, le=100, description="Макс. кількість записів")
    ] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
) -> list[dict]:
    """Повернути записи з фільтрами (AND), відсортовані за id."""
    with api_errors():
        return repository.list_records(
            category_id=category_id,
            status=status,
            min_value=min_value,
            q=q,
            limit=limit,
            offset=offset,
        )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    payload: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Атомарно створити від 1 до 100 записів: або всі, або жодного."""
    with api_errors():
        return repository.create_records_bulk([item.model_dump() for item in payload])


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(payload: RecordCreate) -> dict:
    """Створити запис."""
    with api_errors():
        return repository.create_record(payload.model_dump())


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис за id."""
    with api_errors():
        return repository.get_record(record_id)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Замінити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, payload: RecordReplace) -> dict:
    """Повністю замінити змінювані поля запису."""
    with api_errors():
        return repository.replace_record(record_id, payload.model_dump())


@router.delete(
    "/{record_id}",
    status_code=204,
    summary="Видалити запис",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис."""
    with api_errors():
        repository.delete_record(record_id)
    return Response(status_code=204)
