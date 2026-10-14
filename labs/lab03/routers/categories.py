"""Маршрути категорій."""

from typing import Annotated

from fastapi import APIRouter, Path, Response

from .. import repository
from ..schemas import CategoryCreate, CategoryRead
from .errors import api_errors

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    with api_errors():
        return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію."""
    with api_errors():
        return repository.create_category(payload.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: Annotated[int, Path(gt=0, description="Ідентифікатор категорії")],
) -> Response:
    """Видалити категорію, якщо в ній немає записів."""
    with api_errors():
        repository.delete_category(category_id)
    return Response(status_code=204)
