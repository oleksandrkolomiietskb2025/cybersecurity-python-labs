"""Перетворення помилок шару даних на HTTP-помилки."""

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException

from ..repository import ConflictError, NotFoundError

logger = logging.getLogger(__name__)


@contextmanager
def api_errors() -> Iterator[None]:
    """Перехопити помилки репозиторію й підняти HTTPException."""
    try:
        yield
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        logger.exception("Помилка SQLite")
        raise HTTPException(
            status_code=500, detail="Внутрішня помилка роботи з базою даних"
        ) from exc
