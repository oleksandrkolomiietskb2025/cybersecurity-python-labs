# ЛР №3 — Облік використання сховищ (варіант 12)

Web API на FastAPI + SQLite (без ORM). `value` — частка зайнятого простору у **відсотках (0–100)**, поріг — **85.0**.
Категорії: `logs`, `backups`, `archive`. Статуси: `new`, `in_progress`, `done`.

## Встановлення
```bash
pip install fastapi uvicorn pydantic ruff
pip freeze | grep -iE "fastapi|uvicorn|pydantic|ruff"   # зафіксувати версії в requirements.txt
```

## Запуск (з кореня репозиторію)
```bash
python -m labs.lab03.seed
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```
Swagger UI: http://127.0.0.1:8000/docs

## Приклади
```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i -X POST "http://127.0.0.1:8000/records" -H "Content-Type: application/json" \
  -d '{"code":"V12-TEST","title":"Тестовий запис","category_id":1,"value":77.5,"status":"new"}'
curl -i -X POST "http://127.0.0.1:8000/records/bulk" -H "Content-Type: application/json" \
  -d '[{"code":"V12-ROLLBACK","title":"Перший елемент","category_id":1,"value":40.0,"status":"new"},{"code":"V12-01","title":"Дублікат коду","category_id":2,"value":50.0,"status":"new"}]'
```
