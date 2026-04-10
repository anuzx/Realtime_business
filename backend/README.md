# Backend

```
python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

pip freeze > requirements.txt
```

```
uvicorn main:app --reload --port 3000
or
fastapi dev main.py
```

## Api endpoints

1. `POST /auth/register`
2. `POST /auth/login`
3. `GET /users/me`
4. `POST /api-keys/`
5. `GET /api-keys/`
6. `POST /logs/`
7. `GET /logs/`
8. `GET /alerts/`
9. `PATCH /alerts/{id}`
10. `GET /dashboard/summary`
11. `GET /dashboard/risk-score`
12. `POST /ai/analyze`
