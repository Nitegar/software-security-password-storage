# Simple Login

A complete, minimal Django login app with account registration, sign-in, sign-out, and a protected dashboard. It uses Django's built-in user model and password hashing.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Open http://127.0.0.1:8000/ and select **Create an account**.

This configuration is for local development. Before deployment, set a private `SECRET_KEY`, set `DEBUG = False`, configure `ALLOWED_HOSTS`, and use HTTPS.
