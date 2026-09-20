# Purge Shop (Python / Flask)

Public Minecraft rank store + private admin panel sharing one SQLite database.

## Setup
1. Install Python 3.10+.
2. Create a virtual environment: `python -m venv venv`
3. Activate it. Windows: `venv\\Scripts\\activate` — macOS/Linux: `source venv/bin/activate`
4. Install: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and change `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD`.
6. Run: `python app.py`
7. Public store: `http://127.0.0.1:5000/`
8. Admin login: `http://127.0.0.1:5000/admin/login`

The SQLite database is automatically created at `instance/purge_shop.db` and the five ranks are seeded automatically.

## Payment QR
Place your real QR image at `static/images/payment_qr.png`. Until then, checkout displays a PAYMENT QR placeholder.

## Production
Set `COOKIE_SECURE=true` when serving behind HTTPS, use a long random `SECRET_KEY`, use a strong admin password, disable Flask debug mode, and run with a production WSGI server such as Waitress: `waitress-serve --call app:app` (or adapt to your host). For a larger deployment, move from SQLite to PostgreSQL and put HTTPS/reverse-proxy protection in front of the app.

## Important payment behavior
UTR submission creates a `Pending Verification` order only. It never automatically approves or grants a rank. Admin must manually approve/reject it.
