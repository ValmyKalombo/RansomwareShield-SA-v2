# RansomwareShield-SA v2

Secure Flask assessment prototype with login, public first-user sign-up, stay-signed-in option, questionnaire, dashboard, results, PDF and About page.

## Recommended local location
Use a normal local development folder, not OneDrive sync:
`C:\Users\valmy\Documents\GitHub\RansomwareShield-SA`

## Local setup
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
python run.py
```
Open `http://127.0.0.1:5000`.

## Local HTTPS demonstration
```powershell
python run_https.py
```
Open `https://127.0.0.1:5443`. A browser warning is expected because the development certificate is self-signed. This is not the final public deployment.

## Public HTTPS
Push this folder to GitHub, create a Render PostgreSQL database, set `DATABASE_URL` in the Render Web Service, and deploy with:
- Build: `pip install -r requirements.txt`
- Start: `gunicorn wsgi:app`

## Security warning
Public self-registration is included for the academic requirement. A production banking platform should use invitation or administrator approval, verified domains, MFA and identity governance.
