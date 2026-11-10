# RansomwareShield-SA v3.1.0 - update guide

1. Back up your current project folder.
2. Extract this ZIP and copy everything over your project folder.
   KEEP your own `.env` and `static/logo.jpg` (this package contains neither).
3. In VS Code terminal:
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -m py_compile app.py shieldai.py threat.py report.py
   pytest -q            # expect 4 passed
   python run.py        # test at http://127.0.0.1:5000
4. Push:
   git add .
   git status           # make sure .env is NOT listed
   git commit -m "Release v3.1.0"
   git push
   git tag -a v3.1.0 -m "RansomwareShield-SA v3.1.0"
   git push origin v3.1.0
5. Render > Environment must contain:
   FLASK_ENV=production, DATABASE_URL, SECRET_KEY, SESSION_MINUTES=30,
   SUPERADMIN_EMAIL=<your exact login email>, PUBLIC_BASE_URL=<your https Render URL>
   Optional: GRAPH_*, HIBP_API_KEY, VIRUSTOTAL_API_KEY, AZURE_OPENAI_* or AI_API_BASE/AI_API_KEY/AI_MODEL
6. Render > Settings: Start command `gunicorn wsgi:app --workers 1 --threads 4 --timeout 60`, Health check `/healthz`.
7. Manual Deploy > Deploy latest commit. New columns are added automatically; existing data is kept.
   Everyone is signed out once after this deploy (session security upgrade) - sign in again.
