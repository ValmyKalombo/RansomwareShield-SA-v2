import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import app,db,User

def test_login_page():
 c=app.test_client(); assert c.get('/login').status_code==200

def test_signup_page():
 c=app.test_client(); assert c.get('/signup').status_code==200
