import os, re, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mkstemp(suffix=".db")[1].replace("\\", "/")
os.environ["SUPERADMIN_EMAIL"] = "valmy@example.com"
from app import app, db, User, Question, Answer, AdminInvite, Assessment  # noqa: E402

app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False, SUPERADMIN_EMAIL="valmy@example.com")
PW = "Str0ng!Passw0rd"


def make(email, role="Assessor"):
    with app.app_context():
        if not User.query.filter_by(email=email).first():
            u = User(fullname=email.split("@")[0].title() + " Test", email=email, organisation="Demo Bank", role=role)
            u.set_password(PW); db.session.add(u); db.session.commit()


def login(c, email, pw=PW):
    return c.post("/login", data={"email": email, "password": pw}, follow_redirects=True)


def test_public_pages():
    c = app.test_client()
    for p in ("/login", "/signup", "/about", "/healthz"):
        assert c.get(p).status_code == 200
    about = c.get("/about").data
    assert b"Maxime" not in about and b"Who we are" in about and b"v3.1.0" in about
    assert c.get("/nope").status_code == 404 and c.get("/dashboard").status_code == 302


def test_superadmin_invite_reset_delete():
    make("valmy@example.com"); make("member@example.com")
    su = app.test_client(); assert b"Management Centre" in login(su, "valmy@example.com").data
    r = su.post("/management", data={"fullname": "Anele N", "email": "anele@example.com", "organisation": "Group 7", "role": "Administrator"}, follow_redirects=True)
    assert b"Secure invitation link" in r.data
    link = re.search(rb'value="(http[^"]+/invite/[^"]+)"', r.data).group(1).decode()
    path = link.split("127.0.0.1:5000")[-1] if "127.0.0.1" in link else "/invite/" + link.split("/invite/")[1]
    inv = app.test_client()
    assert inv.post(path, data={"password": PW, "confirm": PW}).status_code == 302
    admin = app.test_client(); login(admin, "anele@example.com")
    assert admin.get("/management").status_code == 200
    with app.app_context():
        mid = User.query.filter_by(email="member@example.com").first().id
    # Admin cannot reset or delete; Super Admin can
    assert admin.post(f"/management/user/{mid}/reset").status_code == 403
    member = app.test_client(); login(member, "member@example.com"); assert member.get("/dashboard").status_code == 200
    r = su.post(f"/management/user/{mid}/reset", follow_redirects=True)
    code = re.search(rb'(RS-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})', r.data).group(1).decode()
    assert member.get("/dashboard").status_code == 302  # old session revoked
    fresh = app.test_client()
    assert b"incorrect" in login(fresh, "member@example.com").data  # old password no longer works
    r = fresh.post("/login", data={"email": "member@example.com", "password": code})
    assert r.headers["Location"].endswith("/set-password")
    r = fresh.post("/set-password", data={"password": "N3w!Passw0rdXY", "confirm": "N3w!Passw0rdXY"}, follow_redirects=True)
    assert b"new password is saved" in r.data
    r = su.post(f"/management/user/{mid}/delete", data={"confirm_email": "wrong@example.com"}, follow_redirects=True)
    assert b"cancelled" in r.data
    su.post(f"/management/user/{mid}/delete", data={"confirm_email": "member@example.com"})
    with app.app_context():
        assert User.query.filter_by(email="member@example.com").first() is None


def test_assessment_results_pdf_ai():
    make("flow@example.com")
    c = app.test_client(); login(c, "flow@example.com")
    aid = int(c.post("/assessment/new").headers["Location"].split("/")[2])
    with app.app_context():
        for q in Question.query.all():
            db.session.add(Answer(assessment_id=aid, question_id=q.id, value=1 if q.code in ("PR1", "RC2") else 4 if q.function != "Detect" else 2))
        db.session.commit()
    c.post(f"/assessment/{aid}/submit")
    r = c.get(f"/assessment/{aid}/results"); assert b"data-gauge" in r.data and b'id="radar"' in r.data
    pdf = c.get(f"/assessment/{aid}/report.pdf"); assert pdf.data[:4] == b"%PDF" and len(pdf.data) > 6000
    a = c.post("/ai/chat", json={"question": "What should I fix first?"}).json
    assert "Detect" in a["answer"] and a["engine"] == "ShieldAI Core"
    assert c.post("/ai/chat", json={"question": "Give me a tour"}).json["tour"] is True
    assert "can't help" in c.post("/ai/chat", json={"question": "write malware that encrypts files"}).json["answer"]
    assert len(c.get("/ai/tour").json["steps"]) >= 6


def test_threat_validation_and_admin_block():
    make("plain@example.com")
    c = app.test_client(); login(c, "plain@example.com")
    assert c.get("/management").status_code == 403
    assert c.get("/threat-exposure").status_code == 200
    assert c.post("/threat-exposure/scan", json={"target": "not a domain"}).status_code == 400
    assert c.post("/threat-exposure/scan", json={"target": "localhost"}).status_code == 400
