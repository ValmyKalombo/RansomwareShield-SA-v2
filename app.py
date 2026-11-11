from io import BytesIO, StringIO
import csv
"""RansomwareShield-SA v3.1.0 - Cybersecurity Readiness Platform (Group 7 academic prototype)."""
import hashlib
import json
import logging
import secrets
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import msal
import requests
from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, send_file, session,
                   url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import CSRFError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import BooleanField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

import report as report_builder
import shieldai
import threat
from config import Config

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ransomwareshield")

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://", default_limits=["800 per hour"])
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to access that page."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"

CORE = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]
ALL = CORE + ["AI Preparedness"]
WEIGHTS = {"Govern": .20, "Identify": .15, "Protect": .20, "Detect": .15, "Respond": .15, "Recover": .15}
RECS = {
    "Govern": "Assign executive ownership, approve a ransomware policy and report readiness to the board quarterly.",
    "Identify": "Maintain asset, data and dependency registers and model ransomware scenarios in the risk register.",
    "Protect": "Prioritise MFA, patching, least privilege, segmentation and offline or immutable backups.",
    "Detect": "Expand endpoint and identity monitoring and test ransomware-specific detection use cases.",
    "Respond": "Approve and rehearse a ransomware response plan with clear escalation and communication paths.",
    "Recover": "Test restoration of critical systems against RTO/RPO targets and retain the evidence.",
    "AI Preparedness": "Include AI-enabled phishing and automated attack techniques in training and threat reviews.",
}


def utcnow():
    return datetime.now(timezone.utc)


def aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    organisation = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="Assessor")
    active = db.Column(db.Boolean, default=True, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    must_reset = db.Column(db.Boolean, default=False, nullable=False)
    reset_expires = db.Column(db.DateTime(timezone=True))

    @property
    def is_active(self):
        return self.active

    def get_id(self):
        # Binding the session to the password hash invalidates every session and
        # remember-me cookie as soon as the password changes or is reset.
        return f"{self.id}:{hashlib.sha256(self.password_hash.encode()).hexdigest()[:16]}"

    def set_password(self, p):
        self.password_hash = generate_password_hash(p, method="scrypt")

    def check_password(self, p):
        return check_password_hash(self.password_hash, p)

    def locked(self):
        lock = aware(self.locked_until)
        return bool(lock and lock > utcnow())


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    function = db.Column(db.String(30), nullable=False)
    text = db.Column(db.Text, nullable=False)
    order = db.Column(db.Integer, nullable=False)


class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    organisation = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(20), default="Draft")
    overall_score = db.Column(db.Float)
    readiness = db.Column(db.String(30))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    submitted_at = db.Column(db.DateTime(timezone=True))
    user = db.relationship("User")
    answers = db.relationship("Answer", cascade="all,delete-orphan", lazy=True)


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessment.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    value = db.Column(db.Integer)
    is_na = db.Column(db.Boolean, default=False)
    note = db.Column(db.String(500))
    question = db.relationship("Question")
    __table_args__ = (db.UniqueConstraint("assessment_id", "question_id"),)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event = db.Column(db.String(50), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


class Action(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessment.id"), nullable=False, index=True)
    question_code = db.Column(db.String(10), nullable=False)
    function = db.Column(db.String(30), nullable=False)
    title = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    owner = db.Column(db.String(100))
    due_date = db.Column(db.Date)
    status = db.Column(db.String(20), default="Open", nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    assessment = db.relationship("Assessment")
    __table_args__ = (db.UniqueConstraint("assessment_id", "question_code"),)


class AdminInvite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    fullname = db.Column(db.String(100), nullable=False)
    organisation = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="Administrator")
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    accepted_at = db.Column(db.DateTime(timezone=True))
    revoked = db.Column(db.Boolean, default=False)
    email_status = db.Column(db.String(30), default="Link created")


class ThreatCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)
    risk = db.Column(db.String(20), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


@login_manager.user_loader
def load_user(uid):
    try:
        raw_id, _, fingerprint = str(uid).partition(":")
        user = db.session.get(User, int(raw_id))
    except (TypeError, ValueError):
        return None
    if not user or not fingerprint or user.get_id() != uid or user.must_reset:
        return None
    return user


# ------------------------------------------------------------------ roles
def is_super(u=None):
    u = u or current_user
    return bool(u and u.is_authenticated and app.config["SUPERADMIN_EMAIL"] and u.email.lower() == app.config["SUPERADMIN_EMAIL"])


def is_admin(u=None):
    u = u or current_user
    return bool(u and u.is_authenticated and (is_super(u) or u.role in ("Administrator", "Admin")))


def display_role(u):
    return "Super Admin" if is_super(u) else u.role


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not is_admin():
            audit("ADMIN_ACCESS", "BLOCKED", request.path)
            abort(403)
        return fn(*a, **kw)
    return wrapper


def super_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not is_super():
            audit("SUPERADMIN_ACCESS", "BLOCKED", request.path)
            abort(403)
        return fn(*a, **kw)
    return wrapper


# ------------------------------------------------------------------ forms
def strong(form, field):
    p = field.data or ""
    classes = sum([any(c.islower() for c in p), any(c.isupper() for c in p), any(c.isdigit() for c in p),
                   any(not c.isalnum() for c in p)])
    if len(p) < 12 or classes < 3:
        raise ValidationError("Use 12+ characters with three of: uppercase, lowercase, number, symbol.")


ROLE_CHOICES = [("Assessor", "Assessor"), ("Organisation Manager", "Organisation Manager")]


class LoginForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password or one-time reset code", validators=[DataRequired(), Length(min=8, max=128)])
    remember = BooleanField("Keep me signed in")
    submit = SubmitField("Sign in securely")


class SignupForm(FlaskForm):
    fullname = StringField("Full name", validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField("Work email", validators=[DataRequired(), Email(), Length(max=255)])
    organisation = StringField("Organisation", validators=[DataRequired(), Length(min=2, max=150)])
    role = SelectField("Role", choices=ROLE_CHOICES)
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128), strong])
    confirm = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", "Passwords must match.")])
    terms = BooleanField("I confirm I will only enter fictional academic data", validators=[DataRequired("Please confirm.")])
    submit = SubmitField("Create secure account")

    def validate_email(self, f):
        if User.query.filter_by(email=f.data.strip().lower()).first():
            raise ValidationError("An account with this email already exists.")


class InviteForm(FlaskForm):
    fullname = StringField("Full name", validators=[DataRequired(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    organisation = StringField("Organisation", validators=[DataRequired(), Length(max=150)])
    role = SelectField("Role", choices=[("Administrator", "Administrator")] + ROLE_CHOICES)
    submit = SubmitField("Create secure invitation")


class NewPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(max=128), strong])
    confirm = PasswordField("Confirm new password", validators=[DataRequired(), EqualTo("password", "Passwords must match.")])
    submit = SubmitField("Save new password")


# ------------------------------------------------------------------ request hooks
@app.before_request
def assign_request_id():
    g.request_id = secrets.token_hex(6)


@app.after_request
def security_headers(r):
    r.headers.update({
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin", "Cache-Control": "no-store",
        "X-Request-ID": g.get("request_id", ""),
        "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                    "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
                                    "form-action 'self'"),
    })
    if app.config["PRODUCTION"]:
        r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return r


@app.context_processor
def inject_globals():
    return {"app_version": app.config["APP_VERSION"], "current_year": utcnow().year,
            "is_admin_user": is_admin(), "is_superadmin": is_super(), "display_role": display_role,
            "super_email": app.config["SUPERADMIN_EMAIL"]}


def audit(event, outcome, details="", user=None):
    try:
        uid = user.id if user is not None else (current_user.id if current_user.is_authenticated else None)
        db.session.add(Audit(user_id=uid, event=event, outcome=outcome, details=(details or "")[:255]))
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.exception("Audit write failed")


# ------------------------------------------------------------------ helpers
def owned(a):
    if a.user_id != current_user.id and not is_admin():
        audit("ACCESS_DENIED", "BLOCKED", f"Assessment {a.id}")
        abort(403)


def get_assessment(aid):
    a = db.session.get(Assessment, aid)
    if a is None:
        abort(404)
    owned(a)
    return a


def level(s):
    return report_builder.level(s)


def function_scores(a):
    out = {}
    for fn in CORE:
        vals = [(x.value - 1) / 4 * 100 for x in a.answers if x.question.function == fn and not x.is_na and x.value]
        out[fn] = round(sum(vals) / len(vals), 1) if vals else None
    return out


def weak_answers(a):
    return sorted([x for x in a.answers if x.value and x.value <= 2], key=lambda x: (x.value, x.question.order))


def ensure_actions(a):
    existing = {x.question_code for x in Action.query.filter_by(assessment_id=a.id)}
    added = False
    for x in weak_answers(a):
        if x.question.code not in existing:
            db.session.add(Action(assessment_id=a.id, question_code=x.question.code, function=x.question.function,
                                  title=x.question.text, recommendation=RECS[x.question.function],
                                  priority="Critical" if x.value == 1 else "High",
                                  due_date=(utcnow() + timedelta(days=30 if x.value == 1 else 60)).date()))
            added = True
    if added:
        db.session.commit()


def user_assessment_ids(user=None):
    user = user or current_user
    return [a.id for a in Assessment.query.filter_by(user_id=user.id).all()]


def ai_context(page=""):
    latest = (Assessment.query.filter_by(user_id=current_user.id, status="Completed")
              .order_by(Assessment.submitted_at.desc()).first())
    ids = user_assessment_ids()
    acts = Action.query.filter(Action.assessment_id.in_(ids)).all() if ids else []
    open_acts = [x for x in acts if x.status in ("Open", "In Progress")]
    last_check = ThreatCheck.query.filter_by(user_id=current_user.id).order_by(ThreatCheck.created_at.desc()).first()
    ctx = {"role": display_role(current_user), "page": page, "open_actions": len(open_acts),
           "critical": sum(1 for x in open_acts if x.priority == "Critical"),
           "exposure": f"{last_check.risk} risk" if last_check else None, "score": None}
    if latest:
        weak = weak_answers(latest)
        ctx.update(score=latest.overall_score, readiness=latest.readiness, functions=function_scores(latest),
                   weak=[(w.question.code, w.question.function, w.question.text) for w in weak],
                   critical_weak=sum(1 for w in weak if w.value == 1))
    return ctx


def seed():
    if Question.query.count():
        return
    for i, x in enumerate(json.loads((BASE / "questions.json").read_text(encoding="utf-8"))):
        db.session.add(Question(code=x["code"], function=x["function"], text=x["text"], order=i))
    db.session.commit()


def migrate():
    """Additive, idempotent column migrations for existing Render databases."""
    insp = inspect(db.engine)
    cols = {c["name"] for c in insp.get_columns("user")}
    ts = "TIMESTAMP WITH TIME ZONE" if db.engine.dialect.name == "postgresql" else "TIMESTAMP"
    with db.engine.begin() as conn:
        if "must_reset" not in cols:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN must_reset BOOLEAN NOT NULL DEFAULT FALSE'))
        if "reset_expires" not in cols:
            conn.execute(text(f'ALTER TABLE "user" ADD COLUMN reset_expires {ts}'))


def send_graph_mail(to, subject, html):
    c = app.config
    if not all([c["GRAPH_TENANT_ID"], c["GRAPH_CLIENT_ID"], c["GRAPH_CLIENT_SECRET"], c["GRAPH_SENDER"]]):
        return False, "Email service not configured - copy the secure link or code below and share it privately."
    try:
        client = msal.ConfidentialClientApplication(c["GRAPH_CLIENT_ID"],
                                                    authority=f"https://login.microsoftonline.com/{c['GRAPH_TENANT_ID']}",
                                                    client_credential=c["GRAPH_CLIENT_SECRET"])
        tok = client.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in tok:
            return False, "Email authentication failed - share the link or code manually."
        body = {"message": {"subject": subject, "body": {"contentType": "HTML", "content": html},
                            "toRecipients": [{"emailAddress": {"address": to}}]}, "saveToSentItems": True}
        r = requests.post(f"https://graph.microsoft.com/v1.0/users/{c['GRAPH_SENDER']}/sendMail",
                          headers={"Authorization": "Bearer " + tok["access_token"]}, json=body, timeout=15)
        return (True, f"Email sent to {to}.") if r.status_code == 202 else (False, f"Email service returned {r.status_code}.")
    except Exception:
        log.exception("Graph mail failed")
        return False, "Email could not be sent - share the link or code manually."


# ------------------------------------------------------------------ errors
def error_page(code, title, message):
    return render_template("error.html", code=code, title=title, message=message,
                           request_id=g.get("request_id", "")), code


for _code, _title, _msg in [
        (400, "Bad request", "The request could not be processed. Go back and try again."),
        (403, "Access denied", "Your account does not have permission to view this resource."),
        (404, "Page not found", "The page you requested does not exist or has moved."),
        (429, "Too many requests", "For your protection this action is temporarily rate limited. Please wait and try again."),
        (500, "Service unavailable", "Something went wrong on our side. The event has been logged.")]:
    app.register_error_handler(_code, lambda e, c=_code, t=_title, m=_msg: error_page(c, t, m))


@app.errorhandler(CSRFError)
def csrf_error(e):
    audit("CSRF_REJECTED", "BLOCKED", request.path)
    return error_page(400, "Security check expired", "Your form session expired. Refresh the page and submit again.")


# ------------------------------------------------------------------ public routes
@app.get("/healthz")
@limiter.exempt
def healthz():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok", version=app.config["APP_VERSION"])
    except Exception:
        return jsonify(status="degraded"), 503


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if u and u.locked():
            audit("LOGIN", "BLOCKED", "Temporary lockout", u)
            flash("This account is temporarily locked after repeated failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html", form=form), 429
        if u and u.active and u.check_password(form.password.data):
            u.failed_attempts, u.locked_until = 0, None
            if u.must_reset:
                if aware(u.reset_expires) and aware(u.reset_expires) < utcnow():
                    db.session.commit()
                    audit("PASSWORD_RESET", "EXPIRED", "Reset code expired", u)
                    flash("Your one-time reset code has expired. Ask your administrator for a new one.", "error")
                    return render_template("login.html", form=form)
                db.session.commit()
                session.clear()
                session["reset_uid"] = u.id
                session["reset_at"] = utcnow().isoformat()
                audit("PASSWORD_RESET", "CODE_ACCEPTED", "Reset code verified", u)
                return redirect(url_for("set_password"))
            db.session.commit()
            session.clear()
            session.permanent = True
            login_user(u, remember=form.remember.data, fresh=True)
            audit("LOGIN", "SUCCESS", "Authenticated session created", u)
            return redirect(url_for("dashboard"))
        if u:
            u.failed_attempts = (u.failed_attempts or 0) + 1
            if u.failed_attempts >= 5:
                u.locked_until = utcnow() + timedelta(minutes=15)
            db.session.commit()
        audit("LOGIN", "FAILED", "Invalid credentials", u)
        flash("The email address or password is incorrect.", "error")
    return render_template("login.html", form=form)


@app.route("/set-password", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def set_password():
    uid = session.get("reset_uid")
    started = session.get("reset_at")
    if not uid or not started or utcnow() - datetime.fromisoformat(started) > timedelta(minutes=10):
        session.pop("reset_uid", None)
        flash("Sign in with your one-time reset code to create a new password.", "warning")
        return redirect(url_for("login"))
    u = db.session.get(User, uid)
    if not u or not u.must_reset:
        session.clear()
        return redirect(url_for("login"))
    form = NewPasswordForm()
    if form.validate_on_submit():
        if u.check_password(form.password.data):
            flash("Choose a new password that is different from the reset code.", "error")
        else:
            u.set_password(form.password.data)
            u.must_reset, u.reset_expires = False, None
            db.session.commit()
            session.clear()
            session.permanent = True
            login_user(u, fresh=True)
            audit("PASSWORD_RESET", "SUCCESS", "User created a new password", u)
            flash("Your new password is saved and all previous sessions were signed out.", "success")
            return redirect(url_for("dashboard"))
    return render_template("set_password.html", form=form, user=u)


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("20 per hour", methods=["POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = SignupForm()
    if form.validate_on_submit():
        u = User(fullname=form.fullname.data.strip(), email=form.email.data.strip().lower(),
                 organisation=form.organisation.data.strip(), role=form.role.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()
        audit("SIGNUP", "SUCCESS", "Self-registration", u)
        flash("Account created. Sign in to continue.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)


@app.post("/logout")
@login_required
def logout():
    audit("LOGOUT", "SUCCESS", "Session ended")
    logout_user()
    session.clear()
    flash("You have been signed out securely.", "success")
    return redirect(url_for("login"))


@app.get("/about")
def about():
    return render_template("about.html")


# ------------------------------------------------------------------ workspace
@app.get("/dashboard")
@login_required
def dashboard():
    assessments = Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()).all()
    completed = [a for a in assessments if a.status == "Completed"]
    latest = completed[0] if completed else None
    ids = [a.id for a in assessments]
    acts = Action.query.filter(Action.assessment_id.in_(ids)).all() if ids else []
    open_acts = [x for x in acts if x.status in ("Open", "In Progress")]
    last_check = ThreatCheck.query.filter_by(user_id=current_user.id).order_by(ThreatCheck.created_at.desc()).first()
    trend = [{"label": a.submitted_at.strftime("%d %b") if a.submitted_at else f"#{a.id}", "score": a.overall_score or 0}
             for a in reversed(completed[:8])]
    hour = (utcnow() + timedelta(hours=2)).hour  # SAST
    greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 18 else "Good evening"
    return render_template("dashboard.html", assessments=assessments, latest=latest,
                           scores=function_scores(latest) if latest else None, trend=trend,
                           open_actions=len(open_acts), critical=sum(1 for x in open_acts if x.priority == "Critical"),
                           overdue=sum(1 for x in open_acts if x.due_date and x.due_date < date.today()),
                           last_check=last_check, greeting=greeting, first_name=current_user.fullname.split()[0])


@app.post("/assessment/new")
@login_required
def new_assessment():
    a = Assessment(user_id=current_user.id, organisation=current_user.organisation)
    db.session.add(a)
    db.session.commit()
    audit("ASSESSMENT_CREATE", "SUCCESS", f"Assessment {a.id}")
    return redirect(url_for("assessment", aid=a.id, fn="Govern"))


@app.route("/assessment/<int:aid>/<fn>", methods=["GET", "POST"])
@login_required
def assessment(aid, fn):
    a = get_assessment(aid)
    if a.status == "Completed":
        return redirect(url_for("results", aid=aid))
    if fn not in ALL:
        abort(404)
    questions = Question.query.filter_by(function=fn).order_by(Question.order).all()
    existing = {x.question_id: x for x in a.answers}
    if request.method == "POST":
        for q in questions:
            raw = request.form.get(f"q{q.id}", "")
            if raw not in {"1", "2", "3", "4", "5", "NA"}:
                continue
            ans = existing.get(q.id) or Answer(assessment_id=aid, question_id=q.id)
            ans.is_na = raw == "NA"
            ans.value = None if ans.is_na else int(raw)
            ans.note = request.form.get(f"n{q.id}", "").strip()[:500]
            db.session.add(ans)
        db.session.commit()
        flash(f"{fn} responses saved securely.", "success")
        i = ALL.index(fn)
        act = request.form.get("action")
        if act == "next" and i < len(ALL) - 1:
            return redirect(url_for("assessment", aid=aid, fn=ALL[i + 1]))
        if act == "submit":
            return redirect(url_for("review", aid=aid))
        return redirect(url_for("assessment", aid=aid, fn=fn))
    answered = sum(1 for x in a.answers if x.value is not None or x.is_na)
    return render_template("assessment.html", a=a, fn=fn, functions=ALL, questions=questions, existing=existing,
                           answered=answered, total=Question.query.count())


@app.get("/assessment/<int:aid>/review")
@login_required
def review(aid):
    a = get_assessment(aid)
    total = Question.query.filter(Question.function != "AI Preparedness").count()
    answered = sum(1 for x in a.answers if x.question.function != "AI Preparedness" and (x.value is not None or x.is_na))
    missing_na = [x.question.code for x in a.answers if x.is_na and not x.note]
    return render_template("review.html", a=a, total=total, answered=answered, missing_na=missing_na)


@app.post("/assessment/<int:aid>/submit")
@login_required
def submit(aid):
    a = get_assessment(aid)
    core = Question.query.filter(Question.function != "AI Preparedness").all()
    answered = {x.question_id for x in a.answers if x.value is not None or x.is_na}
    if not all(q.id in answered for q in core):
        flash("Complete all core questions before submitting.", "error")
        return redirect(url_for("review", aid=aid))
    sc = function_scores(a)
    usable = [f for f in CORE if sc[f] is not None]
    den = sum(WEIGHTS[f] for f in usable)
    a.overall_score = round(sum(sc[f] * WEIGHTS[f] for f in usable) / den, 1) if den else None
    a.readiness = level(a.overall_score)
    a.status = "Completed"
    a.submitted_at = utcnow()
    db.session.commit()
    ensure_actions(a)
    audit("ASSESSMENT_SUBMIT", "SUCCESS", f"Assessment {a.id}")
    return redirect(url_for("results", aid=aid))


@app.get("/assessment/<int:aid>/results")
@login_required
def results(aid):
    a = get_assessment(aid)
    if a.status != "Completed":
        return redirect(url_for("assessment", aid=aid, fn="Govern"))
    ensure_actions(a)
    return render_template("results.html", a=a, scores=function_scores(a), risks=weak_answers(a), recs=RECS)


@app.get("/assessment/<int:aid>/report.pdf")
@login_required
def report(aid):
    a = get_assessment(aid)
    if a.status != "Completed":
        abort(404)
    weak = weak_answers(a)
    sc = function_scores(a)
    ctx = {"score": a.overall_score, "readiness": a.readiness, "functions": sc,
           "weak": [(w.question.code, w.question.function, w.question.text) for w in weak],
           "critical_weak": sum(1 for w in weak if w.value == 1)}
    pdf = report_builder.build(a, sc, weak, RECS, shieldai.executive_summary(ctx), app.config["APP_VERSION"], BASE)
    audit("REPORT_GENERATE", "SUCCESS", f"Assessment {a.id}")
    return send_file(pdf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"RansomwareShield-SA-Readiness-Report-RSA-{a.id:04d}.pdf")


@app.get("/actions")
@login_required
def actions():
    ids = [a.id for a in Assessment.query.all()] if is_admin() else user_assessment_ids()
    items = (Action.query.filter(Action.assessment_id.in_(ids)).order_by(Action.status, Action.due_date).all()) if ids else []
    return render_template("actions.html", items=items, today=date.today())


@app.post("/actions/<int:iid>")
@login_required
def action_update(iid):
    x = db.session.get(Action, iid) or abort(404)
    owned(x.assessment)
    x.owner = request.form.get("owner", "").strip()[:100] or None
    if request.form.get("status") in ("Open", "In Progress", "Remediated", "Accepted Risk"):
        x.status = request.form["status"]
    try:
        x.due_date = date.fromisoformat(request.form["due_date"]) if request.form.get("due_date") else None
    except ValueError:
        flash("Invalid due date ignored.", "warning")
    db.session.commit()
    audit("ACTION_UPDATE", "SUCCESS", f"Action {x.id} -> {x.status}")
    flash(f"{x.question_code} updated.", "success")
    return redirect(url_for("actions"))


@app.get("/security")
@login_required
def security():
    events = Audit.query.filter_by(user_id=current_user.id).order_by(Audit.created_at.desc()).limit(30).all()
    controls = [("TLS-encrypted transport (HTTPS + HSTS)", app.config["PRODUCTION"]),
                ("Secure, HttpOnly, SameSite session cookies", app.config["SESSION_COOKIE_SECURE"]),
                ("CSRF tokens on every form", True), ("scrypt password hashing", True),
                ("Login throttling and 15-minute lockout", True), ("Content Security Policy", True),
                ("Session revocation on password change", True), ("Role-based access control", True),
                ("Tamper-evident audit trail", True)]
    return render_template("security.html", events=events, controls=controls)


# ------------------------------------------------------------------ threat exposure
@app.get("/threat-exposure")
@login_required
def threat_exposure():
    history = ThreatCheck.query.filter_by(user_id=current_user.id).order_by(ThreatCheck.created_at.desc()).limit(10).all()
    return render_template("threat.html", history=history)


@app.post("/threat-exposure/scan")
@login_required
@limiter.limit("20 per hour")
def threat_scan():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", ""))[:255]
    domain, email = threat.normalise(target)
    if not domain:
        return jsonify(error="Enter a valid public domain (example.co.za) or email address."), 400
    result = threat.check(domain, email, app.config)
    if result.get("error"):
        return jsonify(error=result["error"]), 422
    db.session.add(ThreatCheck(user_id=current_user.id, target=target.strip().lower(),
                               target_type="email" if email else "domain", risk=result["risk"],
                               summary=result["summary"]))
    db.session.commit()
    audit("THREAT_CHECK", "SUCCESS", f"{domain} {result['risk']}")
    return jsonify(result)


# ------------------------------------------------------------------ ShieldAI
@app.post("/ai/chat")
@login_required
@limiter.limit("40 per minute")
def ai_chat():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", ""))[:800]
    history = data.get("history") if isinstance(data.get("history"), list) else []
    result = shieldai.answer(app.config, question, history, ai_context(str(data.get("page", ""))[:60]))
    audit("SHIELDAI", "SUCCESS", question[:90])
    return jsonify(result)


@app.get("/ai/tour")
@login_required
def ai_tour():
    steps = [s for s in shieldai.TOUR_STEPS if s["target"] != "nav-management" or is_admin()]
    return jsonify(steps=steps)


# ------------------------------------------------------------------ Management Centre
def invite_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="admin-invite")



def build_monitoring():
    """Every user's questionnaire progress and score, newest activity first."""
    total = Question.query.count()
    rows = []
    for u in User.query.order_by(User.fullname).all():
        assessments = Assessment.query.filter_by(user_id=u.id).order_by(Assessment.created_at.desc()).all()
        if not assessments:
            rows.append({"user": u, "assessment": None, "answered": 0, "total": total, "progress": 0,
                         "last_activity": u.created_at})
        for a in assessments:
            answered = sum(1 for x in a.answers if x.value is not None or x.is_na)
            rows.append({"user": u, "assessment": a, "answered": answered, "total": total,
                         "progress": round(answered / total * 100) if total else 0,
                         "last_activity": a.submitted_at or a.created_at})
    floor = datetime(1970, 1, 1, tzinfo=timezone.utc)
    rows.sort(key=lambda r: aware(r["last_activity"]) or floor, reverse=True)
    return rows, total

@app.route("/management", methods=["GET", "POST"])
@admin_required
def management():
    form = InviteForm()
    new_link = None
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            flash("That email already has an account.", "error")
        elif form.role.data == "Administrator" and not is_super():
            flash("Only the Super Admin can invite Administrators.", "error")
        else:
            raw = secrets.token_urlsafe(32)
            inv = AdminInvite(email=email, fullname=form.fullname.data.strip(), organisation=form.organisation.data.strip(),
                              role=form.role.data, token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                              created_by=current_user.id, expires_at=utcnow() + timedelta(hours=48))
            db.session.add(inv)
            db.session.commit()
            token = invite_serializer().dumps({"id": inv.id, "raw": raw})
            new_link = app.config["PUBLIC_BASE_URL"] + url_for("accept_invite", token=token)
            ok, msg = send_graph_mail(email, "Your RansomwareShield-SA invitation",
                                      f"<p>Hello {inv.fullname},</p><p>You have been invited to RansomwareShield-SA as "
                                      f"<b>{inv.role}</b>.</p><p><a href='{new_link}'>Accept your secure invitation</a></p>"
                                      "<p>The link expires in 48 hours and can be used once.</p>")
            inv.email_status = "Emailed" if ok else "Link created"
            db.session.commit()
            audit("ADMIN_INVITE", "SUCCESS", f"{email} as {inv.role}")
            flash(msg, "success" if ok else "warning")
    users = User.query.order_by(User.created_at.desc()).all()
    invites = AdminInvite.query.order_by(AdminInvite.created_at.desc()).limit(25).all()
    feed = Audit.query.order_by(Audit.created_at.desc()).limit(15).all() if is_super() else []
    names = {u.id: u.fullname for u in users}
    now = utcnow()
    stats = {"users": len(users), "admins": sum(1 for u in users if is_admin(u)),
             "active": sum(1 for u in users if u.active),
             "pending": sum(1 for i in invites if not i.accepted_at and not i.revoked and aware(i.expires_at) > now),
             "assessments": Assessment.query.filter_by(status="Completed").count(),
             "events24": Audit.query.filter(Audit.created_at >= now - timedelta(hours=24)).count(),
             "blocked24": Audit.query.filter(Audit.created_at >= now - timedelta(hours=24),
                                             Audit.outcome.in_(["BLOCKED", "FAILED"])).count()}
    reset_code = session.pop("reset_code", None)
    # v3.2.0 questionnaire monitoring (read-only)
    monitor, total_questions = build_monitoring()

    return render_template("management.html", form=form, users=users, invites=invites, stats=stats,
                           new_link=new_link, feed=feed, names=names, reset_code=reset_code, now=now,
                           monitor=monitor, total_questions=total_questions)

def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M") if dt else ""


@app.get("/management/monitoring.csv")
@admin_required
def export_monitoring_csv():
    rows, _ = build_monitoring()
    out = StringIO()
    w = csv.writer(out)
    w.writerow(["User", "Email", "Organisation", "Role", "Assessment", "Status", "Answered", "Total",
                "Completion %", "Score %", "Readiness", "Started UTC", "Submitted UTC"])
    for r in rows:
        u, a = r["user"], r["assessment"]
        w.writerow([u.fullname, u.email, u.organisation, display_role(u),
                    f"RSA-{a.id:04d}" if a else "", a.status if a else "Not started", r["answered"], r["total"],
                    r["progress"], a.overall_score if a and a.overall_score is not None else "",
                    a.readiness if a and a.readiness else "", _fmt(a.created_at) if a else "",
                    _fmt(a.submitted_at) if a else ""])
    audit("MANAGEMENT_EXPORT", "SUCCESS", "Monitoring CSV")
    return Response(out.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f"attachment; filename=RansomwareShield-SA-Monitoring-{utcnow():%Y-%m-%d}.csv"})


@app.get("/management/activity.csv")
@admin_required
def export_activity_csv():
    users = {u.id: u for u in User.query.all()}
    out = StringIO()
    w = csv.writer(out)
    w.writerow(["UTC time", "User", "Email", "Event", "Outcome", "Details"])
    for e in Audit.query.order_by(Audit.created_at.desc()).all():
        u = users.get(e.user_id)
        w.writerow([_fmt(e.created_at), u.fullname if u else "Anonymous / deleted", u.email if u else "",
                    e.event, e.outcome, e.details or ""])
    audit("MANAGEMENT_EXPORT", "SUCCESS", "Activity CSV")
    return Response(out.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f"attachment; filename=RansomwareShield-SA-Activity-{utcnow():%Y-%m-%d}.csv"})


@app.get("/management/monitoring.pdf")
@admin_required
def export_monitoring_pdf():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    rows, total = build_monitoring()
    st = getSampleStyleSheet()
    cell = st["BodyText"].clone("cell", fontSize=7.5, leading=9.5)
    data = [["User", "Role", "Assessment", "Status", "Answered", "Completion", "Score", "Readiness", "Last activity (UTC)"]]
    for r in rows:
        u, a = r["user"], r["assessment"]
        data.append([Paragraph(f"<b>{u.fullname}</b><br/>{u.email}<br/>{u.organisation}", cell), display_role(u),
                     f"RSA-{a.id:04d}" if a else "-", a.status if a else "Not started", f"{r['answered']}/{total}",
                     f"{r['progress']}%", f"{a.overall_score}%" if a and a.overall_score is not None else "-",
                     a.readiness if a and a.readiness else "-", _fmt(r["last_activity"]) or "-"])
    completed = sum(1 for r in rows if r["assessment"] and r["assessment"].status == "Completed")
    drafts = sum(1 for r in rows if r["assessment"] and r["assessment"].status != "Completed")
    not_started = sum(1 for r in rows if not r["assessment"])
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm, title="RansomwareShield-SA Monitoring Report")
    t = Table(data, repeatRows=1, colWidths=[62 * mm, 30 * mm, 24 * mm, 22 * mm, 20 * mm, 22 * mm, 18 * mm, 24 * mm, 30 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6F2CFF")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                           ("FONTSIZE", (0, 0), (-1, -1), 7.5), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F5FB")]),
                           ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DFE3EF")), ("PADDING", (0, 0), (-1, -1), 4)]))
    doc.build([Paragraph("RansomwareShield-SA - Management Monitoring Report", st["Title"]),
               Paragraph(f"Generated {utcnow():%d %B %Y %H:%M} UTC | v{app.config['APP_VERSION']} | "
                         f"{completed} completed, {drafts} in progress, {not_started} users not started | Confidential", st["Normal"]),
               Spacer(1, 5 * mm), t])
    buf.seek(0)
    audit("MANAGEMENT_EXPORT", "SUCCESS", "Monitoring PDF")
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"RansomwareShield-SA-Monitoring-{utcnow():%Y-%m-%d}.pdf")

@app.post("/management/user/<int:uid>")
@admin_required
def manage_user(uid):
    u = db.session.get(User, uid) or abort(404)
    if is_super(u) or u.id == current_user.id:
        flash("You cannot change this account from here.", "error")
        return redirect(url_for("management"))
    if is_admin(u) and not is_super():
        flash("Only the Super Admin can change another Administrator.", "error")
        return redirect(url_for("management"))
    action = request.form.get("action")
    if action == "toggle":
        u.active = not u.active
        detail = "activated" if u.active else "suspended"
    elif action == "role":
        role = request.form.get("role")
        if role not in ("Administrator", "Organisation Manager", "Assessor"):
            abort(400)
        if role == "Administrator" and not is_super():
            flash("Only the Super Admin can grant Administrator.", "error")
            return redirect(url_for("management"))
        u.role = role
        detail = f"role {role}"
    else:
        abort(400)
    db.session.commit()
    audit("USER_MANAGE", "SUCCESS", f"{u.email} {detail}")
    flash(f"{u.fullname}: {detail}.", "success")
    return redirect(url_for("management"))


@app.post("/management/user/<int:uid>/reset")
@super_required
def reset_user_password(uid):
    u = db.session.get(User, uid) or abort(404)
    if is_super(u):
        flash("Use your own sign-in to change the Super Admin password.", "error")
        return redirect(url_for("management"))
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "RS-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
    u.set_password(code)
    u.must_reset = True
    u.reset_expires = utcnow() + timedelta(hours=24)
    u.failed_attempts, u.locked_until = 0, None
    db.session.commit()
    ok, msg = send_graph_mail(u.email, "Your RansomwareShield-SA password was reset",
                              f"<p>Hello {u.fullname},</p><p>An administrator reset your password.</p>"
                              f"<p>Sign in at {app.config['PUBLIC_BASE_URL']} using your email and this one-time code: "
                              f"<b>{code}</b></p><p>You will then create a new password. The code expires in 24 hours.</p>")
    session["reset_code"] = {"name": u.fullname, "email": u.email, "code": code, "emailed": ok}
    audit("PASSWORD_RESET", "ISSUED", f"{u.email} by Super Admin")
    flash(f"Password reset for {u.fullname}. All their sessions were signed out. {msg}", "success" if ok else "warning")
    return redirect(url_for("management"))


@app.post("/management/user/<int:uid>/delete")
@super_required
def delete_user(uid):
    u = db.session.get(User, uid) or abort(404)
    if is_super(u) or u.id == current_user.id:
        flash("The Super Admin account cannot be deleted.", "error")
        return redirect(url_for("management"))
    if request.form.get("confirm_email", "").strip().lower() != u.email:
        flash("Deletion cancelled - the confirmation email did not match.", "error")
        return redirect(url_for("management"))
    email = u.email
    ids = [a.id for a in Assessment.query.filter_by(user_id=u.id).all()]
    if ids:
        Action.query.filter(Action.assessment_id.in_(ids)).delete(synchronize_session=False)
        for a in Assessment.query.filter(Assessment.id.in_(ids)).all():
            db.session.delete(a)
    ThreatCheck.query.filter_by(user_id=u.id).delete(synchronize_session=False)
    Audit.query.filter_by(user_id=u.id).update({"user_id": None}, synchronize_session=False)
    AdminInvite.query.filter_by(created_by=u.id).update({"created_by": current_user.id}, synchronize_session=False)
    db.session.delete(u)
    db.session.commit()
    audit("USER_DELETE", "SUCCESS", f"{email} and {len(ids)} assessment(s) deleted")
    flash(f"{email} and their data were permanently deleted.", "success")
    return redirect(url_for("management"))


@app.post("/management/invite/<int:iid>/revoke")
@admin_required
def revoke_invite(iid):
    inv = db.session.get(AdminInvite, iid) or abort(404)
    inv.revoked = True
    db.session.commit()
    audit("INVITE_REVOKE", "SUCCESS", inv.email)
    flash("Invitation revoked.", "success")
    return redirect(url_for("management"))


@app.route("/invite/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def accept_invite(token):
    try:
        data = invite_serializer().loads(token, max_age=172800)
        inv = db.session.get(AdminInvite, int(data["id"]))
    except (BadSignature, SignatureExpired, ValueError, KeyError, TypeError):
        return error_page(400, "Invitation invalid", "This invitation is invalid or has expired.")
    if (not inv or inv.revoked or inv.accepted_at or aware(inv.expires_at) < utcnow()
            or not secrets.compare_digest(inv.token_hash, hashlib.sha256(data["raw"].encode()).hexdigest())):
        return error_page(400, "Invitation unavailable", "This invitation has expired, was revoked or was already used.")
    form = NewPasswordForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=inv.email).first():
            return error_page(400, "Account exists", "An account already exists for this email.")
        u = User(fullname=inv.fullname, email=inv.email, organisation=inv.organisation, role=inv.role)
        u.set_password(form.password.data)
        db.session.add(u)
        inv.accepted_at = utcnow()
        db.session.commit()
        audit("INVITE_ACCEPT", "SUCCESS", inv.email, u)
        flash("Account activated. Sign in with your new password.", "success")
        return redirect(url_for("login"))
    return render_template("accept_invite.html", form=form, invite=inv)


with app.app_context():
    db.create_all()
    migrate()
    seed()

if __name__ == "__main__":
    app.run(debug=True)
