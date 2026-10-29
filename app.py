import json, os
from datetime import datetime, timezone, timedelta
from functools import wraps
from io import BytesIO
from pathlib import Path
from flask import Flask, render_template, redirect, url_for, flash, request, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from config import Config

app=Flask(__name__);app.config.from_object(Config)
db=SQLAlchemy(app);csrf=CSRFProtect(app);limiter=Limiter(key_func=get_remote_address,app=app,storage_uri='memory://')
login_manager=LoginManager(app);login_manager.login_view='login';login_manager.login_message='Please sign in to access that page.';login_manager.login_message_category='warning';login_manager.session_protection='strong'
CORE=['Govern','Identify','Protect','Detect','Respond','Recover'];WEIGHTS={'Govern':.20,'Identify':.15,'Protect':.20,'Detect':.15,'Respond':.15,'Recover':.15}

class User(UserMixin,db.Model):
 id=db.Column(db.Integer,primary_key=True);fullname=db.Column(db.String(100),nullable=False);email=db.Column(db.String(255),unique=True,nullable=False,index=True);password_hash=db.Column(db.String(255),nullable=False);organisation=db.Column(db.String(150),nullable=False);role=db.Column(db.String(30),nullable=False,default='Assessor');active=db.Column(db.Boolean,default=True,nullable=False);failed_attempts=db.Column(db.Integer,default=0,nullable=False);locked_until=db.Column(db.DateTime(timezone=True));created_at=db.Column(db.DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
 @property
 def is_active(self):return self.active
 def set_password(self,p):self.password_hash=generate_password_hash(p,method='scrypt')
 def check_password(self,p):return check_password_hash(self.password_hash,p)

class Question(db.Model):
 id=db.Column(db.Integer,primary_key=True);code=db.Column(db.String(10),unique=True,nullable=False);function=db.Column(db.String(30),nullable=False);text=db.Column(db.Text,nullable=False);order=db.Column(db.Integer,nullable=False)
class Assessment(db.Model):
 id=db.Column(db.Integer,primary_key=True);user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False);organisation=db.Column(db.String(150),nullable=False);status=db.Column(db.String(20),default='Draft');overall_score=db.Column(db.Float);readiness=db.Column(db.String(30));created_at=db.Column(db.DateTime(timezone=True),default=lambda:datetime.now(timezone.utc));submitted_at=db.Column(db.DateTime(timezone=True));user=db.relationship('User');answers=db.relationship('Answer',cascade='all,delete-orphan',lazy=True)
class Answer(db.Model):
 id=db.Column(db.Integer,primary_key=True);assessment_id=db.Column(db.Integer,db.ForeignKey('assessment.id'),nullable=False);question_id=db.Column(db.Integer,db.ForeignKey('question.id'),nullable=False);value=db.Column(db.Integer);is_na=db.Column(db.Boolean,default=False);note=db.Column(db.String(500));question=db.relationship('Question');__table_args__=(db.UniqueConstraint('assessment_id','question_id'),)
class Audit(db.Model):
 id=db.Column(db.Integer,primary_key=True);user_id=db.Column(db.Integer,db.ForeignKey('user.id'));event=db.Column(db.String(50),nullable=False);outcome=db.Column(db.String(20),nullable=False);details=db.Column(db.String(255));created_at=db.Column(db.DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
@login_manager.user_loader
def load_user(uid):return db.session.get(User,int(uid))

class LoginForm(FlaskForm):
 email=StringField('Email address',validators=[DataRequired(),Email(),Length(max=255)])
 password=PasswordField('Password',validators=[DataRequired(),Length(min=8,max=128)])
 remember=BooleanField('Keep me signed in')
 submit=SubmitField('Sign in securely')
class SignupForm(FlaskForm):
 fullname=StringField('Full name',validators=[DataRequired(),Length(min=2,max=100)])
 email=StringField('Email address',validators=[DataRequired(),Email(),Length(max=255)])
 organisation=StringField('Bank / organisation',validators=[DataRequired(),Length(min=2,max=150)])
 role=SelectField('Role',choices=[('Assessor','Assessor'),('Organisation Manager','Organisation Manager')],validators=[DataRequired()])
 password=PasswordField('Password',validators=[DataRequired(),Length(min=12,max=128)])
 confirm=PasswordField('Confirm password',validators=[DataRequired(),EqualTo('password')])
 terms=BooleanField('I confirm this is fictional academic data',validators=[DataRequired()])
 submit=SubmitField('Create secure account')
 def validate_email(self,f):
  if User.query.filter_by(email=f.data.strip().lower()).first():raise ValidationError('An account with this email already exists.')

@app.after_request
def headers(r):
 r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Referrer-Policy']='strict-origin-when-cross-origin';r.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()';r.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'";r.headers['Cache-Control']='no-store';return r

def audit(event,outcome,details='',user=None):db.session.add(Audit(user_id=(user or current_user).id if (user or current_user.is_authenticated) else None,event=event,outcome=outcome,details=details));db.session.commit()
def owned(a):
 if a.user_id!=current_user.id:abort(403)
def level(s):return 'Critical' if s<40 else 'Weak' if s<60 else 'Developing' if s<75 else 'Good' if s<90 else 'Strong'
def seed():
 if Question.query.count():return
 data=json.loads((Path(__file__).parent/'questions.json').read_text())
 for i,x in enumerate(data):db.session.add(Question(code=x['code'],function=x['function'],text=x['text'],order=i))
 db.session.commit()

@app.route('/',methods=['GET','POST'])
@app.route('/login',methods=['GET','POST'])
@limiter.limit('10 per minute')
def login():
 if current_user.is_authenticated:return redirect(url_for('dashboard'))
 f=LoginForm()
 if f.validate_on_submit():
  u=User.query.filter_by(email=f.email.data.strip().lower()).first()
  if u and u.locked_until and u.locked_until>datetime.now(timezone.utc):flash('This account is temporarily locked. Try again later.','error');return render_template('login.html',form=f),429
  if u and u.is_active and u.check_password(f.password.data):
   u.failed_attempts=0;u.locked_until=None;db.session.commit();session.clear();session.permanent=True;login_user(u,remember=f.remember.data,fresh=True);audit('LOGIN','SUCCESS','Authenticated session created',u);return redirect(url_for('dashboard'))
  if u:
   u.failed_attempts+=1
   if u.failed_attempts>=5:u.locked_until=datetime.now(timezone.utc)+timedelta(minutes=15)
   db.session.commit()
  audit('LOGIN','FAILED','Invalid credentials',u);flash('The email address or password is incorrect.','error')
 return render_template('login.html',form=f)

@app.route('/signup',methods=['GET','POST'])
@limiter.limit('5 per hour')
def signup():
 if current_user.is_authenticated:return redirect(url_for('dashboard'))
 f=SignupForm()
 if f.validate_on_submit():
  u=User(fullname=f.fullname.data.strip(),email=f.email.data.strip().lower(),organisation=f.organisation.data.strip(),role=f.role.data);u.set_password(f.password.data);db.session.add(u);db.session.commit();audit('SIGNUP','SUCCESS','Self-registration completed',u);flash('Account created. You can now sign in.','success');return redirect(url_for('login'))
 return render_template('signup.html',form=f)

@app.post('/logout')
@login_required
def logout():audit('LOGOUT','SUCCESS','Session ended');logout_user();session.clear();flash('You have been signed out securely.','success');return redirect(url_for('login'))
@app.get('/about')
def about():return render_template('about.html')
@app.get('/dashboard')
@login_required
def dashboard():
 assessments=Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()).all();latest=next((a for a in assessments if a.status=='Completed'),None);return render_template('dashboard.html',assessments=assessments,latest=latest)
@app.post('/assessment/new')
@login_required
def new_assessment():
 a=Assessment(user_id=current_user.id,organisation=current_user.organisation);db.session.add(a);db.session.commit();return redirect(url_for('assessment',aid=a.id,fn='Govern'))
@app.route('/assessment/<int:aid>/<fn>',methods=['GET','POST'])
@login_required
def assessment(aid,fn):
 a=db.session.get(Assessment,aid) or abort(404);owned(a);functions=CORE+['AI Preparedness']
 if fn not in functions:abort(404)
 qs=Question.query.filter_by(function=fn).order_by(Question.order).all();existing={x.question_id:x for x in a.answers}
 if request.method=='POST':
  for q in qs:
   raw=request.form.get(f'q{q.id}');note=request.form.get(f'n{q.id}','').strip();ans=existing.get(q.id) or Answer(assessment_id=a.id,question_id=q.id)
   if raw=='NA':ans.value=None;ans.is_na=True;ans.note=note
   elif raw in '12345':ans.value=int(raw);ans.is_na=False;ans.note=note
   else:continue
   db.session.add(ans)
  db.session.commit();flash(f'{fn} responses saved.','success');action=request.form.get('action');i=functions.index(fn)
  if action=='next' and i<len(functions)-1:return redirect(url_for('assessment',aid=aid,fn=functions[i+1]))
  if action=='submit':return redirect(url_for('review',aid=aid))
 return render_template('assessment.html',a=a,fn=fn,functions=functions,questions=qs,existing=existing)
@app.get('/assessment/<int:aid>/review')
@login_required
def review(aid):a=db.session.get(Assessment,aid) or abort(404);owned(a);return render_template('review.html',a=a,total=Question.query.filter(Question.function!='AI Preparedness').count(),answered=sum(1 for x in a.answers if x.question.function!='AI Preparedness' and (x.value is not None or x.is_na)))
@app.post('/assessment/<int:aid>/submit')
@login_required
def submit(aid):
 a=db.session.get(Assessment,aid) or abort(404);owned(a);core=[q for q in Question.query.filter(Question.function!='AI Preparedness').all()];answered={x.question_id for x in a.answers if x.value is not None or x.is_na}
 if not all(q.id in answered for q in core):flash('Complete all core questions before submitting.','error');return redirect(url_for('review',aid=aid))
 scores={}
 for fn in CORE:
  vals=[(x.value-1)/4*100 for x in a.answers if x.question.function==fn and not x.is_na and x.value]
  scores[fn]=sum(vals)/len(vals) if vals else None
 usable=[f for f in CORE if scores[f] is not None];den=sum(WEIGHTS[f] for f in usable);a.overall_score=round(sum(scores[f]*WEIGHTS[f] for f in usable)/den,1) if den else None;a.readiness=level(a.overall_score) if a.overall_score is not None else 'Not assessable';a.status='Completed';a.submitted_at=datetime.now(timezone.utc);db.session.commit();audit('ASSESSMENT_SUBMIT','SUCCESS',f'Assessment {a.id}');return redirect(url_for('results',aid=aid))
@app.get('/assessment/<int:aid>/results')
@login_required
def results(aid):
 a=db.session.get(Assessment,aid) or abort(404);owned(a);scores={fn:None for fn in CORE}
 for fn in CORE:
  vals=[(x.value-1)/4*100 for x in a.answers if x.question.function==fn and not x.is_na and x.value];scores[fn]=round(sum(vals)/len(vals),1) if vals else None
 risks=[x for x in a.answers if x.value and x.value<=2];return render_template('results.html',a=a,scores=scores,risks=risks)
@app.get('/assessment/<int:aid>/report.pdf')
@login_required
def report(aid):
    a=db.session.get(Assessment,aid) or abort(404);owned(a)
    scores={}
    for fn in CORE:
        vals=[(x.value-1)/4*100 for x in a.answers if x.question.function==fn and not x.is_na and x.value]
        scores[fn]=round(sum(vals)/len(vals),1) if vals else None
    weak=[x for x in a.answers if x.value and x.value<=2]
    badge=('STRONG PREPAREDNESS' if a.readiness=='Strong' else 'GOOD PREPAREDNESS' if a.readiness=='Good' else 'IMPROVEMENT REQUIRED')
    buf=BytesIO();doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=17*mm,leftMargin=17*mm,topMargin=16*mm,bottomMargin=17*mm,title=f'RansomwareShield-SA Assessment {a.id}',author='RansomwareShield-SA Group 7');st=getSampleStyleSheet();brand=colors.HexColor('#6F2CFF');navy=colors.HexColor('#07051B');soft=colors.HexColor('#F3F5FB');story=[]
    logo_path=Path(__file__).parent/'static'/'logo.jpg'
    if logo_path.exists():
        from reportlab.platypus import Image
        logo=Image(str(logo_path),width=42*mm,height=20*mm);logo.hAlign='LEFT';story.append(logo)
    hero=Table([[Paragraph('<font color="#31C8FF"><b>CYBERSECURITY READINESS ASSESSMENT</b></font><br/><font size="22" color="white"><b>RansomwareShield-SA</b></font><br/><font color="#D9DEF2">Official academic prototype report</font>',st['BodyText']),Paragraph(f'<para align="center"><font color="white" size="24"><b>{a.overall_score}%</b></font><br/><font color="#31C8FF"><b>{a.readiness}</b></font></para>',st['BodyText'])]],colWidths=[125*mm,42*mm]);hero.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),navy),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('PADDING',(0,0),(-1,-1),12)]));story += [hero,Spacer(1,10)]
    badge_box=Table([[Paragraph(f'<para align="center"><font color="#6F2CFF"><b>DEMO READINESS BADGE</b></font><br/><font size="17" color="#07051B"><b>{badge}</b></font><br/><font color="#70758F">Project-defined result; not certification or a guarantee against ransomware.</font></para>',st['BodyText'])]],colWidths=[167*mm]);badge_box.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#EEE8FF')),('BOX',(0,0),(-1,-1),1,brand),('PADDING',(0,0),(-1,-1),10)]));story += [badge_box,Spacer(1,12)]
    details=Table([['Organisation',a.organisation],['Assessor',a.user.fullname],['Role',a.user.role],['Assessment ID',f'RSA-{a.id:04d}'],['Completed',a.submitted_at.strftime('%d %B %Y %H:%M UTC') if a.submitted_at else 'Not recorded']],colWidths=[42*mm,125*mm]);details.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),soft),('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#DFE3EF')),('PADDING',(0,0),(-1,-1),7)]));story += [details,Spacer(1,14),Paragraph('Function Scorecard',st['Heading2'])]
    rows=[['NIST CSF Function','Score','Interpretation']]
    for fn,score in scores.items():
        interp='Not assessable' if score is None else ('Strong' if score>=90 else 'Good' if score>=75 else 'Developing' if score>=60 else 'Weak' if score>=40 else 'Critical');rows.append([fn,'N/A' if score is None else f'{score:.1f}%',interp])
    score_table=Table(rows,colWidths=[66*mm,34*mm,67*mm],repeatRows=1);score_table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),brand),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,soft]),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#DFE3EF')),('PADDING',(0,0),(-1,-1),7)]));story += [score_table,Spacer(1,14),Paragraph('Priority Findings and Recommended Actions',st['Heading2'])]
    if weak:
        rr=[['Code','Priority','Finding and recommended action']]
        for x in weak:rr.append([x.question.code,'Critical' if x.value==1 else 'High',Paragraph(f'<b>{x.question.text}</b><br/>Strengthen the {x.question.function} control area, assign an accountable owner, define a target date and retain implementation and testing evidence.',st['BodyText'])])
        rt=Table(rr,colWidths=[20*mm,25*mm,122*mm],repeatRows=1);rt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),navy),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#DFE3EF')),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),6)]));story.append(rt)
    else:story.append(Paragraph('No score-triggered priority findings were generated.',st['BodyText']))
    story += [Spacer(1,14),Paragraph('Management Note',st['Heading2']),Paragraph('This report should be used to prioritise improvement and retesting. It does not certify that the organisation is immune to ransomware or ready for every attack scenario.',st['BodyText']),Spacer(1,12),Paragraph('<font color="#70758F"><b>CONFIDENTIAL DEMONSTRATION REPORT</b> · RansomwareShield-SA Group 7 · Fictional academic assessment information.</font>',st['BodyText'])]
    doc.build(story);buf.seek(0);audit('REPORT_GENERATE','SUCCESS',f'Assessment {a.id}');return send_file(buf,mimetype='application/pdf',as_attachment=True,download_name=f'RansomwareShield-SA-Official-Report-{a.id}.pdf')


with app.app_context():db.create_all();seed()
if __name__=='__main__':app.run(debug=True)
