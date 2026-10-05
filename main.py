import argparse
import getpass
import json
import hashlib
import os
import secrets
import time as clock
from contextlib import asynccontextmanager
from datetime import date, time, datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import FastAPI, Depends, HTTPException, Request, Response, Query
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Text, ForeignKey, CheckConstraint, select, insert, update, delete, event, text
from sqlalchemy.exc import IntegrityError
from starlette.middleware.trustedhost import TrustedHostMiddleware

BASE = Path(__file__).resolve().parent
APP_VERSION = '3.3.0'
DATA = BASE / 'data'
DATA.mkdir(exist_ok=True)
PRODUCTION = os.getenv('APP_ENV', 'development') == 'production'
PUBLIC_URL = os.getenv('PUBLIC_URL', os.getenv('RENDER_EXTERNAL_URL', '')).rstrip('/')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///' + str(DATA / 'new-project.db'))
if DATABASE_URL.startswith(('postgres://', 'postgresql://')):
    DATABASE_URL = 'postgresql+psycopg://' + DATABASE_URL.split('://', 1)[1]
if PRODUCTION and (not PUBLIC_URL.startswith('https://') or not DATABASE_URL.startswith('postgresql')):
    raise RuntimeError('Production requires an HTTPS PUBLIC_URL and PostgreSQL DATABASE_URL.')
engine = create_engine(DATABASE_URL, pool_pre_ping=True,
    connect_args={'check_same_thread': False, 'timeout': 15} if DATABASE_URL.startswith('sqlite') else {})
if engine.dialect.name == 'sqlite':
    @event.listens_for(engine, 'connect')
    def sqlite_settings(connection, record):
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA journal_mode=WAL')
metadata = MetaData()
users = Table('users', metadata,
    Column('id', Integer, primary_key=True),
    Column('name', String(100), nullable=False),
    Column('email', String(254), nullable=False, unique=True),
    Column('student_id', String(50), unique=True),
    Column('staff_id', String(50), unique=True),
    Column('recovery_hash', String(64)),
    Column('password_hash', Text, nullable=False),
    Column('role', String(10), nullable=False),
    Column('created_at', String(40), nullable=False),
    CheckConstraint("role IN ('student','faculty')"))
sessions = Table('sessions', metadata,
    Column('token_hash', String(64), primary_key=True),
    Column('user_id', ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
    Column('expires_at', Integer, nullable=False, index=True))
requests = Table('applications', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', ForeignKey('users.id'), nullable=False, index=True),
    Column('request_type', String(10), nullable=False),
    Column('start_date', String(10), nullable=False),
    Column('end_date', String(10)),
    Column('arrival_time', String(20)),
    Column('reason', Text, nullable=False),
    Column('status', String(10), nullable=False, default='Pending'),
    Column('remarks', Text, nullable=False, default=''),
    Column('created_at', String(40), nullable=False),
    Column('reviewed_at', String(40)),
    Column('reviewed_by', ForeignKey('users.id')),
    CheckConstraint("status IN ('Pending','Approved','Rejected')"),
    CheckConstraint("request_type IN ('permission','leave')"),
    CheckConstraint("(request_type='leave' AND end_date IS NOT NULL AND end_date>=start_date AND arrival_time IS NULL) OR (request_type='permission' AND arrival_time IS NOT NULL AND end_date IS NULL)"))
# New tables are additive: existing student accounts and applications are untouched.
faculty_requests = Table('faculty_applications', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', ForeignKey('users.id'), nullable=False, index=True),
    Column('request_type', String(10), nullable=False),
    Column('start_date', String(10), nullable=False),
    Column('end_date', String(10)),
    Column('arrival_time', String(20)),
    Column('reason', Text, nullable=False),
    Column('status', String(10), nullable=False, default='Pending'),
    Column('remarks', Text, nullable=False, default=''),
    Column('created_at', String(40), nullable=False),
    Column('reviewed_at', String(40)),
    Column('reviewed_by', String(30)),
    CheckConstraint("status IN ('Pending','Approved','Rejected')"),
    CheckConstraint("request_type IN ('permission','leave')"),
    CheckConstraint("(request_type='leave' AND end_date IS NOT NULL AND end_date>=start_date AND arrival_time IS NULL) OR (request_type='permission' AND arrival_time IS NOT NULL AND end_date IS NULL)"))
admin_sessions = Table('admin_sessions', metadata,
    Column('token_hash', String(64), primary_key=True),
    Column('key_fingerprint', String(64), nullable=False),
    Column('expires_at', Integer, nullable=False, index=True))
limits = Table('rate_limits', metadata,
    Column('key', String(64), primary_key=True),
    Column('count', Integer, nullable=False),
    Column('expires_at', Integer, nullable=False, index=True))
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(24))
COOKIE = '__Host-leave_new_v32' if PRODUCTION else 'leave_new_v32'
SESSION_SECONDS = 8 * 60 * 60
ADMIN_COOKIE = '__Host-leave_admin' if PRODUCTION else 'leave_admin'
ADMIN_SESSION_SECONDS = 60 * 60

def now():
    return datetime.now(timezone.utc).isoformat()

def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def initialize_database():
    metadata.create_all(engine)

@asynccontextmanager
async def lifespan(app):
    initialize_database()
    yield

app = FastAPI(title='Permission and Leave Approval', lifespan=lifespan,
    docs_url=None if PRODUCTION else '/docs', redoc_url=None)
hosts = [urlsplit(PUBLIC_URL).hostname] if PRODUCTION else ['localhost', '127.0.0.1', 'testserver']
app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

@app.middleware('http')
async def protect_requests(request: Request, call_next):
    if request.method in {'POST', 'PATCH', 'DELETE', 'PUT'}:
        origin = request.headers.get('origin')
        expected = PUBLIC_URL if PRODUCTION else str(request.base_url).rstrip('/')
        if request.headers.get('x-app-request') != '1' or (origin and origin != expected):
            return JSONResponse({'detail': 'Request origin could not be verified.'}, status_code=403)
    if request.method in {'POST', 'PATCH', 'DELETE', 'PUT'} and request.headers.get('x-app-version') != APP_VERSION:
        return JSONResponse({'detail': 'This page is out of date. Press Ctrl+F5 and try again.'}, status_code=409)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-App-Version'] = APP_VERSION
    if PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

def throttle(scope, identity, maximum, period=900):
    current = int(clock.time())
    key = token_hash(f'{scope}:{identity}:{current // period}')
    if engine.dialect.name == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert as upsert
    else:
        from sqlalchemy.dialects.sqlite import insert as upsert
    statement = upsert(limits).values(key=key, count=1, expires_at=current + period)
    statement = statement.on_conflict_do_update(index_elements=[limits.c.key], set_={'count': limits.c.count + 1}).returning(limits.c.count)
    with engine.begin() as db:
        db.execute(delete(limits).where(limits.c.expires_at < current))
        count = db.execute(statement).scalar_one()
    if count > maximum:
        raise HTTPException(429, 'Too many attempts. Please try again later.', headers={'Retry-After': str(period)})

def current_user(request: Request):
    token = request.cookies.get(COOKIE, '')
    with engine.connect() as db:
        user = db.execute(select(users).join(sessions, users.c.id == sessions.c.user_id).where(
            sessions.c.token_hash == token_hash(token), sessions.c.expires_at > int(clock.time()))).mappings().first()
    if not user:
        raise HTTPException(401, 'Please log in.')
    return dict(user)

def public_user(user):
    return {key: user[key] for key in ('id', 'name', 'email', 'student_id', 'staff_id', 'role')}

def valid_faculty_code(code):
    invitation = os.getenv('FACULTY_SIGNUP_CODE', '')
    if invitation:
        return len(invitation) >= 16 and secrets.compare_digest(code.encode(), invitation.encode())
    if PRODUCTION:
        return False
    try:
        config = json.loads((BASE / 'local-settings.json').read_text())
        return hasher.verify(config['faculty_invitation_hash'], code)
    except (OSError, ValueError, KeyError, VerificationError, InvalidHashError):
        return False

@app.exception_handler(RequestValidationError)
async def invalid_input(request, exc):
    # Never echo submitted passwords or recovery codes in validation errors.
    messages = ['.'.join(str(part) for part in error['loc'][1:]) + ': ' + error['msg'] for error in exc.errors()]
    return JSONResponse({'detail': '; '.join(messages)}, status_code=422)

class Signup(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    role: Literal['student', 'faculty']
    invitation_code: str = Field(default='', max_length=256)
    student_id: str | None = Field(default=None, min_length=1, max_length=50, pattern=r'^[A-Za-z0-9_-]+$')
    staff_id: str | None = Field(default=None, min_length=1, max_length=50, pattern=r'^[A-Za-z0-9_-]+$')
    password: str = Field(min_length=12, max_length=128)
    @field_validator('name')
    @classmethod
    def clean_name(cls, value):
        if not value.strip():
            raise ValueError('Name is required')
        return value.strip()
    @field_validator('email')
    @classmethod
    def clean_email(cls, value):
        return str(value).lower()
    @field_validator('student_id', 'staff_id')
    @classmethod
    def clean_id(cls, value):
        return value.upper() if value else None

    @model_validator(mode='after')
    def require_student_id(self):
        if self.role == 'student' and not self.student_id:
            raise ValueError('Register number is required for students.')
        if self.role == 'faculty' and not self.staff_id:
            raise ValueError('Staff ID is required for faculty.')
        return self

class Login(BaseModel):
    model_config = ConfigDict(extra='forbid')
    role: Literal['student', 'faculty']
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class Application(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    request_type: Literal['permission', 'leave']
    start_date: date
    end_date: date | None = None
    arrival_time: time | None = None
    reason: str = Field(min_length=1, max_length=2000)
    @model_validator(mode='after')
    def check_dates(self):
        if self.request_type == 'leave':
            if self.end_date is None or self.end_date < self.start_date or self.arrival_time is not None:
                raise ValueError('Leave requires valid start and end dates, with no arrival time.')
        elif self.arrival_time is None or self.end_date is not None:
            raise ValueError('Permission requires an arrival time, with no leave end date.')
        return self

class Decision(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    status: Literal['Approved', 'Rejected']
    remarks: str = Field(default='', max_length=2000)

@app.post('/api/auth/signup', status_code=201)
def signup(data: Signup, request: Request):
    throttle('signup', request.client.host, 10)
    if data.role == 'faculty':
        if not valid_faculty_code(data.invitation_code):
            raise HTTPException(403, 'A valid faculty invitation code is required. Contact the administrator.')
    recovery = secrets.token_urlsafe(32)
    try:
        with engine.begin() as db:
            db.execute(insert(users).values(name=data.name, email=data.email, student_id=data.student_id if data.role == 'student' else None,
                staff_id=data.staff_id if data.role == 'faculty' else None, recovery_hash=token_hash(recovery),
                password_hash=hasher.hash(data.password), role=data.role, created_at=now()))
    except IntegrityError:
        raise HTTPException(409, 'An account with these details already exists. Contact your administrator if needed.')
    return {'message': 'Account created. Save your recovery code before logging in.', 'role': data.role, 'recovery_code': recovery}

@app.post('/api/auth/login')
def login(data: Login, request: Request, response: Response):
    email = str(data.email).lower()
    throttle('login-ip', request.client.host, 60)
    throttle('login-email', email, 10)
    with engine.connect() as db:
        user = db.execute(select(users).where(users.c.email == email)).mappings().first()
    try:
        valid = hasher.verify(user['password_hash'] if user else DUMMY_HASH, data.password)
    except (VerificationError, InvalidHashError):
        valid = False
    if not valid or not user:
        raise HTTPException(401, 'Incorrect email or password.')
    if data.role != user['role']:
        raise HTTPException(403, 'Selected role does not match this account. Choose the correct role.')
    token = secrets.token_urlsafe(32)
    with engine.begin() as db:
        db.execute(delete(sessions).where(sessions.c.expires_at < int(clock.time())))
        db.execute(delete(sessions).where(sessions.c.token_hash == token_hash(request.cookies.get(COOKIE, ''))))
        db.execute(insert(sessions).values(token_hash=token_hash(token), user_id=user['id'], expires_at=int(clock.time()) + SESSION_SECONDS))
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True, secure=PRODUCTION, samesite='lax', path='/')
    return public_user(user)

class PasswordReset(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email: EmailStr
    role: Literal['student', 'faculty']
    recovery_code: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=12, max_length=128)

@app.post('/api/auth/reset-password')
def reset_password(data: PasswordReset, request: Request, response: Response):
    email = str(data.email).lower()
    throttle('reset-ip', request.client.host, 20)
    throttle('reset-account', email, 5)
    new_recovery = secrets.token_urlsafe(32)
    password_hash = hasher.hash(data.password)
    with engine.begin() as db:
        user_id = db.execute(update(users).where(users.c.email == email,
            users.c.role == data.role, users.c.recovery_hash == token_hash(data.recovery_code.strip())).values(
            password_hash=password_hash, recovery_hash=token_hash(new_recovery)).returning(users.c.id)).scalar_one_or_none()
        if user_id is None:
            raise HTTPException(400, 'Email, role or recovery code is incorrect.')
        db.execute(delete(sessions).where(sessions.c.user_id == user_id))
    response.delete_cookie(COOKIE, path='/', secure=PRODUCTION, httponly=True, samesite='lax')
    return {'message':'Password changed. Save your NEW recovery code; the previous code no longer works.',
        'role': data.role, 'recovery_code':new_recovery}

@app.get('/api/auth/me')
def me(user=Depends(current_user)):
    return public_user(user)

@app.post('/api/auth/logout')
def logout(request: Request, response: Response):
    with engine.begin() as db:
        db.execute(delete(sessions).where(sessions.c.token_hash == token_hash(request.cookies.get(COOKIE, ''))))
    response.delete_cookie(COOKIE, path='/', secure=PRODUCTION, httponly=True, samesite='lax')
    return {'message': 'Logged out.'}

@app.post('/api/requests', status_code=201)
def create_request(data: Application, user=Depends(current_user)):
    if user['role'] != 'student':
        raise HTTPException(403, 'Only students can submit requests.')
    throttle('submit', str(user['id']), 30, 3600)
    with engine.begin() as db:
        result = db.execute(insert(requests).values(user_id=user['id'], **data.model_dump(mode='json'), status='Pending', remarks='', created_at=now()))
        row = db.execute(select(requests).where(requests.c.id == result.inserted_primary_key[0])).mappings().one()
    return dict(row)

@app.get('/api/requests')
def list_requests(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=200), user=Depends(current_user)):
    query = select(requests, users.c.name.label('student_name'), users.c.student_id).join(users, requests.c.user_id == users.c.id)
    if user['role'] == 'student':
        query = query.where(requests.c.user_id == user['id'])
    with engine.connect() as db:
        rows = db.execute(query.order_by(requests.c.id.desc()).offset(offset).limit(limit)).mappings().all()
    return [dict(row) for row in rows]

@app.patch('/api/requests/{request_id}')
def decide_request(request_id: int, data: Decision, user=Depends(current_user)):
    if user['role'] != 'faculty':
        raise HTTPException(403, 'Only faculty can review requests.')
    with engine.begin() as db:
        result = db.execute(update(requests).where(requests.c.id == request_id, requests.c.status == 'Pending').values(
            status=data.status, remarks=data.remarks, reviewed_at=now(), reviewed_by=user['id']))
        if not result.rowcount:
            exists = db.execute(select(requests.c.id).where(requests.c.id == request_id)).first()
            raise HTTPException(409 if exists else 404, 'Already reviewed.' if exists else 'Request not found.')
        row = db.execute(select(requests).where(requests.c.id == request_id)).mappings().one()
    return dict(row)

def admin_key_configuration():
    key = os.getenv('ADMIN_ACCESS_KEY', '')
    if key:
        return ('plain', key) if 8 <= len(key) <= 10 else None
    if not PRODUCTION:
        try:
            value = json.loads((BASE / 'local-settings.json').read_text())['admin_access_hash']
            if value.startswith('$argon2id$'):
                return ('hash', value)
        except (OSError, ValueError, KeyError, AttributeError):
            pass
    return None

def current_admin(request: Request):
    config = admin_key_configuration()
    if not config:
        raise HTTPException(401, 'Please log in as admin.')
    with engine.connect() as db:
        session = db.execute(select(admin_sessions.c.token_hash).where(
            admin_sessions.c.token_hash == token_hash(request.cookies.get(ADMIN_COOKIE, '')),
            admin_sessions.c.key_fingerprint == token_hash(config[1]),
            admin_sessions.c.expires_at > int(clock.time()))).first()
    if not session:
        raise HTTPException(401, 'Admin session expired. Please log in again.')
    return {'role': 'admin', 'name': 'Administrator'}

class AdminLogin(BaseModel):
    model_config = ConfigDict(extra='forbid')
    access_key: str = Field(min_length=1, max_length=256)

@app.post('/api/admin/login')
def admin_login(data: AdminLogin, request: Request, response: Response):
    throttle('admin-login', request.client.host, 10)
    config = admin_key_configuration()
    if not config:
        raise HTTPException(503, 'Admin access is not configured. Set ADMIN_ACCESS_KEY on the server.')
    try:
        valid = (secrets.compare_digest(data.access_key.encode(), config[1].encode())
                 if config[0] == 'plain' else hasher.verify(config[1], data.access_key))
    except (VerificationError, InvalidHashError):
        valid = False
    if not valid:
        raise HTTPException(401, 'Incorrect admin access key.')
    token = secrets.token_urlsafe(32)
    with engine.begin() as db:
        db.execute(delete(admin_sessions).where(admin_sessions.c.expires_at < int(clock.time())))
        db.execute(delete(admin_sessions).where(admin_sessions.c.token_hash == token_hash(request.cookies.get(ADMIN_COOKIE, ''))))
        db.execute(insert(admin_sessions).values(token_hash=token_hash(token),
            key_fingerprint=token_hash(config[1]), expires_at=int(clock.time()) + ADMIN_SESSION_SECONDS))
    response.set_cookie(ADMIN_COOKIE, token, max_age=ADMIN_SESSION_SECONDS,
        httponly=True, secure=PRODUCTION, samesite='lax', path='/')
    return {'role': 'admin'}

@app.get('/api/admin/me')
def admin_me(admin=Depends(current_admin)):
    return admin

@app.post('/api/admin/logout')
def admin_logout(request: Request, response: Response):
    with engine.begin() as db:
        db.execute(delete(admin_sessions).where(admin_sessions.c.token_hash == token_hash(request.cookies.get(ADMIN_COOKIE, ''))))
    response.delete_cookie(ADMIN_COOKIE, path='/', secure=PRODUCTION, httponly=True, samesite='lax')
    return {'message': 'Logged out.'}

@app.post('/api/faculty-requests', status_code=201)
def create_faculty_request(data: Application, user=Depends(current_user)):
    if user['role'] != 'faculty':
        raise HTTPException(403, 'Only faculty can submit faculty applications.')
    throttle('faculty-submit', str(user['id']), 30, 3600)
    with engine.begin() as db:
        result = db.execute(insert(faculty_requests).values(user_id=user['id'],
            **data.model_dump(mode='json'), status='Pending', remarks='', created_at=now()))
        row = db.execute(select(faculty_requests).where(faculty_requests.c.id == result.inserted_primary_key[0])).mappings().one()
    return dict(row)

@app.get('/api/faculty-requests')
def own_faculty_requests(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=200), user=Depends(current_user)):
    if user['role'] != 'faculty':
        raise HTTPException(403, 'Only faculty can view their faculty applications.')
    with engine.connect() as db:
        rows = db.execute(select(faculty_requests).where(faculty_requests.c.user_id == user['id'])
            .order_by(faculty_requests.c.id.desc()).offset(offset).limit(limit)).mappings().all()
    return [dict(row) for row in rows]

@app.get('/api/admin/faculty-requests')
def admin_faculty_requests(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=200), admin=Depends(current_admin)):
    with engine.connect() as db:
        rows = db.execute(select(faculty_requests, users.c.name.label('faculty_name'), users.c.staff_id)
            .join(users, faculty_requests.c.user_id == users.c.id)
            .order_by(faculty_requests.c.id.desc()).offset(offset).limit(limit)).mappings().all()
    return [dict(row) for row in rows]

@app.patch('/api/admin/faculty-requests/{request_id}')
def admin_decide_faculty_request(request_id: int, data: Decision, admin=Depends(current_admin)):
    with engine.begin() as db:
        result = db.execute(update(faculty_requests).where(faculty_requests.c.id == request_id,
            faculty_requests.c.status == 'Pending').values(status=data.status, remarks=data.remarks,
            reviewed_at=now(), reviewed_by='Administrator'))
        if not result.rowcount:
            exists = db.execute(select(faculty_requests.c.id).where(faculty_requests.c.id == request_id)).first()
            raise HTTPException(409 if exists else 404, 'Already reviewed.' if exists else 'Request not found.')
        row = db.execute(select(faculty_requests).where(faculty_requests.c.id == request_id)).mappings().one()
    return dict(row)

@app.get('/pages/faculty-leave-home.html')
def faculty_leave_page(request: Request):
    try:
        user = current_user(request)
    except HTTPException:
        return RedirectResponse('/pages/faculty-leave-login.html', status_code=303)
    if user['role'] != 'faculty':
        return RedirectResponse('/pages/student-home.html', status_code=303)
    return FileResponse(BASE / 'pages' / 'faculty-leave-home.html')

@app.get('/pages/admin-home.html')
def admin_page(request: Request):
    try:
        current_admin(request)
    except HTTPException:
        return RedirectResponse('/pages/admin-login.html', status_code=303)
    return FileResponse(BASE / 'pages' / 'admin-home.html')

@app.get('/health')
def health():
    return {'status': 'ok', 'version': APP_VERSION}

@app.get('/')
def home():
    return RedirectResponse('/pages/home.html')
@app.get('/pages/student-home.html')
def student_page(request: Request):
    return dashboard_page(request, 'student')

@app.get('/pages/faculty-home.html')
def faculty_page(request: Request):
    return dashboard_page(request, 'faculty')

def dashboard_page(request, role):
    try:
        user = current_user(request)
    except HTTPException:
        return RedirectResponse('/pages/login.html', status_code=303)
    if user['role'] != role:
        return RedirectResponse('/pages/' + user['role'] + '-home.html', status_code=303)
    return FileResponse(BASE / 'pages' / (role + '-home.html'))

app.mount('/pages', StaticFiles(directory=BASE / 'pages'), name='pages')

def manage_accounts():
    parser = argparse.ArgumentParser(description='Server-owner account management')
    parser.add_argument('command', choices=['create-faculty', 'reset-password'])
    parser.add_argument('--email', required=True)
    parser.add_argument('--name')
    parser.add_argument('--staff-id')
    args = parser.parse_args()
    from pydantic import TypeAdapter
    email = str(TypeAdapter(EmailStr).validate_python(args.email)).lower()
    if args.command == 'create-faculty' and (not args.name or not args.name.strip() or len(args.name)>100):
        parser.error('--name is required (1–100 characters).')
    if args.command == 'create-faculty' and not args.staff_id:
        parser.error('--staff-id is required.')
    recovery = secrets.token_urlsafe(32)
    password = getpass.getpass('Password (12–128 characters): ')
    if not 12 <= len(password) <= 128 or password != getpass.getpass('Confirm password: '):
        parser.error('Passwords must match and contain 12–128 characters.')
    initialize_database()
    try:
        with engine.begin() as db:
            if args.command == 'create-faculty':
                db.execute(insert(users).values(name=args.name.strip(), email=email, student_id=None, staff_id=args.staff_id.upper(), recovery_hash=token_hash(recovery),
                    password_hash=hasher.hash(password), role='faculty', created_at=now()))
            else:
                user_id = db.execute(select(users.c.id).where(users.c.email == email)).scalar_one_or_none()
                if user_id is None:
                    parser.error('Account not found.')
                db.execute(update(users).where(users.c.id == user_id).values(password_hash=hasher.hash(password), recovery_hash=token_hash(recovery)))
                db.execute(delete(sessions).where(sessions.c.user_id == user_id))
    except IntegrityError:
        parser.error('An account with this email already exists.')
    print('Account updated successfully. Give the account owner this recovery code privately:')
    print(recovery)

if __name__ == '__main__':
    manage_accounts()
