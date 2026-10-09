"""Run: python -m unittest discover -s tests -v (requires httpx)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

temporary = tempfile.TemporaryDirectory()
os.environ['DATABASE_URL'] = 'sqlite:///' + str(Path(temporary.name) / 'test.db')
os.environ['APP_ENV'] = 'development'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
import main
from sqlalchemy import insert, select, delete

HEADERS = {'X-App-Request': '1', 'X-App-Version':'3.4.0'}
PASSWORD = 'a-strong-test-password'

class SecurityFlow(unittest.TestCase):
    def setUp(self):
        os.environ.pop('FACULTY_SIGNUP_CODE', None)
        main.initialize_database()
        with main.engine.begin() as db:
            for table in (main.faculty_requests, main.admin_sessions, main.requests, main.sessions, main.limits, main.users):
                db.execute(delete(table))
            db.execute(insert(main.users).values(name='Faculty', email='faculty@example.com', role='faculty',
                password_hash=main.hasher.hash(PASSWORD), created_at=main.now()))
        self.client = TestClient(main.app, headers=HEADERS)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def signup(self, email='student@example.com', student_id='CS001'):
        response = self.client.post('/api/auth/signup', json={
            'name': 'Student', 'email': email, 'student_id': student_id, 'password': PASSWORD, 'role':'student'})
        self.assertEqual(response.status_code, 201, response.text)

    def login(self, email='student@example.com'):
        response = self.client.post('/api/auth/login', json={'email': email, 'password': PASSWORD, 'role':'faculty' if email == 'faculty@example.com' else 'student'})
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def test_complete_flow_and_persistence(self):
        self.signup()
        response = self.login()
        self.assertIn('HttpOnly', response.headers['set-cookie'])
        self.assertNotIn('password_hash', response.json())
        body = {'request_type': 'permission', 'start_date': '2026-09-30', 'arrival_time': '09:30', 'reason': 'Bus delay'}
        response = self.client.post('/api/requests', json=body)
        self.assertEqual(response.status_code, 201, response.text)
        request_id = response.json()['id']
        self.assertEqual(self.client.patch(f'/api/requests/{request_id}', json={'status':'Approved'}).status_code, 403)
        self.signup('other@example.com', 'CS002')
        self.login('other@example.com')
        self.assertEqual(self.client.get('/api/requests?student_id=CS001').json(), [])
        self.login('faculty@example.com')
        self.assertEqual(len(self.client.get('/api/requests').json()), 1)
        self.assertEqual(self.client.post('/api/requests', json=body).status_code, 403)
        result = self.client.patch(f'/api/requests/{request_id}', json={'status':'Approved','remarks':'OK'})
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.json()['reviewed_by'])
        self.assertEqual(self.client.patch(f'/api/requests/{request_id}', json={'status':'Rejected'}).status_code, 409)
        self.login()
        self.assertEqual(self.client.get('/api/requests').json()[0]['status'], 'Approved')
        cookie = self.client.cookies.get(main.COOKIE)
        self.client.post('/api/auth/logout')
        self.client.cookies.set(main.COOKIE, cookie)
        self.assertEqual(self.client.get('/api/auth/me').status_code, 401)
        with TestClient(main.app, headers=HEADERS) as reopened:
            reopened.post('/api/auth/login', json={'email':'student@example.com','password':PASSWORD,'role':'student'})
            self.assertEqual(reopened.get('/api/requests').json()[0]['status'], 'Approved')

    def test_input_and_authentication_protection(self):
        self.assertEqual(self.client.get('/api/requests').status_code, 401)
        self.assertEqual(self.client.post('/api/auth/signup', headers={'X-App-Request':''}, json={}).status_code, 403)
        self.assertEqual(self.client.post('/api/auth/signup', headers={'Origin':'https://attacker.example'}, json={}).status_code, 403)
        data = {'name':'Test','email':'test@example.com','student_id':'CS1','password':PASSWORD,'role':'faculty','staff_id':'STAFF002'}
        self.assertEqual(self.client.post('/api/auth/signup', json=data).status_code, 403)
        self.signup()
        self.assertEqual(self.client.post('/api/auth/login', json={'email':'student@example.com','password':'wrong-password','role':'student'}).status_code, 401)
        self.login()
        invalid = {'request_type':'leave','start_date':'2026-10-02','end_date':'2026-10-01','reason':'Test'}
        self.assertEqual(self.client.post('/api/requests', json=invalid).status_code, 422)
        invalid.update(end_date='2026-10-03', student_id='CS002')
        self.assertEqual(self.client.post('/api/requests', json=invalid).status_code, 422)
        invalid.pop('student_id')
        self.assertEqual(self.client.post('/api/requests', json=invalid).status_code, 201)
        with main.engine.connect() as db:
            saved = db.execute(select(main.users.c.password_hash).where(main.users.c.email=='student@example.com')).scalar_one()
            self.assertTrue(saved.startswith('$argon2id$'))
            self.assertNotEqual(saved, PASSWORD)

    def test_role_signup_and_login(self):
        from unittest.mock import patch
        data = {'name':'Teacher', 'email':'teacher@example.com', 'password':PASSWORD, 'role':'faculty', 'staff_id':'STAFF002'}
        with patch.dict(os.environ, {'FACULTY_SIGNUP_CODE':'test-only-invitation-code'}):
            self.assertEqual(self.client.post('/api/auth/signup', json=data).status_code, 403)
            data['invitation_code'] = 'wrong'
            self.assertEqual(self.client.post('/api/auth/signup', json=data).status_code, 403)
            data['invitation_code'] = 'test-only-invitation-code'
            self.assertEqual(self.client.post('/api/auth/signup', json=data).status_code, 201)
        login = {'email':data['email'], 'password':PASSWORD, 'role':'student'}
        self.assertEqual(self.client.post('/api/auth/login', json=login).status_code, 403)
        self.assertEqual(self.client.get('/api/auth/me').status_code, 401)
        login['role'] = 'faculty'
        self.assertEqual(self.client.post('/api/auth/login', json=login).json()['role'], 'faculty')
        self.assertEqual(self.client.get('/api/requests').status_code, 200)
        self.assertEqual(self.client.post('/api/auth/signup', json={
            'name':'Student','email':'new@example.com','password':PASSWORD,'role':'student'}).status_code, 422)

    def test_password_recovery_rotates_code_and_revokes_sessions(self):
        account = {'name':'Student', 'email':'student@example.com', 'student_id':'CS001', 'password':PASSWORD, 'role':'student'}
        signup = self.client.post('/api/auth/signup', json=account).json()
        recovery = signup['recovery_code']
        self.login()
        cookie = self.client.cookies.get(main.COOKIE)
        reset = {'email':account['email'], 'role':'student', 'password':'new-strong-password', 'recovery_code':'wrong'}
        self.assertEqual(self.client.post('/api/auth/reset-password', json=reset).status_code, 400)
        reset['recovery_code'] = recovery
        result = self.client.post('/api/auth/reset-password', json=reset)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertNotEqual(result.json()['recovery_code'], recovery)
        self.assertEqual(self.client.post('/api/auth/reset-password', json=reset).status_code, 400)
        self.client.cookies.set(main.COOKIE, cookie)
        self.assertEqual(self.client.get('/api/auth/me').status_code, 401)
        self.assertEqual(self.client.post('/api/auth/login', json={
            'email':account['email'], 'password':PASSWORD, 'role':'student'}).status_code, 401)
        self.assertEqual(self.client.post('/api/auth/login', json={
            'email':account['email'], 'password':reset['password'], 'role':'student'}).status_code, 200)
        with main.engine.connect() as db:
            stored = db.execute(select(main.users.c.recovery_hash).where(main.users.c.email == account['email'])).scalar_one()
        self.assertNotEqual(stored, result.json()['recovery_code'])

    def test_role_required_cache_and_dashboard_guards(self):
        self.signup()
        payload = {'email':'student@example.com', 'password':PASSWORD}
        self.assertEqual(self.client.post('/api/auth/login', json=payload).status_code, 422)
        payload['role'] = 'faculty'
        self.assertEqual(self.client.post('/api/auth/login', json=payload).status_code, 403)
        self.assertEqual(self.client.get('/pages/faculty-home.html', follow_redirects=False).headers['location'], '/pages/login.html')
        self.login()
        wrong = self.client.get('/pages/faculty-home.html', follow_redirects=False)
        self.assertEqual(wrong.status_code, 303)
        self.assertEqual(wrong.headers['location'], '/pages/student-home.html')
        self.assertEqual(self.client.get('/pages/student-home.html').status_code, 200)
        self.assertEqual(self.client.post('/api/auth/login', json=payload, headers={'X-App-Version':'old'}).status_code, 409)
        self.assertEqual(self.client.post('/api/auth/login', json=payload, headers={'X-App-Version':''}).status_code, 409)
        for url in ['/', '/pages/login.html', '/pages/auth.js', '/api/auth/me']:
            self.assertIn('no-store', self.client.get(url).headers['cache-control'])
        self.login('faculty@example.com')
        self.assertEqual(self.client.get('/pages/student-home.html', follow_redirects=False).headers['location'], '/pages/faculty-home.html')
        self.assertEqual(self.client.get('/pages/faculty-home.html').status_code, 200)

    def test_local_invitation_hash_and_validation_secrets(self):
        from unittest.mock import patch
        import json
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / 'local-settings.json'
            config.write_text(json.dumps({'faculty_invitation_hash':main.hasher.hash('private-test-code')}))
            with patch.object(main, 'BASE', Path(folder)):
                self.assertTrue(main.valid_faculty_code('private-test-code'))
                self.assertFalse(main.valid_faculty_code('wrong'))
        result = self.client.post('/api/auth/signup', json={
            'name':'Test','email':'invalid','password':'private-short','role':'student','student_id':'S1'})
        self.assertEqual(result.status_code, 422)
        self.assertNotIn('private-short', result.text)

    def test_rate_limit(self):
        for attempt in range(10):
            self.assertEqual(self.client.post('/api/auth/login',json={'email':'missing@example.com','password':PASSWORD,'role':'student'}).status_code,401)
        self.assertEqual(self.client.post('/api/auth/login',json={'email':'missing@example.com','password':PASSWORD,'role':'student'}).status_code,429)

    def test_assets_and_headers(self):
        for page in ['login.html','signup.html','common.js','student.js','faculty.js','auth.js','forgot-password.html','style.css']:
            result = self.client.get('/pages/' + page)
            self.assertEqual(result.status_code, 200)
            self.assertIn("script-src 'self'", result.headers['content-security-policy'])
        self.assertEqual(self.client.get('/health').json(), {'status':'ok','version':'3.4.0'})

    def test_faculty_requests_are_private_and_admin_only(self):
        from unittest.mock import patch
        body = {'request_type':'leave', 'start_date':'2026-10-06', 'end_date':'2026-10-07', 'reason':'Personal leave'}
        self.assertEqual(self.client.get('/api/faculty-requests').status_code, 401)
        self.signup()
        self.login()
        self.assertEqual(self.client.post('/api/faculty-requests', json=body).status_code, 403)
        student_request = self.client.post('/api/requests', json=body).json()
        self.login('faculty@example.com')
        faculty_request = self.client.post('/api/faculty-requests', json=body)
        self.assertEqual(faculty_request.status_code, 201, faculty_request.text)
        fid = faculty_request.json()['id']
        self.assertEqual(len(self.client.get('/api/requests').json()), 1)
        self.assertEqual(self.client.get('/api/requests').json()[0]['user_id'], student_request['user_id'])
        self.assertEqual(self.client.get('/api/admin/faculty-requests').status_code, 401)
        self.assertEqual(self.client.patch(f'/api/admin/faculty-requests/{fid}', json={'status':'Approved'}).status_code, 401)
        with main.engine.begin() as db:
            db.execute(insert(main.users).values(name='Second Teacher', email='second@example.com', role='faculty',
                staff_id='F002', password_hash=main.hasher.hash(PASSWORD), created_at=main.now()))
        self.client.post('/api/auth/login', json={'email':'second@example.com','password':PASSWORD,'role':'faculty'})
        self.assertEqual(self.client.get('/api/faculty-requests?user_id=1').json(), [])
        with patch.dict(os.environ, {'ADMIN_ACCESS_KEY':'private-admin-key-for-tests-only'}):
            self.client.post('/api/auth/logout')
            login = self.client.post('/api/admin/login', json={'access_key':'private-admin-key-for-tests-only'})
            self.assertEqual(login.status_code, 200)
            self.assertIn('HttpOnly', login.headers['set-cookie'])
            self.assertEqual(self.client.get('/api/requests').status_code, 401)
            rows = self.client.get('/api/admin/faculty-requests').json()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['faculty_name'], 'Faculty')
            result = self.client.patch(f'/api/admin/faculty-requests/{fid}', json={'status':'Approved','remarks':'Approved by admin'})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()['reviewed_by'], 'Administrator')
            self.assertEqual(self.client.patch(f'/api/admin/faculty-requests/{fid}', json={'status':'Rejected'}).status_code, 409)
            self.assertEqual(self.client.patch('/api/admin/faculty-requests/999', json={'status':'Rejected'}).status_code, 404)
            self.login('faculty@example.com')
            self.assertEqual(self.client.get('/api/faculty-requests').json()[0]['status'], 'Approved')
            self.assertEqual(self.client.get('/api/requests').json()[0]['status'], 'Pending')
            self.client.post('/api/auth/logout')
            self.login()
            self.assertEqual(self.client.get('/api/faculty-requests').status_code, 403)
            self.assertEqual(self.client.get('/api/requests').json()[0]['status'], 'Pending')

    def test_admin_sessions_rotation_logout_and_expiry(self):
        from unittest.mock import patch
        from sqlalchemy import update
        with patch.dict(os.environ, {'ADMIN_ACCESS_KEY':'private-admin-key-for-tests-only'}):
            self.assertEqual(self.client.post('/api/admin/login', json={'access_key':'wrong'}).status_code, 401)
            self.assertEqual(self.client.post('/api/admin/login', headers={'Origin':'https://evil.example'}, json={'access_key':'private-admin-key-for-tests-only'}).status_code, 403)
            self.assertEqual(self.client.get('/pages/admin-home.html', follow_redirects=False).status_code, 303)
            self.client.post('/api/admin/login', json={'access_key':'private-admin-key-for-tests-only'})
            cookie = self.client.cookies.get(main.ADMIN_COOKIE)
            self.assertEqual(self.client.get('/api/admin/me').status_code, 200)
            self.assertEqual(self.client.get('/pages/admin-home.html').status_code, 200)
            with patch.dict(os.environ, {'ADMIN_ACCESS_KEY':'a-different-private-admin-test-key'}):
                self.assertEqual(self.client.get('/api/admin/me').status_code, 401)
            self.client.post('/api/admin/logout')
            self.client.cookies.set(main.ADMIN_COOKIE, cookie)
            self.assertEqual(self.client.get('/api/admin/me').status_code, 401)
            self.client.cookies.clear()
            self.client.post('/api/admin/login', json={'access_key':'private-admin-key-for-tests-only'})
            with main.engine.begin() as db:
                db.execute(update(main.admin_sessions).values(expires_at=0))
            self.assertEqual(self.client.get('/api/admin/me').status_code, 401)

    def test_admin_configuration_and_throttle(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {'ADMIN_ACCESS_KEY':'short'}):
            self.assertEqual(self.client.post('/api/admin/login', json={'access_key':'short'}).status_code, 503)
        with main.engine.begin() as db:
            db.execute(delete(main.limits))
        with patch.dict(os.environ, {'ADMIN_ACCESS_KEY':'private-admin-key-for-tests-only'}):
            for _ in range(10):
                self.assertEqual(self.client.post('/api/admin/login', json={'access_key':'wrong'}).status_code, 401)
            self.assertEqual(self.client.post('/api/admin/login', json={'access_key':'wrong'}).status_code, 429)

    def test_faculty_permission_validation_and_dashboard(self):
        self.assertEqual(self.client.get('/pages/faculty-leave-home.html', follow_redirects=False).headers['location'], '/pages/faculty-leave-login.html')
        self.signup(); self.login()
        self.assertEqual(self.client.get('/pages/faculty-leave-home.html', follow_redirects=False).headers['location'], '/pages/student-home.html')
        self.login('faculty@example.com')
        self.assertEqual(self.client.get('/pages/faculty-leave-home.html').status_code, 200)
        body = {'request_type':'permission', 'start_date':'2026-10-06','arrival_time':'09:30','reason':'Travel delay'}
        self.assertEqual(self.client.post('/api/faculty-requests', json=body).status_code, 201)
        body['end_date'] = '2026-10-07'
        self.assertEqual(self.client.post('/api/faculty-requests', json=body).status_code, 422)
        body.pop('end_date'); body['user_id'] = 99
        self.assertEqual(self.client.post('/api/faculty-requests', json=body).status_code, 422)

    def test_additive_schema_preserves_existing_records(self):
        self.signup(); self.login()
        self.client.post('/api/requests', json={'request_type':'permission','start_date':'2026-10-06','arrival_time':'09:30','reason':'Existing application'})
        main.faculty_requests.drop(main.engine)
        main.admin_sessions.drop(main.engine)
        main.initialize_database()
        main.initialize_database()
        self.assertEqual(self.client.get('/api/auth/me').json()['email'], 'student@example.com')
        self.assertEqual(self.client.get('/api/requests').json()[0]['reason'], 'Existing application')

if __name__ == '__main__':
    unittest.main()
