# First Hour Permission & Leave Approval — 3.3.0

Read **UPDATE-GUIDE.txt** for the existing Render website update and local setup.

- Student Login: submit student permission and leave requests.
- Faculty Login → Faculty Approval: review student requests.
- Faculty Login → Faculty Leave: submit personal faculty requests, using the same faculty account.
- Admin Login: private access key; review faculty requests only.

Faculty applications use a separate table. Students and ordinary faculty sessions cannot access admin APIs. Each faculty member can see only their own applications. Admin decisions are final and recorded with a timestamp. A single shared admin key identifies the reviewer as Administrator.

## Configuration

Production uses `APP_ENV=production`, `DATABASE_URL`, `PUBLIC_URL` (or Render's `RENDER_EXTERNAL_URL`), `FACULTY_SIGNUP_CODE`, and `ADMIN_ACCESS_KEY` (20–256 characters). Store keys only in server configuration. Admin access stays disabled until its key is configured. Existing student/faculty operations still work without the admin key.

Local setup uses `start.bat` and Argon2 hashes in `local-settings.json`. It preserves existing invitation settings and adds the admin key configuration. Existing SQLite data lives in `data/new-project.db`.

## Data and security

Startup uses additive `create_all`; it adds `faculty_applications` and `admin_sessions` without altering existing application/account tables. Passwords use Argon2; recovery codes and session tokens are hashed. Admin cookies are HttpOnly, Secure in production, same-site and expire after an hour. Key rotation invalidates admin sessions. Mutations require same-origin checks and app-version headers. Inline CSS/JS remains blocked by CSP; page styles are external.

Student and faculty email/password accounts retain saved recovery-code password reset. This project does not send email or implement Google OAuth. Request tables refresh every five seconds while visible.

## Tests

Install `httpx` in addition to project requirements and run:

```
python -m unittest discover -s tests -v
```

The tests use a temporary database. They cover the original account/student flows, faculty request isolation, admin authentication/decisions, rate limits, session revocation and preserving old records when adding new tables.
