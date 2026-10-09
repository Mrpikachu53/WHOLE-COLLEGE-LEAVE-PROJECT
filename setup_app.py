"""Configure local invitation and admin keys; only Argon2 hashes are saved."""
import getpass
import json
import os
import sys
from pathlib import Path
from argon2 import PasswordHasher
BASE = Path(__file__).resolve().parent
settings = BASE / 'local-settings.json'
if os.getenv('APP_ENV') == 'production':
    sys.exit('Configure FACULTY_SIGNUP_CODE and ADMIN_ACCESS_KEY in your hosting dashboard.')
try:
    saved = json.loads(settings.read_text()) if settings.exists() else {}
    if not isinstance(saved, dict):
        raise ValueError()
except (ValueError, OSError):
    sys.exit('Cannot read local-settings.json. Keep a backup and check the file before continuing.')
hasher = PasswordHasher()
for field, label, minimum, force in [
    ('faculty_invitation_hash', 'Faculty SIGNUP invitation code', 16, '--change-code'),
    ('admin_access_hash', 'ADMIN LOGIN access key', 8, '--change-admin-key')]:
    if saved.get(field, '').startswith('$argon2id$') and force not in sys.argv:
        print(label + ' is already configured.')
        continue
    print('\nChoose a private ' + label + '. Keep it somewhere safe.')
    print('Typed characters will be hidden. This is normal.')
    while True:
        code = getpass.getpass(f'{label} ({minimum}-128 characters): ')
        if not minimum <= len(code) <= 128:
            print('The key length is not valid. Try again.'); continue
        if code != getpass.getpass('Confirm the same key: '):
            print('Keys do not match. Try again.'); continue
        break
    saved[field] = hasher.hash(code)
    settings.write_text(json.dumps(saved, indent=2))
    try:
        settings.chmod(0o600)
    except OSError:
        pass
print('\nSetup saved. Faculty accounts use their own email and password.')
print('The admin access key is used only on Admin Login.')
