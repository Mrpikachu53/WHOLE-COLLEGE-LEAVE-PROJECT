'use strict';
const page = document.body.dataset.page;
const chosenRole = new URLSearchParams(location.search).get('role');
if (page !== 'login' && ['student', 'faculty'].includes(chosenRole)) get('role').value = chosenRole;
const facultyLeave = document.body.dataset.portal === 'faculty-leave' || new URLSearchParams(location.search).get('portal') === 'faculty-leave';
let recoveryDownload = '';
function showRecovery(result, form) {
  form.hidden = true;
  get('recovery-result').hidden = false;
  get('recovery-message').textContent = result.message;
  get('recovery-value').value = result.recovery_code;
  get('continue-login').href = result.role === 'student' ? '/pages/student-login.html' : (facultyLeave ? '/pages/faculty-leave-login.html' : '/pages/faculty-login.html');
  recoveryDownload = 'Leave Approval account recovery\nEmail: ' + get('email').value.trim() + '\nRole: ' + result.role + '\nRecovery code: ' + result.recovery_code + '\nKeep this private. Use it on the Forgot password page.\n';
  get('recovery-result').scrollIntoView({ behavior: 'smooth' });
}
if (get('download-recovery')) get('download-recovery').addEventListener('click', () => downloadText('leave-approval-recovery.txt', recoveryDownload));
if (page === 'signup') {
  function updateRoleFields() {
    const role = get('role').value;
    get('student-fields').hidden = role !== 'student';
    get('faculty-fields').hidden = role !== 'faculty';
    for (const [id, expected] of [['student-id', 'student'], ['staff-id', 'faculty'], ['invitation-code', 'faculty']]) {
      get(id).disabled = role !== expected;
      get(id).required = role === expected;
    }
  }
  get('role').addEventListener('change', updateRoleFields);
  updateRoleFields();
}
const form = get(page === 'login' ? 'login-form' : page === 'signup' ? 'signup-form' : 'reset-form');
form.addEventListener('submit', async event => {
  event.preventDefault();
  notify('message', '');
  if (page !== 'login' && get('password').value !== get('confirm').value) {
    notify('message', 'Passwords do not match.', true); return;
  }
  const payload = { role: get('role').value, email: get('email').value.trim(), password: get('password').value };
  let path = '/auth/login';
  if (page === 'signup') {
    path = '/auth/signup';
    Object.assign(payload, {
      name: get('name').value.trim(),
      student_id: payload.role === 'student' ? get('student-id').value.trim() : null,
      staff_id: payload.role === 'faculty' ? get('staff-id').value.trim() : null,
      invitation_code: payload.role === 'faculty' ? get('invitation-code').value : ''
    });
  } else if (page === 'reset') {
    path = '/auth/reset-password';
    payload.recovery_code = get('recovery-code').value.trim();
  }
  get('submit-button').disabled = true;
  try {
    const result = await api(path, { method: 'POST', body: JSON.stringify(payload) });
    get('password').value = '';
    if (page === 'login') {
      if (result.role !== payload.role) throw new Error('Account role mismatch. Refresh this page and try again.');
      location.assign(result.role === 'faculty' && facultyLeave ? '/pages/faculty-leave-home.html' : '/pages/' + result.role + '-home.html');
    } else {
      get('confirm').value = '';
      if (get('invitation-code')) get('invitation-code').value = '';
      if (get('recovery-code')) get('recovery-code').value = '';
      showRecovery(result, form);
    }
  } catch (error) { notify('message', error.message, true); }
  finally { get('submit-button').disabled = false; }
});
