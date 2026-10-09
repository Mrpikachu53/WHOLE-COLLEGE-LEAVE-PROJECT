'use strict';
const APP_VERSION = '3.4.0';
const get = id => document.getElementById(id);
function notify(id, message, error = false) {
  get(id).textContent = message;
  get(id).classList.toggle('error', error);
}
async function api(path, options = {}) {
  let response;
  try {
    response = await fetch('/api' + path, {
      ...options, cache: 'no-store', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-App-Request': '1', 'X-App-Version': APP_VERSION, ...options.headers }
    });
  } catch (error) { throw new Error('Cannot reach the server. Check that it is running and try again.'); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/auth/')) location.replace(path.startsWith('/admin/') ? '/pages/admin-login.html' : '/pages/login.html');
    throw new Error(typeof data.detail === 'string' ? data.detail : 'The request failed. Please try again.');
  }
  return data;
}
async function requireAccount(role) {
  try {
    const user = await api('/auth/me');
    if (user.role !== role) { location.replace('/pages/' + user.role + '-home.html'); return null; }
    get('logout').addEventListener('click', async () => {
      get('logout').disabled = true;
      try { await api('/auth/logout', { method: 'POST' }); location.replace('/pages/login.html'); }
      catch (error) { notify('account-message', error.message, true); get('logout').disabled = false; }
    });
    get('welcome').textContent = 'Welcome, ' + user.name;
    get('identity').textContent = (role === 'student' ? 'Register number: ' + user.student_id : 'Staff ID: ' + user.staff_id) + ' · ' + user.email;
    get('dashboard').hidden = false;
    return user;
  } catch (error) { location.replace('/pages/login.html'); return null; }
}
async function allRequests(endpoint = '/requests') {
  const rows = [];
  for (let offset = 0; ; offset += 200) {
    const page = await api(endpoint + '?limit=200&offset=' + offset);
    rows.push(...page);
    if (page.length < 200) return [...new Map(rows.map(row => [row.id, row])).values()];
  }
}
function addCell(row, value, className = '') {
  const cell = document.createElement('td');
  cell.textContent = value || '—';
  cell.className = className;
  row.appendChild(cell);
  return cell;
}
function downloadText(filename, text, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a');
  link.href = url; link.download = filename;
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function startRefresh(callback) {
  callback();
  const timer = setInterval(() => { if (!document.hidden) callback(); }, 5000);
  get('refresh').addEventListener('click', callback);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) callback(); });
  window.addEventListener('pagehide', () => clearInterval(timer), { once: true });
}
// Revalidate protected pages restored by browser Back instead of displaying an old session.
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });

async function requireAdmin() {
  try {
    const user = await api('/admin/me');
    get('logout').addEventListener('click', async () => {
      get('logout').disabled = true;
      try { await api('/admin/logout', {method: 'POST'}); location.replace('/pages/login.html'); }
      catch (error) { notify('account-message', error.message, true); get('logout').disabled = false; }
    });
    get('welcome').textContent = 'Welcome, Administrator';
    get('identity').textContent = 'Review faculty applications. Admin sessions last one hour.';
    get('dashboard').hidden = false;
    return user;
  } catch (error) { location.replace('/pages/admin-login.html'); return null; }
}
