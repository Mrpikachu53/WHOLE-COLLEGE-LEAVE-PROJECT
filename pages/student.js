'use strict';
const facultyApplication = document.body.dataset.page === 'faculty-leave';
const requestEndpoint = facultyApplication ? '/faculty-requests' : '/requests';
function showApplication(scroll = false) {
  const target = location.hash.slice(1);
  if (!['permission-application', 'leave-application'].includes(target)) return;
  get('permission-application').hidden = target !== 'permission-application';
  get('leave-application').hidden = target !== 'leave-application';
  if (scroll) get(target).scrollIntoView({ behavior: 'smooth' });
}
window.addEventListener('hashchange', () => showApplication(true));
showApplication();
let loading = false;
async function loadRequests() {
  if (loading) return;
  loading = true;
  try {
    const rows = await allRequests(requestEndpoint);
    get('request-list').replaceChildren();
    for (const request of rows) {
      const row = document.createElement('tr');
      addCell(row, request.id);
      addCell(row, request.request_type === 'permission' ? 'First Hour Permission' : 'Leave');
      addCell(row, request.start_date + (request.end_date ? ' to ' + request.end_date : ''));
      addCell(row, request.arrival_time?.slice(0, 5));
      addCell(row, request.reason);
      addCell(row, request.status, request.status.toLowerCase());
      addCell(row, request.remarks);
      get('request-list').appendChild(row);
    }
    notify('load-message', rows.length ? 'Last updated: ' + new Date().toLocaleTimeString() : 'No requests yet. Your applications will appear here.');
  } catch (error) { notify('load-message', error.message, true); }
  finally { loading = false; }
}
for (const type of ['permission', 'leave']) {
  get(type + '-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button');
    const payload = {
      request_type: type,
      start_date: get(type === 'permission' ? 'permission-date' : 'start-date').value,
      end_date: type === 'leave' ? get('end-date').value : null,
      arrival_time: type === 'permission' ? get('arrival-time').value : null,
      reason: get(type + '-reason').value.trim()
    };
    if (!payload.reason) { notify(type + '-message', 'Please enter a reason.', true); return; }
    if (type === 'leave' && payload.end_date < payload.start_date) {
      notify(type + '-message', 'Leave end date cannot be before the start date.', true); return;
    }
    button.disabled = true;
    try {
      const result = await api(requestEndpoint, { method: 'POST', body: JSON.stringify(payload) });
      form.reset();
      notify(type + '-message', 'Request #' + result.id + ' saved. Status: Pending.');
      await loadRequests();
    } catch (error) { notify(type + '-message', error.message, true); }
    finally { button.disabled = false; }
  });
}
requireAccount(facultyApplication ? 'faculty' : 'student').then(user => { if (user) startRefresh(loadRequests); });
