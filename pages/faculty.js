'use strict';
const adminReview = document.body.dataset.page === 'admin';
const reviewEndpoint = adminReview ? '/admin/faculty-requests' : '/requests';
let loading = false;
let deciding = false;
let reportRows = [];
const drafts = new Map();
async function loadRequests() {
  if (loading || deciding) return;
  loading = true;
  try {
    const rows = await allRequests(reviewEndpoint);
    // Keep the current table intact while a teacher types remarks or makes a decision.
    if (deciding || document.activeElement?.classList.contains('remarks-input')) return;
    reportRows = rows;
    get('permission-list').replaceChildren();
    get('leave-list').replaceChildren();
    for (const request of rows) {
      const row = document.createElement('tr');
      addCell(row, request.id);
      addCell(row, (adminReview ? request.faculty_name : request.student_name) + ' / ' + ((adminReview ? request.staff_id : request.student_id) || '—'));
      addCell(row, request.start_date + (request.end_date ? ' to ' + request.end_date : ' / ' + request.arrival_time.slice(0, 5)));
      addCell(row, request.reason);
      addCell(row, request.status, request.status.toLowerCase());
      const remarksCell = addCell(row, request.remarks);
      const actions = addCell(row, 'Reviewed', 'actions');
      if (request.status === 'Pending') {
        remarksCell.textContent = ''; actions.textContent = '';
        const remarks = document.createElement('input');
        remarks.className = 'remarks-input'; remarks.maxLength = 2000;
        remarks.setAttribute('aria-label', 'Remarks for request ' + request.id);
        remarks.value = drafts.get(request.id) || '';
        remarks.addEventListener('input', () => drafts.set(request.id, remarks.value));
        remarksCell.appendChild(remarks);
        for (const status of ['Approved', 'Rejected']) {
          const button = document.createElement('button');
          button.type = 'button'; button.textContent = status === 'Approved' ? 'Approve' : 'Reject';
          if (status === 'Rejected') button.className = 'reject';
          button.setAttribute('aria-label', button.textContent + ' request ' + request.id);
          button.addEventListener('click', async () => {
            if (deciding) return;
            deciding = true;
            actions.querySelectorAll('button').forEach(item => item.disabled = true);
            try {
              await api(reviewEndpoint + '/' + request.id, { method: 'PATCH', body: JSON.stringify({ status, remarks: remarks.value.trim() }) });
              drafts.delete(request.id);
              notify('decision-message', 'Request #' + request.id + ' ' + status.toLowerCase() + (adminReview ? '. The faculty member can see the decision.' : '. The student can see the decision.'));
            } catch (error) { notify('decision-message', error.message, true); }
            finally {
              deciding = false;
              actions.querySelectorAll('button').forEach(item => item.disabled = false);
              await loadRequests();
            }
          });
          actions.appendChild(button);
        }
      }
      get(request.request_type + '-list').appendChild(row);
    }
    get('total-count').textContent = rows.length;
    for (const status of ['Pending', 'Approved', 'Rejected']) get(status.toLowerCase() + '-count').textContent = rows.filter(row => row.status === status).length;
    for (const type of ['permission', 'leave']) get(type + '-empty').textContent = rows.some(row => row.request_type === type) ? '' : 'No applications of this type yet.';
    get('download-report').disabled = rows.length === 0;
    notify('load-message', 'Last updated: ' + new Date().toLocaleTimeString());
  } catch (error) { notify('load-message', error.message, true); }
  finally { loading = false; }
}
get('download-report').addEventListener('click', () => {
  const escape = value => {
    let text = String(value ?? '');
    if (/^[\s]*[=+@-]/.test(text) || /^[\t\r\n]/.test(text)) text = "'" + text;
    return '"' + text.replaceAll('"', '""') + '"';
  };
  const header = ['ID', adminReview ? 'Faculty' : 'Student', adminReview ? 'Staff ID' : 'Register Number', 'Type', 'Start Date', 'End Date', 'Arrival', 'Reason', 'Status', 'Remarks', 'Reviewed At'];
  const rows = reportRows.map(r => [r.id, adminReview ? r.faculty_name : r.student_name, adminReview ? r.staff_id : r.student_id, r.request_type, r.start_date, r.end_date, r.arrival_time, r.reason, r.status, r.remarks, r.reviewed_at]);
  downloadText(adminReview ? 'faculty-leave-report.csv' : 'student-leave-report.csv', '\uFEFF' + [header, ...rows].map(row => row.map(escape).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
});
(adminReview ? requireAdmin() : requireAccount('faculty')).then(user => { if (user) startRefresh(loadRequests); });
