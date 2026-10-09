"use strict";
get('admin-form').addEventListener('submit', async event => {
  event.preventDefault();
  get('submit-button').disabled = true;
  notify('message', '');
  try {
    await api('/admin/login', {method: 'POST', body: JSON.stringify({access_key: get('access-key').value})});
    get('access-key').value = '';
    location.assign('/pages/admin-home.html');
  } catch (error) { notify('message', error.message, true); }
  finally { get('submit-button').disabled = false; }
});
