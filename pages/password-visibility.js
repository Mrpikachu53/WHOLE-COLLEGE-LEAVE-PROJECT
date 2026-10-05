'use strict';
(() => {
  document.querySelectorAll('[data-password-target]').forEach(button => {
    const input = document.getElementById(button.dataset.passwordTarget);
    if (!input) return;
    const slash = button.querySelector('.eye-slash');
    function setVisible(visible) {
      input.type = visible ? 'text' : 'password';
      const label = (visible ? 'Hide ' : 'Show ') + button.dataset.fieldLabel;
      button.setAttribute('aria-label', label);
      button.title = label;
      if (slash) slash.toggleAttribute('hidden', !visible);
    }
    button.addEventListener('click', () => {
      if (!input.disabled) setVisible(input.type === 'password');
    });
    input.form?.addEventListener('reset', () => setVisible(false));
    setVisible(false);
  });
})();
