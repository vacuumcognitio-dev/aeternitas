document.querySelectorAll('[data-year]').forEach((item) => { item.textContent = new Date().getFullYear(); });

const form = document.querySelector('#login-form');
if (form) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = form.username.value.trim();
    const password = form.password.value;
    const message = document.querySelector('#form-message');
    const button = form.querySelector('button');
    button.disabled = true;
    message.textContent = '';
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const result = await response.json();
      if (response.ok) {
        window.location.href = 'download.html';
        return;
      }
      message.textContent = result.error || 'Não foi possível entrar.';
    } catch {
      message.textContent = 'Não foi possível conectar ao servidor.';
    }
    form.password.value = '';
    button.disabled = false;
    form.password.focus();
  });
}

const content = document.querySelector('#download-content');
if (content) {
  fetch('/api/session').then((response) => response.json()).then((result) => {
    if (!result.authenticated) window.location.replace('index.html');
    else content.hidden = false;
  }).catch(() => window.location.replace('index.html'));
}

document.querySelector('#logout')?.addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = 'index.html';
});
