const DEFAULT_BACKEND_URL = 'http://localhost:3000';

const backendUrlInput = document.getElementById('backendUrl');
const statusLabel = document.getElementById('status');
const form = document.getElementById('backend-form');

function setStatus(message, isError = false) {
  statusLabel.textContent = message;
  statusLabel.style.color = isError ? '#fecaca' : '#bbf7d0';
}

chrome.storage.local.get('backendUrl', (data) => {
  backendUrlInput.value = data.backendUrl || DEFAULT_BACKEND_URL;
});

form.addEventListener('submit', (event) => {
  event.preventDefault();

  const backendUrl = backendUrlInput.value.trim() || DEFAULT_BACKEND_URL;
  chrome.storage.local.set({ backendUrl }, () => {
    setStatus(`Saved: ${backendUrl}`);
  });
});
