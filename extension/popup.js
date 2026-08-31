function normalizeVerdict(result) {
  if (!result) return 'caution';
  if (result.verdict) return result.verdict.toLowerCase();

  // Kept in sync with the backend's thresholds (server.js) so the popup
  // never disagrees with the badge/warning page for the same score.
  const score = Number(result.score || 0);
  if (score >= 60) return 'dangerous';
  if (score >= 20) return 'caution';
  return 'safe';
}

async function loadResult() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const statusEl = document.getElementById('status');
  const domainEl = document.getElementById('domain');
  const scoreEl = document.getElementById('score');
  const reasonsEl = document.getElementById('reasons');

  if (!tab || !tab.url) {
    statusEl.textContent = 'NO TAB';
    statusEl.className = 'status caution';
    domainEl.textContent = 'No active page available';
    return;
  }

  domainEl.textContent = tab.url;

  try {
    const sessionKey = String(tab.id);
    let result = (await chrome.storage.session.get(sessionKey))[sessionKey];

    if (!result || !result.verdict) {
      const response = await fetch('http://localhost:3000/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      result = await response.json();
      result.verdict = normalizeVerdict(result);
      await chrome.storage.session.set({ [sessionKey]: result });
    }

    const verdict = normalizeVerdict(result);
    statusEl.textContent = verdict.toUpperCase();
    statusEl.className = `status ${verdict}`;
    scoreEl.textContent = `${Number(result.score || 0)}/100`;

    reasonsEl.innerHTML = '';
    (result.reasons || ['No details available']).forEach((reason) => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsEl.appendChild(li);
    });
  } catch (error) {
    console.error('Popup check failed:', error);
    statusEl.textContent = 'ERROR';
    statusEl.className = 'status caution';
    scoreEl.textContent = '--';
    reasonsEl.innerHTML = '<li>Could not connect to backend.</li>';
  }
}

document.addEventListener('DOMContentLoaded', loadResult);
