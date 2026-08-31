const params = new URLSearchParams(window.location.search);
const target = params.get('target') || 'about:blank';
const previous = params.get('previous') || '';
const isChecking = params.get('state') === 'checking';
const verdict = (params.get('verdict') || 'dangerous').toLowerCase();
const score = params.get('score') || '0';

const targetEl = document.getElementById('targetUrl');
const verdictEl = document.getElementById('verdict');
const messageEl = document.getElementById('message');
const reasonsEl = document.getElementById('reasonsList');
const statusNoteEl = document.getElementById('statusNote');
const goBackBtn = document.getElementById('goBack');
const continueBtn = document.getElementById('continueAnyways');

function normalizeHostname(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return String(value || '').replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  }
}

function renderReasons() {
  let reasons = [];
  try {
    reasons = JSON.parse(params.get('reasons') || '[]');
  } catch {
    reasons = [];
  }

  (reasons.length ? reasons : ['No further detail was provided for this verdict.']).forEach((reason) => {
    const li = document.createElement('li');
    li.textContent = reason;
    reasonsEl.appendChild(li);
  });
}

targetEl.textContent = target;
verdictEl.textContent = isChecking ? 'ANALYZING' : verdict.toUpperCase();
renderReasons();

if (isChecking) {
  messageEl.textContent = 'Checking this URL before it opens...';
  reasonsEl.innerHTML = '<li>Please wait a moment.</li>';
  goBackBtn.style.display = 'none';
  continueBtn.style.display = 'none';
  statusNoteEl.textContent = 'Analysis in progress';
}

if (!isChecking && verdict === 'caution') {
  verdictEl.classList.add('warning');
  messageEl.textContent = 'This site has been flagged as caution and may be unsafe. Please review before continuing.';
} else if (!isChecking) {
  verdictEl.classList.remove('warning');
  messageEl.textContent = `This site has been flagged as dangerous by SafeSite Guard (score: ${score}/100). Please do not continue unless you trust it.`;
}

goBackBtn.addEventListener('click', async () => {
  goBackBtn.disabled = true;
  statusNoteEl.textContent = 'Going back...';
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      if (previous && previous !== 'about:blank') {
        await chrome.tabs.update(tab.id, { url: previous });
      } else {
        await chrome.tabs.update(tab.id, { url: 'chrome://newtab/' });
      }
      return;
    }
  } catch (error) {
    console.error('Go back failed', error);
    statusNoteEl.textContent = 'Could not go back automatically.';
  } finally {
    goBackBtn.disabled = false;
  }
});

continueBtn.addEventListener('click', async () => {
  continueBtn.disabled = true;
  statusNoteEl.textContent = 'Continuing...';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      await chrome.runtime.sendMessage({
        type: 'ALLOW_TAB_ONCE',
        tabId: tab.id,
        hostname: normalizeHostname(target)
      });
      await chrome.tabs.update(tab.id, { url: target });
      return;
    }
  } catch (error) {
    console.error('Continue failed', error);
  }

  window.location.href = target;
});
