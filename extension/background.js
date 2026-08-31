const BADGE_COLORS = {
  safe: "#16a34a",
  caution: "#d97706",
  dangerous: "#dc2626"
};

function normalizeVerdict(result) {
  if (!result) return "caution";

  if (result.verdict) {
    return result.verdict.toLowerCase();
  }

  const score = Number(result.score || 0);
  if (score >= 60) return "dangerous";
  if (score >= 20) return "caution";
  return "safe";
}

// Returns the bare hostname for a URL, or null if it can't be parsed
// (e.g. chrome://, about:, chrome-extension:// pages).
function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// A URL belongs to the extension itself (the warning page) — never check
// or re-check these, or the warning page can end up re-triggering itself.
function isOwnExtensionUrl(url) {
  return typeof url === "string" && url.startsWith(chrome.runtime.getURL(""));
}

function isCheckableUrl(url) {
  if (!url) return false;
  if (!/^https?:\/\//i.test(url)) return false;
  if (isOwnExtensionUrl(url)) return false;
  return true;
}

const pendingPreviousUrls = new Map();

async function getTrustedHosts() {
  const data = await chrome.storage.session.get("trustedHosts");
  return data.trustedHosts || {};
}

async function trustHostForSession(hostname) {
  const trustedHosts = await getTrustedHosts();
  trustedHosts[hostname] = Date.now();
  await chrome.storage.session.set({ trustedHosts });
}

async function isHostTrusted(hostname) {
  const trustedHosts = await getTrustedHosts();
  return Boolean(hostname && trustedHosts[hostname]);
}

function getBypassStorageKey(tabId) {
  return `bypass:${String(tabId)}`;
}

async function setTabBypass(tabId, hostname) {
  const normalizedHostname = String(hostname || '').toLowerCase();
  if (!normalizedHostname) return;

  await chrome.storage.session.set({
    [getBypassStorageKey(tabId)]: {
      hostname: normalizedHostname,
      expiresAt: Date.now() + 30_000
    }
  });
}

async function getTabBypass(tabId) {
  const data = await chrome.storage.session.get(getBypassStorageKey(tabId));
  return data[getBypassStorageKey(tabId)] || null;
}

async function clearTabBypass(tabId) {
  await chrome.storage.session.remove(getBypassStorageKey(tabId));
}

async function isTabTemporarilyAllowed(tabId, hostname) {
  const bypass = await getTabBypass(tabId);
  if (!bypass) return false;

  const normalizedHostname = String(hostname || '').toLowerCase();
  if (bypass.hostname !== normalizedHostname) {
    await clearTabBypass(tabId);
    return false;
  }

  if (Date.now() > Number(bypass.expiresAt || 0)) {
    await clearTabBypass(tabId);
    return false;
  }

  return true;
}

// --- Badge ------------------------------------------------------------------

async function updateBadge(tabId, verdict, score) {
  try {
    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: BADGE_COLORS[verdict] || BADGE_COLORS.caution
    });
    await chrome.action.setBadgeText({
      tabId,
      text: verdict === "safe" ? "OK" : String(score ?? "")
    });
  } catch (error) {
    // Tab may have closed before this resolved — safe to ignore.
  }
}

// --- Core check ---------------------------------------------------------------

async function checkUrlForTab(tabId, url) {
  if (!isCheckableUrl(url)) return;

  const tabKey = String(tabId);
  const hostname = getHostname(url);

  if (await isHostTrusted(hostname)) {
    await chrome.storage.session.set({
      [tabKey]: { url, score: 0, verdict: "safe", reasons: ["Allowed for this browser session"] }
    });
    await updateBadge(tabId, "safe", 0);
    return;
  }

  if (await isTabTemporarilyAllowed(tabId, hostname)) {
    await clearTabBypass(tabId);
    await chrome.storage.session.set({
      [tabKey]: { url, score: 0, verdict: "safe", reasons: ["Temporarily allowed for this navigation"] }
    });
    await updateBadge(tabId, "safe", 0);
    return;
  }

  try {
    const response = await fetch("http://localhost:3000/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = await response.json();
    result.verdict = normalizeVerdict(result);
    await chrome.storage.session.set({ [tabKey]: result });
    await updateBadge(tabId, result.verdict, result.score);

    if (["caution", "dangerous"].includes(result.verdict)) {
      const currentTab = await chrome.tabs.get(tabId);
      const previous = pendingPreviousUrls.get(tabId) || "";
      pendingPreviousUrls.delete(tabId);

      if (currentTab && (currentTab.url === url || currentTab.url.startsWith(chrome.runtime.getURL("warning.html")))) {
        await chrome.tabs.update(tabId, { url: createWarningUrl(url, previous, result) });
      }
    } else {
      const currentTab = await chrome.tabs.get(tabId);
      const previous = pendingPreviousUrls.get(tabId) || "";
      pendingPreviousUrls.delete(tabId);

      if (currentTab && currentTab.url.startsWith(chrome.runtime.getURL("warning.html"))) {
        await chrome.tabs.update(tabId, { url });
      }
    }
  } catch (error) {
    console.error("Error checking URL for tab", tabId, error);
    await chrome.storage.session.set({
      [tabKey]: {
        url,
        score: 0,
        verdict: "caution",
        reasons: ["Backend unavailable — could not verify this site right now"]
      }
    });
    await updateBadge(tabId, "caution", "?");

    if (pendingPreviousUrls.has(tabId)) {
      const previous = pendingPreviousUrls.get(tabId);
      pendingPreviousUrls.delete(tabId);
      const currentTab = await chrome.tabs.get(tabId);
      if (currentTab && currentTab.url === url) {
        await chrome.tabs.update(tabId, {
          url: createWarningUrl(url, previous, {
            verdict: "caution",
            score: 0,
            reasons: ["Backend unavailable — could not verify this site right now"]
          })
        });
      }
    }
  }
}

function createWarningUrl(target, previous, result = null, state = null) {
  const warningUrl = chrome.runtime.getURL(
    `warning.html?target=${encodeURIComponent(target)}` +
      `&previous=${encodeURIComponent(previous || "")}` +
      (state ? `&state=${encodeURIComponent(state)}` : "")
  );

  if (!result) return warningUrl;

  return `${warningUrl}&verdict=${encodeURIComponent(result.verdict)}` +
    `&score=${encodeURIComponent(result.score || 0)}` +
    `&reasons=${encodeURIComponent(JSON.stringify(result.reasons || []))}`;
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!isCheckableUrl(details.url)) return;
  if (isOwnExtensionUrl(details.url)) return;

  chrome.tabs.get(details.tabId).then(async (tab) => {
    const previous = tab && tab.url && !isOwnExtensionUrl(tab.url) && tab.url !== details.url
      ? tab.url
      : "";

    pendingPreviousUrls.set(details.tabId, previous);

    if (tab && tab.url && !isOwnExtensionUrl(tab.url)) {
      const warningUrl = createWarningUrl(details.url, previous, null, "checking");
      await chrome.tabs.update(details.tabId, { url: warningUrl });
    }
  }).catch((error) => console.error("Could not show analysis screen", error));

  checkUrlForTab(details.tabId, details.url);
});

// --- Messages from warning.html -----------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "TRUST_HOST" && message.hostname) {
    trustHostForSession(message.hostname)
      .then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message?.type === "ALLOW_TAB_ONCE" && typeof message.tabId === "number" && message.hostname) {
    setTabBypass(message.tabId, message.hostname)
      .then(() => sendResponse({ ok: true }));
    return true;
  }
});
