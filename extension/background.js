importScripts("config.js");

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

function shouldBlockWarning(verdict, isVerified = true, url = "", isUserAllowed = false) {
  if (!isVerified) return false;
  if (isUserAllowed) return false;

  const normalized = String(verdict || "").trim().toLowerCase();
  if (normalized === "caution" || normalized === "dangerous") {
    return true;
  }

  return /^http:\/\//i.test(String(url || ""));
}

function getFastDangerIndicators(url) {
  if (!isCheckableUrl(url)) {
    return null;
  }

  const hostname = getHostname(url);
  if (!hostname) {
    return null;
  }

  if (/^http:\/\//i.test(url)) {
    return {
      verdict: "dangerous",
      score: 70,
      reasons: ["Website is using plain HTTP instead of HTTPS"]
    };
  }

  if (hostname.includes("xn--") || hostname.includes("@")) {
    return {
      verdict: "dangerous",
      score: 75,
      reasons: ["Suspicious hostname pattern detected before page load"]
    };
  }

  if (/\d+\.\d+\.\d+\.\d+/.test(hostname)) {
    return {
      verdict: "dangerous",
      score: 80,
      reasons: ["IP address used instead of a normal hostname"]
    };
  }

  const suspiciousTokens = ["login", "secure", "account", "verify", "update", "billing", "confirm", "security", "support", "wallet", "payment"];
  if (suspiciousTokens.some((token) => hostname.includes(token))) {
    return {
      verdict: "caution",
      score: 45,
      reasons: ["Hostname resembles a login or account-related phishing pattern"]
    };
  }

  return null;
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
    const response = await fetch(`${SAFESITE_CONFIG.BACKEND_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = await response.json();
    result.verdict = normalizeVerdict(result);
    result.verified = true;
    await chrome.storage.session.set({ [tabKey]: result });
    await updateBadge(tabId, result.verdict, result.score);

    const certificateState = result?.tls?.status || result?.status || "";
    if (shouldBlockWarning(result.verdict, result.verified, url, false, certificateState)) {
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
    const fallback = {
      url,
      score: 0,
      verdict: "safe",
      verified: false,
      reasons: ["Backend unavailable — could not verify this site right now"]
    };

    await chrome.storage.session.set({ [tabKey]: fallback });
    await updateBadge(tabId, "safe", 0);
    pendingPreviousUrls.delete(tabId);
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

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (!details || !details.url || details.frameId !== 0) return;
  if (!isCheckableUrl(details.url)) return;
  if (isOwnExtensionUrl(details.url)) return;

  const hostname = getHostname(details.url);
  if (!hostname) return;

  if (await isHostTrusted(hostname)) return;
  if (await isTabTemporarilyAllowed(details.tabId, hostname)) return;

  const fastSignal = getFastDangerIndicators(details.url);
  if (!fastSignal) return;

  const warningUrl = createWarningUrl(details.url, "", {
    verdict: fastSignal.verdict,
    score: fastSignal.score,
    reasons: fastSignal.reasons
  });

  chrome.tabs.update(details.tabId, { url: warningUrl }).catch((error) => {
    console.error("Could not redirect dangerous page before load", error);
  });
}, { url: [{ schemes: ["http", "https"] }] });

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab || !tab.url) return;
  if (!isCheckableUrl(tab.url)) return;
  if (isOwnExtensionUrl(tab.url)) return;

  chrome.tabs.get(tabId).then(async (currentTab) => {
    const previous = currentTab && currentTab.url && !isOwnExtensionUrl(currentTab.url) && currentTab.url !== tab.url
      ? currentTab.url
      : "";

    pendingPreviousUrls.set(tabId, previous);
  }).catch((error) => console.error("Could not track previous page", error));

  checkUrlForTab(tabId, tab.url);
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
