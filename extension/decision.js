function normalizeVerdict(verdict) {
  return String(verdict || '').trim().toLowerCase();
}

function isPrivateOrLocalIpUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    if (hostname === 'localhost') return true;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return false;

    const parts = hostname.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
  } catch {
    return false;
  }
}

function hasStandaloneDangerToken(hostname) {
  if (!hostname) return false;
  const tokens = [
    'login', 'secure', 'account', 'verify', 'update', 'billing',
    'confirm', 'security', 'support', 'wallet', 'payment'
  ];

  const parts = hostname.toLowerCase().replace(/^www\./, '').split(/[.-]/).filter(Boolean);
  return tokens.some((token) => parts.includes(token));
}

function isSuspiciousHostname(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (!hostname) return false;

    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) && !isPrivateOrLocalIpUrl(url)) {
      return true;
    }

    if (hostname.includes('xn--')) return true;
    return hasStandaloneDangerToken(hostname);
  } catch {
    return false;
  }
}

function isInsecureHttpUrl(url) {
  return typeof url === 'string' && /^http:\/\//i.test(url) && !isPrivateOrLocalIpUrl(url);
}

function shouldBlockWarning(verdict, isVerified = true, url = '', isUserAllowed = false, certificateState = '') {
  if (!isVerified) return false;
  if (isUserAllowed) return false;

  const normalized = normalizeVerdict(verdict);
  const certState = normalizeVerdict(certificateState);

  if (['revoked', 'expired', 'not-yet-valid', 'invalid'].includes(certState)) {
    return true;
  }

  if (normalized === 'caution' || normalized === 'dangerous') {
    return true;
  }

  if (isSuspiciousHostname(url)) {
    return true;
  }

  return isInsecureHttpUrl(url);
}

function shouldDisplayWarning(result) {
  if (!result || typeof result !== 'object') {
    return false;
  }

  return shouldBlockWarning(result.verdict, result.verified !== false);
}

if (typeof module !== 'undefined') {
  module.exports = {
    normalizeVerdict,
    shouldBlockWarning,
    shouldDisplayWarning
  };
}
