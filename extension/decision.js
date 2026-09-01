function normalizeVerdict(verdict) {
  return String(verdict || '').trim().toLowerCase();
}

function isInsecureHttpUrl(url) {
  return typeof url === 'string' && /^http:\/\//i.test(url);
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
