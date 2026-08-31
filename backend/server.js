require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());

async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function checkSafeBrowsing(url) {
  if (!process.env.GOOGLE_SAFE_BROWSING_KEY) {
    return {
      threatStatus: "unknown",
      matches: [],
      reason: "Missing GOOGLE_SAFE_BROWSING_KEY in backend/.env"
    };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return {
      threatStatus: "unknown",
      matches: [],
      reason: "Invalid URL format"
    };
  }

  const requestBody = {
    client: {
      clientId: "safesiteguard",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(process.env.GOOGLE_SAFE_BROWSING_KEY)}`;

  const response = await fetchWithTimeout(apiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const text = await response.text();
    return {
      threatStatus: "unknown",
      matches: [],
      reason: `Safe Browsing request failed: ${response.status} ${text}`
    };
  }

  const data = await response.json();

  return {
    threatStatus: data.matches && data.matches.length > 0 ? "flagged" : "clean",
    matches: data.matches || [],
    hostname: parsedUrl.hostname,
    reason: data.matches && data.matches.length > 0 ? "Google Safe Browsing flagged this URL" : "No known threats reported by Google Safe Browsing"
  };
}
async function checkDomainAge(domain) {
  let host = domain;

  try {
    const url = new URL(domain);
    host = url.hostname;
  } catch {
    host = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  }

  host = host.toLowerCase();

  try {
    const response = await fetchWithTimeout(`https://rdap.org/domain/${host}`);

    if (!response.ok) {
      return {
        domain: host,
        ageDays: "unknown",
        reason: "No RDAP data returned"
      };
    }

    const data = await response.json();

    const events = Array.isArray(data.events) ? data.events : [];
    const registrationEvent = events.find((event) => event.eventAction === "registration");

    if (!registrationEvent || !registrationEvent.eventDate) {
      return {
        domain: host,
        ageDays: "unknown",
        reason: "No registration date found"
      };
    }

    const registeredAt = new Date(registrationEvent.eventDate).getTime();
    const now = Date.now();
    const ageDays = Math.max(0, Math.floor((now - registeredAt) / (1000 * 60 * 60 * 24)));

    return {
      domain: host,
      ageDays,
      reason: `Domain registered ${ageDays} days ago`
    };
  } catch (error) {
    return {
      domain: host,
      ageDays: "unknown",
      reason: "RDAP request failed"
    };
  }
}
app.get("/test-age", async (req, res) => {
  const result = await checkDomainAge("https://example.com");
  res.json(result);
});
const tls = require("tls");

// Checks whether `host` is covered by a certificate SAN entry, which may be
// an exact name ("web.whatsapp.com") or a wildcard ("*.whatsapp.com").
// The previous version only accepted an exact string match, which fails for
// the wildcard certificates that most major sites (WhatsApp, Google, banks,
// etc.) actually use in production — that was the cause of legitimate,
// secure sites being flagged as having a "hostname mismatch".
function hostMatchesCertName(host, certName) {
  host = host.toLowerCase();
  certName = certName.toLowerCase();

  if (certName === host) return true;

  if (certName.startsWith("*.")) {
    const suffix = certName.slice(1); // ".whatsapp.com"
    // Wildcard covers exactly one label: "web.whatsapp.com" matches
    // "*.whatsapp.com" but "a.web.whatsapp.com" does not.
    if (host.endsWith(suffix)) {
      const remainder = host.slice(0, host.length - suffix.length);
      return remainder.length > 0 && !remainder.includes(".");
    }
  }

  return false;
}

function certHostnameMatches(cert, host) {
  const names = [];

  if (cert.subjectaltname) {
    cert.subjectaltname.split(",").forEach((entry) => {
      const trimmed = entry.trim();
      if (trimmed.toLowerCase().startsWith("dns:")) {
        names.push(trimmed.slice(4));
      }
    });
  }

  // Fall back to the certificate's Common Name if there's no SAN at all
  // (older certs sometimes omit SAN entirely).
  if (names.length === 0 && cert.subject && cert.subject.CN) {
    names.push(cert.subject.CN);
  }

  return names.some((name) => hostMatchesCertName(host, name));
}

async function checkTlsCert(domain) {
  let host = domain;

  try {
    const parsed = new URL(domain);
    host = parsed.hostname;
  } catch {
    host = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  }

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false
      },
      () => {
        const cert = socket.getPeerCertificate();

        const result = {
          domain: host,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          authorized: socket.authorized || false,
          subject: cert.subject || null,
          issuer: cert.issuer || null,
          hostnameMatch: cert && (cert.subjectaltname || cert.subject) ? certHostnameMatches(cert, host) : false,
          reason: socket.authorized
            ? "TLS certificate is valid and authorized"
            : "TLS certificate is not authorized or is invalid"
        };

        socket.end();
        resolve(result);
      }
    );

    socket.setTimeout(5000, () => {
      socket.destroy();
      resolve({
        domain: host,
        validFrom: null,
        validTo: null,
        authorized: false,
        subject: null,
        issuer: null,
        hostnameMatch: false,
        reason: "TLS connection timed out"
      });
    });

    socket.on("error", () => {
      resolve({
        domain: host,
        validFrom: null,
        validTo: null,
        authorized: false,
        subject: null,
        issuer: null,
        hostnameMatch: false,
        reason: "TLS connection failed"
      });
    });
  });
}
app.get("/test-tls", async (req, res) => {
  const result = await checkTlsCert("https://example.com");
  res.json(result);
});
function isIpLiteral(url) {
  try {
    const parsed = new URL(url);
    // NOTE: previously this regex used \\d (a literal backslash + "d"),
    // which can never match a digit. It should be \d (a digit class).
    return /^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname);
  } catch {
    return false;
  }
}

function isPunycode(hostname) {
  return typeof hostname === "string" && hostname.includes("xn--");
}

function getHostnameFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return String(url).replace(/^https?:\/\//i, "").split("/")[0];
  }
}

function countSubdomains(hostname) {
  const host = String(hostname || "").replace(/\.$/, "").toLowerCase();
  if (!host || host === "localhost") return 0;

  const parts = host.split(".");
  if (parts.length <= 2) return 0;

  return parts.length - 2;
}

function hasAtSymbol(url) {
  try {
    return String(url).includes("@");
  } catch {
    return false;
  }
}

function isHttps(url) {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

function brandLookalikeScore(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");

  const suspiciousTokens = [
    "login", "secure", "account", "verify", "update", "billing",
    "confirm", "security", "support", "wallet", "payment"
  ];

  let score = 0;

  suspiciousTokens.forEach((token) => {
    if (host.includes(token)) score += 10;
  });

  if (host.includes("xn--")) score += 20;
  if (host.split(".").length > 3) score += 10;

  return Math.min(score, 100);
}

function analyzeHeuristics(url) {
  const hostname = getHostnameFromUrl(url);
  const heuristic = {
    isIpLiteral: isIpLiteral(url),
    isPunycode: isPunycode(hostname),
    countSubdomains: countSubdomains(hostname),
    hasAtSymbol: hasAtSymbol(url),
    isHttps: isHttps(url),
    brandLookalikeScore: brandLookalikeScore(hostname)
  };

  let heuristicRisk = 0;
  const reasons = [];

  if (heuristic.isIpLiteral) {
    heuristicRisk += 30;
    reasons.push("IP address used instead of a normal hostname");
  }

  if (heuristic.isPunycode) {
    heuristicRisk += 35;
    reasons.push("Punycode hostname detected");
  }

  if (heuristic.countSubdomains > 1) {
    heuristicRisk += 15;
    reasons.push("Multiple subdomains detected");
  }

  if (heuristic.hasAtSymbol) {
    heuristicRisk += 20;
    reasons.push("URL contains an @ symbol");
  }

  if (!heuristic.isHttps) {
    heuristicRisk += 25;
    reasons.push("Website is not using HTTPS");
  }

  if (heuristic.brandLookalikeScore > 0) {
    heuristicRisk += Math.min(35, heuristic.brandLookalikeScore);
    reasons.push("Brand-like or deceptive hostname pattern detected");
  }

  return {
    ...heuristic,
    heuristicRisk,
    reasons
  };
}

app.get("/test-heuristics", (req, res) => {
  const samples = [
    { name: "safe", url: "https://example.com" },
    { name: "ip", url: "http://192.168.1.5" },
    { name: "suspicious", url: "https://secure-login-update-account.com" },
    { name: "punycode", url: "https://xn--example-abc.com" }
  ];

  const result = samples.map((sample) => {
    const hostname = getHostnameFromUrl(sample.url);

    return {
      name: sample.name,
      url: sample.url,
      isIpLiteral: isIpLiteral(sample.url),
      isPunycode: isPunycode(hostname),
      countSubdomains: countSubdomains(hostname),
      hasAtSymbol: hasAtSymbol(sample.url),
      isHttps: isHttps(sample.url),
      brandLookalikeScore: brandLookalikeScore(hostname)
    };
  });

  res.json(result);
});

function dedupe(list) {
  return [...new Set(list.filter(Boolean))];
}

app.post("/check", async (req, res) => {
  const url = req.body && req.body.url;

  if (!url) {
    return res.status(400).json({
      url: null,
      score: 0,
      verdict: "caution",
      reasons: ["No URL was provided"]
    });
  }

  try {
    const hostname = getHostnameFromUrl(url);
    const [safeBrowsing, domainAge, tls] = await Promise.all([
      checkSafeBrowsing(url),
      checkDomainAge(hostname),
      checkTlsCert(hostname)
    ]);
    const heuristics = analyzeHeuristics(url);

    let score = 0;
    const reasons = [];

    if (safeBrowsing.threatStatus === "flagged") {
      score += 70;
      reasons.push("Google Safe Browsing reported a threat match");
    } else if (safeBrowsing.threatStatus === "unknown") {
      // An "unknown" result (e.g. missing/rate-limited key, transient
      // network failure) is not itself evidence of danger, so it should
      // only nudge the score slightly, not be treated as a near-miss.
      score += 5;
      reasons.push(safeBrowsing.reason);
    } else {
      reasons.push("No Google Safe Browsing threat matches were found");
    }

    if (typeof domainAge.ageDays === "number") {
      if (domainAge.ageDays <= 30) {
        score += 35;
        reasons.push("Domain is very new and likely risky");
      } else if (domainAge.ageDays <= 365) {
        score += 15;
        reasons.push("Domain is relatively new");
      } else {
        reasons.push("Domain age looks established");
      }
    } else {
      // Large/established organizations frequently have privacy-redacted
      // or incomplete RDAP records, so "unknown" should be a mild signal,
      // not treated close to "brand new domain".
      score += 8;
      reasons.push("Domain age could not be verified");
    }

    if (!tls.authorized) {
      score += 40;
      reasons.push("TLS certificate is invalid or unauthorized");
    } else if (!tls.hostnameMatch) {
      score += 18;
      reasons.push("TLS hostname does not match the certificate");
    } else {
      reasons.push("TLS certificate appears valid");
    }

    score += heuristics.heuristicRisk;
    reasons.push(...heuristics.reasons);

    const finalScore = Math.min(100, Math.max(0, score));
    const verdict = finalScore >= 60 ? "dangerous" : finalScore >= 20 ? "caution" : "safe";

    return res.json({
      url,
      score: finalScore,
      verdict,
      reasons: dedupe(reasons),
      safeBrowsing,
      domainAge,
      tls,
      heuristics
    });
  } catch (error) {
    return res.status(500).json({
      url,
      score: 0,
      verdict: "caution",
      reasons: [error.message || "Security analysis failed"]
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));