importScripts('phishing-features.js', 'ai-assistance.js');
// ─── PhishGuard Service Worker ────────────────────────────────────────────────
//
// ROLE: Coordinator.  No regex / keyword / scoring logic lives here.
//       See phishing-features.js for the heuristic layer.
//
// PIPELINE (per email):
//   1. runHeuristicAnalysis()    — local, instant, no network
//   2. runDatasetChecks()        — PhishTank + OpenPhish feed lookups
//   3. checkExternalReputation() — Google Safe Browsing + URLhaus (this file)
//      ├─ checkSafeBrowsing()    — Google v4 API, batched, cached, key required
//      └─ checkCommunityBlacklist() — URLhaus API, no key needed, per-URL
//
// CACHE STRATEGY:
//   analysisCache    — full result per email, keyed on sender+subject+body prefix
//   reputationCache  — per-URL result combining both external sources
//     TTL tiers:
//       MALICIOUS URL  → 60 min (stable signal; no point re-checking soon)
//       CLEAN URL      → 15 min (clean verdicts go stale faster; feeds update)
//       API ERROR      →  2 min (retry quickly after a transient failure)
//
// FAIL-SAFE CONTRACT:
//   Every external call is wrapped so that a network error, timeout, bad API key,
//   or malformed response returns { malicious: false } rather than crashing.
//   Warnings are logged to the service worker console; the UI always gets a result.
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

// ─── Config ───────────────────────────────────────────────────────────────────

// Replace with your key from https://console.cloud.google.com/
// → enable "Safe Browsing API" → Credentials → Create API Key
// Leave as placeholder to run in heuristics-only mode (no crash, just a warning).
const SAFE_BROWSING_API_KEY = 'AIzaSyAm-U-SNIPUKwCysxnxisBgnJm-qG1FAKI';

const SAFE_BROWSING_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find';

// URLhaus — free community feed run by abuse.ch, no key required.
// Docs: https://urlhaus-api.abuse.ch/
const URLHAUS_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/';

// Cache TTLs
const CACHE_DURATION           =  5 * 60 * 1000; // 5 min  — full email analysis
const REPUTATION_TTL_MALICIOUS = 60 * 60 * 1000; // 60 min — confirmed bad URL
const REPUTATION_TTL_CLEAN     = 15 * 60 * 1000; // 15 min — clean URL
const REPUTATION_TTL_ERROR     =  2 * 60 * 1000; //  2 min — retry after API error

// Network timeouts
const TIMEOUT_SAFE_BROWSING_MS = 5000; // 5 s — single batched POST
const TIMEOUT_URLHAUS_MS       = 4000; // 4 s — per-URL POST

// Score weights for external reputation hits.
// Heuristic weights live in RULE_CONFIG in phishing-features.js.
const EXTERNAL_SCORES = {
  safeBrowsingMalicious:    40, // Google confirmed malicious (fresh signal)
  urlhausMalicious:         35, // Community confirmed malicious (fresh signal)
  bothSourcesMalicious:     55, // Both agree — stronger, but NOT simply additive
  safeBrowsingConfirmBonus: 10, // SB confirms what heuristics already caught
  urlhausConfirmBonus:       8, // URLhaus confirms what heuristics already caught
};

// Google Safe Browsing threat types we care about.
const SB_THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',       // phishing falls under this category
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];

// ─── Caches ───────────────────────────────────────────────────────────────────

const analysisCache   = new Map(); // full email analysis results
const reputationCache = new Map(); // per-URL unified verdict { verdict, timestamp, ttl }

// ─── Message listener ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_EMAIL') {
    handleAnalyzeEmail(message.data)
      .then(sendResponse)
      .catch(error => sendResponse({ error: error.message }));
    return true; // async response
  }
});

// ─── Main coordinator ─────────────────────────────────────────────────────────

async function handleAnalyzeEmail(emailData) {
  try {
    if (!emailData?.sender || !emailData?.subject || !emailData?.body) {
      throw new Error('Incomplete email data — sender, subject, and body are required');
    }

    // Full-analysis cache check
    const cacheKey = generateCacheKey(emailData);
    const cached   = analysisCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp < CACHE_DURATION)) {
      return cached.result;
    }

    const urls = normalizeLinks(emailData.links);

    // ── Layer 1: Heuristic (phishing-features.js) ─────────────────────────────
    // All regex / keyword / pattern checks. Instant, no network.
    // Returns { score, indicators, flags }.
    // flags is a de-duplication contract read by Layer 3 to avoid double-counting.
    const heuristic = runHeuristicAnalysis(emailData);

    // ── Layer 2: Dataset feed lookups (phishing-features.js) ─────────────────
    // PhishTank + OpenPhish blacklist checks + Nazario sender patterns.
    // Non-overlapping with Layer 1 by design.
    const dataset = await runDatasetChecks(emailData, urls);

    // ── Layer 3: External reputation (this file) ──────────────────────────────
    // Google Safe Browsing (batched) → URLhaus (per-URL, only for SB-clean URLs).
    // Reads heuristic.flags to apply de-duplication on overlapping signals.
    const external = await checkExternalReputation(urls, heuristic.flags);

    // ── Aggregate ─────────────────────────────────────────────────────────────
    const totalScore = Math.min(
      heuristic.score + dataset.score + external.score,
      100
    );

    const allIndicators = [
      ...heuristic.indicators,
      ...dataset.indicators,
      ...external.indicators,
    ];

    const result = {
      riskScore:  totalScore,
      riskLevel:  getRiskLevel(totalScore),
      breakdown: {
        heuristicScore: heuristic.score,
        datasetScore:   dataset.score,
        externalScore:  external.score,
      },
      indicators:        allIndicators,
      aiExplanation:    '',
      aiRecommendation: '',
      timestamp:         Date.now(),
    };

    // ── Optional: AI explanation ──────────────────────────────────────────────
    try {
      const aiResult = await generateAIExplanation(result, emailData);
      result.aiExplanation    = aiResult.explanation    || '';
      result.aiRecommendation = aiResult.recommendation || '';
    } catch (err) {
      console.warn('[PhishGuard AI] Failed to attach AI explanation:', err.message);
    }

    analysisCache.set(cacheKey, { result, timestamp: Date.now() });
    cleanCache();

    return result;

  } catch (error) {
    console.error('[PhishGuard] Analysis error:', error);
    throw error;
  }
}

// ─── External reputation orchestrator ────────────────────────────────────────
//
// Coordinates Safe Browsing and URLhaus in a single pass:
//
//   1. Pull anything still valid from reputationCache immediately.
//   2. For uncached URLs, run Safe Browsing (one batched request).
//   3. For URLs that SB returned CLEAN, run URLhaus (parallel per-URL).
//      We deliberately skip URLhaus for SB-confirmed-malicious URLs — the
//      verdict is already certain and URLhaus calls are per-URL (slower).
//   4. Merge the two verdicts, write to reputationCache, and score.
//
// heuristicFlags prevents double-counting: if the heuristic layer already
// flagged brand impersonation for a URL, an external hit on that same URL
// earns a smaller "confirmation bonus" rather than the full fresh-signal weight.

async function checkExternalReputation(urls, heuristicFlags) {
  if (urls.length === 0) return { score: 0, indicators: [] };

  const indicators = [];
  let score = 0;

  // ── Step 1: reputation cache ──────────────────────────────────────────────
  const { cached: cachedVerdicts, unchecked } = partitionByCacheState(urls);

  for (const [url, verdict] of Object.entries(cachedVerdicts)) {
    const { points, label } = scoreSingleVerdict(url, verdict, heuristicFlags);
    score += points;
    if (label) indicators.push(label);
  }

  if (unchecked.length === 0) {
    return { score: Math.min(score, 80), indicators };
  }

  // ── Step 2: Google Safe Browsing (batched) ────────────────────────────────
  const sbVerdicts = await checkSafeBrowsing(unchecked);

  const sbMaliciousUrls = [];
  const sbCleanUrls     = [];

  for (const url of unchecked) {
    (sbVerdicts[url]?.malicious ? sbMaliciousUrls : sbCleanUrls).push(url);
  }

  // ── Step 3: URLhaus — only for SB-clean URLs ──────────────────────────────
  const urlhausVerdicts = await checkCommunityBlacklist(sbCleanUrls);

  // ── Step 4: merge, cache, score ───────────────────────────────────────────
  for (const url of unchecked) {
    const sbV = sbVerdicts[url]      || { malicious: false, threatTypes: [], error: false };
    const uhV = urlhausVerdicts[url] || { malicious: false, tags: [],       error: false };

    const merged = mergeVerdicts(sbV, uhV);

    const ttl = merged.malicious
      ? REPUTATION_TTL_MALICIOUS
      : (sbV.error || uhV.error ? REPUTATION_TTL_ERROR : REPUTATION_TTL_CLEAN);

    reputationCache.set(url, { verdict: merged, timestamp: Date.now(), ttl });

    const { points, label } = scoreSingleVerdict(url, merged, heuristicFlags);
    score += points;
    if (label) indicators.push(label);
  }

  return { score: Math.min(score, 80), indicators };
}

// ─── Google Safe Browsing v4 ─────────────────────────────────────────────────
//
// Sends one POST request for all URLs (up to 500 per API limit).
// Returns: { [url]: { malicious: bool, threatTypes: string[], error: bool } }
//
// Fail-safe guarantees:
//   • Missing / placeholder API key  → warn + return all clean (no crash)
//   • HTTP 400 (bad URL format)      → warn + return all clean
//   • HTTP 403 (bad key / quota)     → warn + return all clean
//   • Other HTTP error               → warn + return all error-flagged (short TTL)
//   • Network failure / timeout      → warn + return all error-flagged (short TTL)

async function checkSafeBrowsing(urls) {
  // Default: assume clean for every URL
  const results = Object.fromEntries(
    urls.map(u => [u, { malicious: false, threatTypes: [], error: false }])
  );

  if (!SAFE_BROWSING_API_KEY || SAFE_BROWSING_API_KEY === 'AIzaSyAm-U-SNIPUKwCysxnxisBgnJm-qG1FAKI') {
    console.warn('[PhishGuard] Safe Browsing skipped — no API key configured. ' +
      'Add your key to SAFE_BROWSING_API_KEY in service-worker.js');
    return results;
  }

  if (urls.length === 0) return results;

  const batch      = urls.slice(0, 500); // API hard limit
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), TIMEOUT_SAFE_BROWSING_MS);

  try {
    const response = await fetch(
      `${SAFE_BROWSING_ENDPOINT}?key=${SAFE_BROWSING_API_KEY}`,
      {
        method:  'POST',
        signal:  controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: {
            clientId:      'phishguard-extension',
            clientVersion: '1.0.0',
          },
          threatInfo: {
            threatTypes:      SB_THREAT_TYPES,
            platformTypes:    ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries:    batch.map(url => ({ url })),
          },
        }),
      }
    );

    clearTimeout(timeoutId);

    // ── HTTP error handling ────────────────────────────────────────────────
    if (response.status === 400) {
      console.warn('[PhishGuard] Safe Browsing 400 Bad Request — ' +
        'one or more URLs may be malformed. Skipping this batch.');
      return results; // clean — malformed URLs aren't a phishing signal
    }

    if (response.status === 403) {
      console.warn('[PhishGuard] Safe Browsing 403 Forbidden — ' +
        'check your API key is correct and has not exceeded its daily quota.');
      return results;
    }

    if (!response.ok) {
      console.warn(`[PhishGuard] Safe Browsing unexpected error: ${response.status} ${response.statusText}`);
      // Error-flag so reputationCache uses the short TTL and we retry soon
      return Object.fromEntries(
        urls.map(u => [u, { malicious: false, threatTypes: [], error: true }])
      );
    }

    // ── Parse response ─────────────────────────────────────────────────────
    const data = await response.json();

    // When nothing is flagged, the API omits 'matches' entirely (not an error).
    if (data.matches?.length > 0) {
      for (const match of data.matches) {
        const matchedUrl = match.threat?.url;
        if (matchedUrl && results[matchedUrl] !== undefined) {
          results[matchedUrl].malicious = true;
          results[matchedUrl].threatTypes.push(match.threatType);
        }
      }
    }

    return results;

  } catch (err) {
    clearTimeout(timeoutId);

    if (err.name === 'AbortError') {
      console.warn(
        `[PhishGuard] Safe Browsing timed out after ${TIMEOUT_SAFE_BROWSING_MS}ms. ` +
        'Results will be retried on next analysis.'
      );
    } else {
      console.warn('[PhishGuard] Safe Browsing network error:', err.message);
    }

    // Error-flag so cache uses short TTL → we'll retry quickly
    return Object.fromEntries(
      urls.map(u => [u, { malicious: false, threatTypes: [], error: true }])
    );
  }
}

// ─── URLhaus community blacklist ──────────────────────────────────────────────
//
// URLhaus (abuse.ch) is a free, no-key community feed of malware distribution
// and phishing URLs.  The API is per-URL (no batch endpoint), so we only call
// it for URLs that Safe Browsing returned CLEAN, keeping total latency low.
//
// Returns: { [url]: { malicious: bool, urlStatus: string, tags: string[], error: bool } }
//
//   malicious:  true only when url_status === 'online' (still actively serving threats)
//   urlStatus:  'online' | 'offline' — 'offline' entries are flagged as informational
//   tags:       URLhaus classification tags, e.g. ['phishing', 'malware', 'elf']
//
// Fail-safe: any error returns { malicious: false, tags: [], error: true }.

async function checkCommunityBlacklist(urls) {
  if (urls.length === 0) return {};

  // Fire all lookups in parallel — URLhaus rate limits per IP, not per request,
  // and a typical email has far fewer than 10 links so this is safe.
  const entries = await Promise.all(
    urls.map(async url => [url, await lookupUrlhaus(url)])
  );

  return Object.fromEntries(entries);
}

async function lookupUrlhaus(url) {
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), TIMEOUT_URLHAUS_MS);

  try {
    // URLhaus uses form encoding, not JSON
    const response = await fetch(URLHAUS_ENDPOINT, {
      method:  'POST',
      signal:  controller.signal,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({ url }).toString(),
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`[PhishGuard] URLhaus HTTP ${response.status} for ${url}`);
      return { malicious: false, tags: [], error: true };
    }

    const data = await response.json();

    if (data.query_status === 'no_results') {
      // Not in URLhaus — clean
      return { malicious: false, urlStatus: null, tags: [], error: false };
    }

    if (data.query_status === 'isListed') {
      // 'online'  → URL is actively serving threats → flag as malicious
      // 'offline' → URL has been taken down → informational only (lower confidence)
      return {
        malicious:  data.url_status === 'online',
        urlStatus:  data.url_status,
        tags:       data.tags || [],
        urlhausId:  data.id,
        error:      false,
      };
    }

    // Unexpected status — treat as clean, log for diagnostics
    console.warn('[PhishGuard] URLhaus unexpected query_status:', data.query_status, 'for', url);
    return { malicious: false, tags: [], error: false };

  } catch (err) {
    clearTimeout(timeoutId);

    if (err.name === 'AbortError') {
      console.warn(`[PhishGuard] URLhaus timed out (${TIMEOUT_URLHAUS_MS}ms) for ${url}`);
    } else {
      console.warn('[PhishGuard] URLhaus network error for', url, ':', err.message);
    }

    return { malicious: false, tags: [], error: true };
  }
}

// ─── Verdict merge ────────────────────────────────────────────────────────────
//
// Combines SB and URLhaus into a single unified verdict.
// Two independent sources agreeing is stronger evidence than either alone,
// hence bothSourcesMalicious < safeBrowsingMalicious + urlhausMalicious
// (we do not simply add them — that would create inflation).

function mergeVerdicts(sbVerdict, uhVerdict) {
  const bothConfirmed     = sbVerdict.malicious && uhVerdict.malicious;
  const anyMalicious      = sbVerdict.malicious || uhVerdict.malicious;
  const urlhausOfflineOnly =
    uhVerdict.malicious && uhVerdict.urlStatus === 'offline' && !sbVerdict.malicious;

  const sources = [];
  if (sbVerdict.malicious) {
    sources.push({ name: 'Google Safe Browsing', types: sbVerdict.threatTypes });
  }
  if (uhVerdict.malicious) {
    sources.push({ name: 'URLhaus', tags: uhVerdict.tags, status: uhVerdict.urlStatus });
  }

  return {
    malicious:          anyMalicious,
    bothConfirmed,
    urlhausOfflineOnly,
    sources,
    error:              sbVerdict.error || uhVerdict.error,
  };
}

// ─── Single-URL scoring ───────────────────────────────────────────────────────
//
// Applies the de-duplication contract: if the heuristic layer already flagged
// brand impersonation, external confirmation earns a smaller bonus weight
// rather than the full fresh-signal weight.

function scoreSingleVerdict(url, verdict, heuristicFlags) {
  if (!verdict.malicious) return { points: 0, label: null };

  const alreadyFlagged = heuristicFlags?.hasBrandImpersonation ?? false;
  const sourceNames    = verdict.sources.map(s => s.name).join(' + ');

  // Previously malicious but now offline — informational, very low weight
  if (verdict.urlhausOfflineOnly) {
    return {
      points: alreadyFlagged ? 0 : 10,
      label:  `⚠️ URLhaus: previously malicious URL (now offline): ${url}`,
    };
  }

  let points;
  if (verdict.bothConfirmed) {
    points = alreadyFlagged
      ? EXTERNAL_SCORES.safeBrowsingConfirmBonus + EXTERNAL_SCORES.urlhausConfirmBonus
      : EXTERNAL_SCORES.bothSourcesMalicious;
  } else if (verdict.sources[0]?.name === 'Google Safe Browsing') {
    points = alreadyFlagged
      ? EXTERNAL_SCORES.safeBrowsingConfirmBonus
      : EXTERNAL_SCORES.safeBrowsingMalicious;
  } else {
    // URLhaus-only hit
    points = alreadyFlagged
      ? EXTERNAL_SCORES.urlhausConfirmBonus
      : EXTERNAL_SCORES.urlhausMalicious;
  }

  const overlapNote = alreadyFlagged ? ' [heuristic overlap — partial credit]' : '';
  const label = `🚨 ${sourceNames}: malicious URL confirmed${overlapNote}: ${url}`;

  return { points, label };
}

// ─── Reputation cache helpers ─────────────────────────────────────────────────

// Separates a URL list into those with a valid cache entry vs. those that need
// a live network check.  Uses the per-entry TTL (malicious / clean / error tiers).
function partitionByCacheState(urls) {
  const now       = Date.now();
  const cached    = {};
  const unchecked = [];

  for (const url of urls) {
    const entry = reputationCache.get(url);
    if (entry && (now - entry.timestamp < entry.ttl)) {
      cached[url] = entry.verdict;
    } else {
      unchecked.push(url);
    }
  }

  return { cached, unchecked };
}

// ─── Link normalization ───────────────────────────────────────────────────────

// Accepts both plain-string links (old gmail-parser format) and link objects
// { href, displayedDomain, actualDomain, … } (current format).
function normalizeLinks(links) {
  if (!links || links.length === 0) return [];
  return links
    .map(link => typeof link === 'string' ? link : (link.href || ''))
    .filter(url => url.length > 0);
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function getRiskLevel(score) {
  if (score < 30) return 'low';
  if (score < 60) return 'medium';
  return 'high';
}

function generateCacheKey(emailData) {
  return `${emailData.sender}:${emailData.subject}:${emailData.body.substring(0, 100)}`;
}

function cleanCache() {
  const now = Date.now();

  for (const [key, value] of analysisCache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) analysisCache.delete(key);
  }

  // Reputation cache uses per-entry TTL (not a global constant)
  for (const [key, entry] of reputationCache.entries()) {
    if (now - entry.timestamp > entry.ttl) reputationCache.delete(key);
  }
}

chrome.runtime.onStartup.addListener(() => {
  analysisCache.clear();
  reputationCache.clear();
});

// ─── Dev helper ───────────────────────────────────────────────────────────────
//
// Open chrome://extensions → PhishGuard → "service worker" DevTools console,
// then call:  testExternalReputation()

async function testExternalReputation() {
  console.log('[PhishGuard test] Testing external reputation checks …\n');

  const TEST_URLS = [
    'https://testsafebrowsing.appspot.com/s/phishing.html', // SB always flags this
    'https://google.com',                                    // always clean
  ];

  // Flush cache so we always make live network calls during the test
  TEST_URLS.forEach(url => reputationCache.delete(url));

  const result = await checkExternalReputation(TEST_URLS, {});

  console.log('Score:',      result.score);
  console.log('Indicators:', result.indicators);

  const testUrlFlagged = result.indicators.some(i => i.includes('testsafebrowsing'));
  console.log(
    testUrlFlagged
      ? '✓ Known-malicious URL was correctly flagged'
      : '✗ Known-malicious URL was NOT flagged — verify your API key and quota'
  );
}