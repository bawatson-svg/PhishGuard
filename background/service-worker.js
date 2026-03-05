// PhishGuard Service Worker - Rule-based detection + Google Safe Browsing reputation checks

// ─── Config ───────────────────────────────────────────────────────────────────

// To enable Safe Browsing lookups, replace this with your real API key from:
// https://console.cloud.google.com/ → enable "Safe Browsing API" → create credentials
// If this stays as the placeholder, we just skip reputation checks entirely (no error).
const SAFE_BROWSING_API_KEY = 'PLEASE ADD YOUR API HERE';

// how long to keep email analysis results cached (5 min)
const CACHE_DURATION = 5 * 60 * 1000;

// separate, longer cache for Safe Browsing results — no need to re-check the same
// URL every time, and the API has rate limits we don't want to burn through
const SB_CACHE_DURATION = 10 * 60 * 1000; // 10 minutes

// ─── Caches ───────────────────────────────────────────────────────────────────

const analysisCache  = new Map(); // full email analysis results
const sbCache        = new Map(); // Safe Browsing results keyed by URL

// ─── Message listener ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_EMAIL') {
    handleAnalyzeEmail(message.data)
      .then(sendResponse)
      .catch(error => sendResponse({ error: error.message }));
    return true; // tell Chrome we'll call sendResponse asynchronously
  }
});

// ─── Main handler ─────────────────────────────────────────────────────────────

async function handleAnalyzeEmail(emailData) {
  try {
    if (!emailData || !emailData.sender || !emailData.subject || !emailData.body) {
      throw new Error('Incomplete email data');
    }

    // check if we already analyzed this exact email recently
    const cacheKey = generateCacheKey(emailData);
    const cached = analysisCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp < CACHE_DURATION)) {
      return cached.result;
    }

    // step 1: run our local rule-based checks (fast, no network)
    const analysis = runRuleBasedAnalysis(emailData);

    // step 2: pull out plain URL strings from links (handles both old string format
    // and new object format — see normalizeLinks() below)
    const urls = normalizeLinks(emailData.links);

    // step 3: check those URLs against Google Safe Browsing (slow, network, may fail)
    // we do this after rule-based so a network failure doesn't block everything
    const sbResults = await checkSafeBrowsing(urls);

    // step 4: fold Safe Browsing findings into the score and indicators
    let extraScore = 0;
    const sbIndicators = [];

    for (const [url, result] of Object.entries(sbResults)) {
      if (result.malicious) {
        // +40 per confirmed-malicious URL — this is a very strong signal since
        // Safe Browsing is backed by Google's actual threat intelligence database
        extraScore += 40;
        const threats = result.threatTypes.join(', ');
        sbIndicators.push(`🚨 Safe Browsing flagged malicious URL (${threats}): ${url}`);
      }
    }

    // merge everything together
    const finalScore = Math.min(analysis.score + extraScore, 100);
    const allIndicators = [...analysis.indicators, ...sbIndicators];

    // if rule-based came back clean but SB found nothing either, make sure we still
    // have the "looks safe" message (it gets added in runRuleBasedAnalysis already,
    // but double-check since we might have added SB indicators after the fact)
    const result = {
      riskScore:  finalScore,
      riskLevel:  getRiskLevel(finalScore),
      ruleScore:  analysis.score,
      llmScore:   0,
      indicators: allIndicators,
      timestamp:  Date.now()
    };

    analysisCache.set(cacheKey, { result, timestamp: Date.now() });
    cleanCache();

    return result;

  } catch (error) {
    console.error('Analysis error:', error);
    throw error;
  }
}

// ─── Link normalization ───────────────────────────────────────────────────────

// gmail-parser.js might give us links as plain strings (old format) or as objects
// with { href, text, ... } (new format). This just flattens them to URL strings
// so Safe Browsing and any other URL-based checks have a consistent input.
function normalizeLinks(links) {
  if (!links || links.length === 0) return [];

  return links
    .map(link => typeof link === 'string' ? link : (link.href || ''))
    .filter(url => url.length > 0); // drop any blanks
}

// ─── Google Safe Browsing lookup ──────────────────────────────────────────────

// Google Safe Browsing is a free API (with rate limits) that checks URLs against
// Google's database of known malware, phishing, and unwanted software sites.
// Basically we send a list of URLs and Google tells us if any are flagged.
// Docs: https://developers.google.com/safe-browsing/reference/rest/v4/threatMatches/find
//
// We batch all URLs into one request (API supports up to 500 at a time) to avoid
// making a separate API call per link — that would be slow and burn our quota fast.

async function checkSafeBrowsing(urls) {
  // if no API key is set, just silently skip — rules-only mode is still useful
  if (!SAFE_BROWSING_API_KEY || SAFE_BROWSING_API_KEY === 'YOUR_API_KEY_HERE') {
    return {};
  }

  if (urls.length === 0) return {};

  // figure out which URLs we already have cached so we don't re-check them
  const now = Date.now();
  const cachedResults = {};
  const urlsToFetch = [];

  for (const url of urls) {
    const cached = sbCache.get(url);
    if (cached && (now - cached.timestamp < SB_CACHE_DURATION)) {
      cachedResults[url] = cached.data; // still fresh, use it
    } else {
      urlsToFetch.push(url); // expired or never checked, need to fetch
    }
  }

  // if everything was cached, we're done — no network call needed
  if (urlsToFetch.length === 0) {
    return cachedResults;
  }

  // Safe Browsing supports up to 500 URLs per request, but just in case
  // someone somehow has a wild email with a ton of links, slice it
  const batch = urlsToFetch.slice(0, 500);

  // set up a timeout so a slow/hung API call doesn't freeze the UI
  // AbortController lets us cancel the fetch after N milliseconds
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000); // 4 second timeout

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`,
      {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          // client block identifies our app to Google — required by the API
          client: {
            clientId:      'phishguard-extension',
            clientVersion: '1.0.0'
          },
          threatInfo: {
            // the four main threat categories we care about
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',        // this is what phishing falls under
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            platformTypes:    ['ANY_PLATFORM'], // we don't care which OS, just flag it
            threatEntryTypes: ['URL'],
            threatEntries: batch.map(url => ({ url })) // [{ url: "https://..." }, ...]
          }
        })
      }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      // API returned an error (bad key, quota exceeded, etc.) — log it and bail
      console.warn('[PhishGuard] Safe Browsing API error:', response.status, response.statusText);
      return cachedResults; // return whatever we had cached at least
    }

    const data = await response.json();

    // build a lookup map: url -> { malicious, threatTypes }
    // start with everything as clean, then mark the flagged ones
    const fetchedResults = {};
    for (const url of batch) {
      fetchedResults[url] = { malicious: false, threatTypes: [] };
    }

    // data.matches is an array of threat matches — each one has a .threat.url
    // and a .threatType telling us what kind of threat it is
    if (data.matches && data.matches.length > 0) {
      for (const match of data.matches) {
        const matchedUrl = match.threat.url;
        if (fetchedResults[matchedUrl]) {
          fetchedResults[matchedUrl].malicious = true;
          fetchedResults[matchedUrl].threatTypes.push(match.threatType);
        }
      }
    }

    // cache all the results we just fetched so we don't hit the API again soon
    for (const [url, result] of Object.entries(fetchedResults)) {
      sbCache.set(url, { data: result, timestamp: now });
    }

    // return cached + freshly fetched results together
    return { ...cachedResults, ...fetchedResults };

  } catch (error) {
    clearTimeout(timeoutId);

    if (error.name === 'AbortError') {
      // fetch timed out — just continue without SB results, don't crash the whole analysis
      console.warn('[PhishGuard] Safe Browsing request timed out, skipping');
    } else {
      console.warn('[PhishGuard] Safe Browsing fetch failed:', error.message);
    }

    return cachedResults; // return whatever we had cached at least
  }
}

// ─── Rule-based analysis (unchanged) ─────────────────────────────────────────

function runRuleBasedAnalysis(emailData) {
  const indicators = [];
  let totalScore = 0;

  // URL Analysis (40 points)
  // links are now objects with { href, text, title, displayedDomain, actualDomain }
  // we pull out .href for all the string-based checks, same as before
  if (emailData.links && emailData.links.length > 0) {
    emailData.links.forEach(link => {
      // support both the old string format and the new object format, just in case
      const url = typeof link === 'string' ? link : (link.href || '');
      if (!url) return;

      if (/\.(tk|ml|ga|cf|gq)$/i.test(url)) {
        indicators.push('⚠️ Suspicious domain extension (.tk, .ml, .ga)');
        totalScore += 15;
      }

      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
        indicators.push('⚠️ IP address used instead of domain name');
        totalScore += 20;
      }

      if (/bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co/i.test(url)) {
        indicators.push('⚠️ URL shortener detected (hides destination)');
        totalScore += 10;
      }

      const commonBrands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'bank'];
      commonBrands.forEach(brand => {
        const typoPattern = new RegExp(brand.replace(/o/g, '[o0]').replace(/l/g, '[l1]').replace(/a/g, '[a4]'), 'i');
        if (typoPattern.test(url) && !url.toLowerCase().includes(brand + '.com')) {
          indicators.push(`🚨 Possible ${brand.toUpperCase()} brand impersonation in URL`);
          totalScore += 25;
        }
      });

      const subdomains = url.split('//')[1]?.split('/')[0]?.split('.') || [];
      if (subdomains.length > 4) {
        indicators.push('⚠️ Excessive subdomains (suspicious structure)');
        totalScore += 12;
      }

      // domain mismatch check — only possible now that links are objects.
      // this is one of the most common phishing tricks: show "www.paypal.com" as
      // the link text but actually point to a completely different domain.
      if (link.displayedDomain && link.actualDomain &&
          link.displayedDomain !== link.actualDomain) {
        indicators.push(`🚨 Link text shows "${link.displayedDomain}" but goes to "${link.actualDomain}"`);
        totalScore += 30;
      }
    });
  }

  // Sender Analysis (30 points)
  const senderEmail = emailData.sender.toLowerCase();
  const displayName = emailData.displayName.toLowerCase();
  const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'];
  const corporateNames = ['paypal', 'amazon', 'microsoft', 'apple', 'bank', 'irs', 'support', 'security', 'admin'];

  if (freeProviders.some(p => senderEmail.includes(p))) {
    if (corporateNames.some(c => displayName.includes(c))) {
      indicators.push('🚨 Corporate name using free email provider');
      totalScore += 20;
    }
  }

  const emailDomain = senderEmail.split('@')[1] || '';
  const domainBase = emailDomain.split('.')[0];

  if (displayName && domainBase && !displayName.includes(domainBase)) {
    if (corporateNames.some(c => displayName.includes(c))) {
      indicators.push('⚠️ Display name does not match sender domain');
      totalScore += 18;
    }
  }

  // Content Analysis (30 points)
  const bodyLower = emailData.body.toLowerCase();
  const subjectLower = emailData.subject.toLowerCase();
  const fullText = bodyLower + ' ' + subjectLower;

  const urgencyWords = ['urgent', 'immediate', 'expire', 'suspended', 'verify now', 'act now', 'limited time', 'within 24 hours', 'account will be closed'];
  const urgencyCount = urgencyWords.filter(w => fullText.includes(w)).length;

  if (urgencyCount >= 2) {
    indicators.push('⚠️ Multiple urgency keywords detected');
    totalScore += 15;
  } else if (urgencyCount === 1) {
    indicators.push('⚠️ Urgency language used');
    totalScore += 8;
  }

  if (/dear (customer|user|member|sir|madam|valued customer)/i.test(emailData.body)) {
    indicators.push('⚠️ Generic greeting (no personalization)');
    totalScore += 10;
  }

  if (/password|credit card|social security|ssn|account number|pin code|cvv|verify.*account|confirm.*identity/i.test(fullText)) {
    indicators.push('🚨 Requests sensitive information');
    totalScore += 25;
  }

  if (/account.*(closed|suspended|locked|terminated)|legal action|unauthorized.*activity|unusual.*activity/i.test(fullText)) {
    indicators.push('⚠️ Contains threats or alarming warnings');
    totalScore += 15;
  }

  if (/click.*here|click.*below|update.*now|verify.*now/i.test(fullText) && emailData.links.length > 0) {
    indicators.push('⚠️ Pressures user to click links');
    totalScore += 10;
  }

  // Grammar and spelling issues (simple check)
  const misspellings = ['recieve', 'seperate', 'occured', 'bussiness', 'adress'];
  if (misspellings.some(word => fullText.includes(word))) {
    indicators.push('⚠️ Spelling errors detected');
    totalScore += 8;
  }

  if (indicators.length === 0) {
    indicators.push('✓ No significant phishing indicators detected');
  }

  return {
    score: Math.min(totalScore, 100),
    indicators
  };
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function getRiskLevel(score) {
  if (score <= 30) return 'low';
  if (score <= 60) return 'medium';
  return 'high';
}

function generateCacheKey(emailData) {
  return `${emailData.sender}:${emailData.subject}:${emailData.body.substring(0, 100)}`;
}

// clean out expired entries from both caches so memory doesn't grow forever
function cleanCache() {
  const now = Date.now();

  for (const [key, value] of analysisCache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) {
      analysisCache.delete(key);
    }
  }

  for (const [key, value] of sbCache.entries()) {
    if (now - value.timestamp > SB_CACHE_DURATION) {
      sbCache.delete(key);
    }
  }
}

chrome.runtime.onStartup.addListener(() => {
  // service workers can be killed and restarted by Chrome at any time,
  // so in-memory caches get wiped on restart anyway — this is just explicit cleanup
  analysisCache.clear();
  sbCache.clear();
});

// ─── Dev helper: Safe Browsing sanity check ───────────────────────────────────
//
// To run this, open chrome://extensions → find PhishGuard → click "service worker"
// to open its DevTools console, then type: testSafeBrowsing()
//
// It hits the API with one known-clean URL and one that Google permanently keeps
// flagged for exactly this kind of testing, so you can verify both paths work.

async function testSafeBrowsing() {
  console.log('[PhishGuard test] Starting Safe Browsing API check...');

  if (!SAFE_BROWSING_API_KEY || SAFE_BROWSING_API_KEY === 'YOUR_API_KEY_HERE') {
    console.warn('[PhishGuard test] ✗ No API key set — add your key to SAFE_BROWSING_API_KEY in service-worker.js');
    return;
  }

  // Google maintains these test URLs permanently for this exact purpose:
  // the phishing one is always flagged, google.com is always clean
  const TEST_URLS = [
    'https://testsafebrowsing.appspot.com/s/phishing.html', // should come back malicious
    'https://google.com',                                    // should come back clean
  ];

  // bypass the sbCache so we always make a real network call during the test
  // (otherwise a cached result could mask a broken API key)
  const savedCache = new Map(sbCache);
  TEST_URLS.forEach(url => sbCache.delete(url));

  try {
    const results = await checkSafeBrowsing(TEST_URLS);

    const flagged = results['https://testsafebrowsing.appspot.com/s/phishing.html'];
    const clean   = results['https://google.com'];

    const flaggedOk = flagged?.malicious === true;
    const cleanOk   = clean?.malicious   === false;

    if (flaggedOk && cleanOk) {
      console.log('[PhishGuard test] ✓ API is working correctly');
      console.log('  → known-malicious URL flagged:', flagged.threatTypes.join(', '));
      console.log('  → google.com returned clean ✓');
    } else {
      if (!flaggedOk) console.warn('[PhishGuard test] ✗ Known-malicious URL was NOT flagged — check your API key and quota');
      if (!cleanOk)   console.warn('[PhishGuard test] ✗ google.com came back as malicious — something is very wrong');
    }

  } catch (err) {
    console.error('[PhishGuard test] ✗ Test failed with error:', err.message);
  } finally {
    // restore the cache to how it was before the test ran
    TEST_URLS.forEach(url => {
      if (savedCache.has(url)) sbCache.set(url, savedCache.get(url));
      else sbCache.delete(url);
    });
  }
}