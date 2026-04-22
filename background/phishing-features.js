// ─── phishing-features.js ─────────────────────────────────────────────────────
//
// THE HEURISTIC LAYER — sole source of truth for all rule-based signal detection.
//
// Architecture contract:
//   • This file owns ALL regex / keyword / pattern checks.
//   • service-worker.js handles external reputation (Safe Browsing, URLhaus,
//     OpenPhish, PhishStats) and must NOT duplicate any check from here.
//   • To tune a rule, edit RULE_CONFIG — no logic changes needed.
//
// Exports (via self.* for importScripts compatibility):
//   runHeuristicAnalysis(emailData)   → { score, indicators, flags }
//   runDatasetChecks(emailData, urls) → { score, indicators }  [async]
//   normalizeUrl(url)                 → string
//
// The `flags` object is a de-duplication contract read by service-worker.js
// to avoid double-counting signals already caught here.
//
// DETECTION PHILOSOPHY:
//   Detection is behavior-based, not keyword-based.  Instead of matching the
//   exact phrase "your account has been suspended", we match the behavioral
//   pattern: a "problem concept" (failed / suspended / on hold / issue / unable
//   to deliver) paired with an "action concept" (click / confirm / update /
//   login / track).  This catches new phishing templates that use synonyms or
//   rearranged phrasing the old keyword lists never saw.
//
// TRUSTED DOMAINS (Tranco top-10k):
//   Loaded once at startup from tranco-top-10k.txt (bundled with the extension).
//   Trusted status does NOT bypass detection — it only:
//     • Suppresses weak brand-impersonation false positives on the host itself
//     • Applies a small score reduction (-5, min 0) when only minor flags fired
//   Strong signals (credential request, hidden text, account threats, shipping
//   scams from unrelated domains, etc.) are never suppressed.
//
// DATA SOURCES (feeds, managed by this file):
//   • PhishStats  — community-verified phishing URL blacklist
//   • OpenPhish   — active phishing feed (free tier, ~12 h cadence)
//   Corpus-derived weights:
//   • SpamAssassin public corpus — body heuristic weights
//   • Nazario phishing corpus    — sender / obfuscation patterns
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

// ─── Trusted domain list ──────────────────────────────────────────────────────

let trustedDomains       = new Set();
let trustedDomainsLoaded = false;

/**
 * Load Tranco top-10k domains bundled with the extension.
 * Called once at module load (see bottom of file).
 * Failures are non-fatal — detection continues with an empty trusted set.
 */
async function loadTrustedDomains() {
  try {
    const url      = chrome.runtime.getURL('tranco-top-10k.txt');
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const text = await response.text();
    trustedDomains = new Set(
      text.split('\n')
          .map(d => d.trim().toLowerCase())
          .filter(Boolean)
    );
    trustedDomainsLoaded = true;
    console.log(`[PhishGuard] Loaded ${trustedDomains.size} trusted domains from Tranco`);
  } catch (err) {
    console.warn('[PhishGuard] Failed to load trusted domains — false-positive suppression disabled:', err.message);
  }
}

/**
 * Returns true if `host` is in the trusted set OR is a subdomain of a trusted
 * domain (e.g. "mail.google.com" → trusted because "google.com" is trusted).
 *
 * @param {string} host — hostname, already lowercased
 */
function isTrustedDomain(host) {
  if (!host || !trustedDomainsLoaded) return false;
  if (trustedDomains.has(host)) return true;

  // Walk up the label hierarchy: a.b.c.com → b.c.com → c.com
  const parts = host.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (trustedDomains.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

// ─── Master rule configuration ────────────────────────────────────────────────
//
// Score bands enforced in service-worker.js:
//   0 – 29  → LOW     (informational)
//  30 – 59  → MEDIUM  (warn user)
//  60 – 100 → HIGH    (block / strong warning)
//
// Weights are calibrated so that:
//   • Any single minor flag              ≤ 15 pts  (stays in LOW)
//   • Clearly phishing email heuristics   55–75 pts (HIGH before external checks)
//   • External checks push the rest to 100

const RULE_CONFIG = {

  // ── URL checks ────────────────────────────────────────────────────────────
  url: {
    suspiciousTLDs:        /\.(tk|ml|ga|cf|gq)$/i,
    ipAddress:             /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/,
    urlShorteners:         /bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co/i,
    excessiveSubdomains:   4,    // flag if label count > this (a.b.c.d.com = 5)
    trustedScoreReduction: 5,    // applied when trusted host has other minor flags

    // Canonical brand domains — typosquat check only runs on untrusted hosts.
    // Each entry: { name, canonical } where canonical is the exact registered
    // domain (no www) that is always legitimate.
    brands: [
      { name: 'paypal',        canonical: 'paypal.com'        },
      { name: 'amazon',        canonical: 'amazon.com'        },
      { name: 'microsoft',     canonical: 'microsoft.com'     },
      { name: 'apple',         canonical: 'apple.com'         },
      { name: 'facebook',      canonical: 'facebook.com'      },
      { name: 'google',        canonical: 'google.com'        },
      { name: 'netflix',       canonical: 'netflix.com'       },
      { name: 'chase',         canonical: 'chase.com'         },
      { name: 'wellsfargo',    canonical: 'wellsfargo.com'    },
      { name: 'bankofamerica', canonical: 'bankofamerica.com' },
      // Shipping carriers — used by both URL and shipping-scam checks
      { name: 'ups',           canonical: 'ups.com'           },
      { name: 'usps',          canonical: 'usps.com'          },
      { name: 'fedex',         canonical: 'fedex.com'         },
      { name: 'dhl',           canonical: 'dhl.com'           },
    ],

    scores: {
      suspiciousTLD:       15,
      ipAddress:           20,
      urlShortener:        10,
      brandImpersonation:  25,
      excessiveSubdomains: 12,
      domainMismatch:      30,
    },
  },

  // ── Sender / domain checks ────────────────────────────────────────────────
  sender: {
    freeProviders: ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'],

    // Corporate display-name terms that suggest a known brand.
    // Also used by shipping-scam check (shipping brands are a subset).
    corporateTerms: [
      'paypal', 'amazon', 'microsoft', 'apple', 'bank', 'irs',
      'support', 'security', 'admin', 'netflix', 'chase',
      'ups', 'usps', 'fedex', 'dhl', 'shipping', 'delivery', 'parcel',
    ],

    // Shipping carrier names specifically — used for the delivery-scam check.
    shippingBrands: ['ups', 'usps', 'fedex', 'dhl'],

    // Brand domain patterns: match brand + separator + something NOT the
    // canonical suffix, to avoid flagging apple.com, ups.com, etc.
    brandDomainPatterns: [
      /paypal[-.](?!com\b)/i,
      /amazon[-.](?!com\b|co\b)/i,
      /apple[-.](?!com\b)/i,
      /microsoft[-.](?!com\b)/i,
      /google[-.](?!com\b)/i,
      /netflix[-.](?!com\b|net\b)/i,
      /chase[-.](?!com\b)/i,
      /wellsfargo[-.](?!com\b)/i,
      /bankofamerica[-.](?!com\b)/i,
      /\birs[-.](?!gov\b)/i,
      // Shipping carriers
      /\bups[-.](?!com\b)/i,
      /\busps[-.](?!com\b)/i,
      /\bfedex[-.](?!com\b)/i,
      /\bdhl[-.](?!com\b)/i,
    ],

    suspiciousCompoundTLD:  /\.(biz|info|online|site|xyz|top|click|link|store|shop|vip|work)\.\w{2}$|\.(biz|info|xyz|top|click|link|store|shop|vip|work)$/i,
    excessiveSubdomains:    3,
    randomLocalPartMinLen:  20,

    scores: {
      corporateFreeProvider:              20,
      displayNameDomainMismatch:           8,
      shippingBrandUntrustedDomain:       28,  // shipping claim + unrelated sender domain
      brandDomainImpersonation:           20,
      suspiciousCompoundTLD:              15,
      excessiveSubdomains:                15,
      randomLocalPart:                     8,
      randomDomainSegments:                8,
      replyToMismatch:                     5,
      noReplyMismatch:                     8,
    },
  },

  // ── Behavior-based content patterns ──────────────────────────────────────
  //
  // Instead of matching single exact phrases, we use grouped concept regexes:
  //   PROBLEM CONCEPT  — something bad happened / is happening
  //   ACTION CONCEPT   — user is asked to do something about it
  //
  // Firing when BOTH are present in the same email is a strong phishing signal
  // (it models the "scare + hook" pattern common to 80%+ of phishing templates).
  behavior: {
    // Something went wrong / is at risk
    problemConcept: /(?:fail(?:ed|ure)|on\s+hold|suspend(?:ed|ension)|terminat(?:ed|ion)|expir(?:ed|ing)|block(?:ed|ing)|lock(?:ed|out)|unauthorized|unusual\s+activit|unable\s+to\s+deliver|delivery\s+(?:fail|exception|issue|problem|attempt)|shipment\s+(?:hold|issue|delay|problem)|package\s+(?:hold|issue|return)|issue\s+with\s+(?:your|the)|problem\s+with\s+(?:your|the)|action\s+required|attention\s+required)/i,

    // User is asked to act
    actionConcept: /(?:click|tap|follow|visit|go\s+to|open|confirm|verify|validate|update|complete|provide|submit|login|log\s+in|sign\s+in|track|reschedule|schedule\s+(?:delivery|redelivery)|pay\s+(?:fee|charge)|enter\s+(?:your|details)|fill\s+(?:out|in))/i,

    // Delivery / shipping specific problem language
    deliveryProblem: /(?:delivery\s+(?:fail(?:ed|ure)|attempt|exception|notice|notification|problem|issue)|unable\s+to\s+deliver|package\s+(?:on\s+hold|returned?|undeliverable|awaiting)|shipment\s+(?:on\s+hold|held?|delayed?|exception)|parcel\s+(?:held?|awaiting|on\s+hold)|confirm\s+(?:your\s+)?(?:address|delivery|shipment)|reschedule\s+(?:delivery|shipment)|track\s+(?:your\s+)?(?:package|parcel|shipment)|redelivery\s+fee|customs\s+(?:fee|charge|hold))/i,

    // Credential / identity harvest language
    credentialRequest: /(?:password|credit\s*card|social\s*security|(?:^|\s)ssn(?:\s|$)|account\s*number|pin\s*code|cvv|billing\s+(?:info|details)|payment\s+(?:info|details)|bank\s+(?:info|details))|(?:(?:confirm|verify|validate|update|enter)\s+(?:your\s+)?(?:account|identity|information|details|credentials|card|address|payment))/i,

    scores: {
      problemActionPair:     22,  // both problem + action present
      problemOnly:            8,  // problem concept without explicit action CTA
      deliveryScam:          20,  // delivery problem language in email
      credentialRequest:     25,
    },
  },

  // ── Body / content checks ─────────────────────────────────────────────────
  content: {
    urgencyPhrases: [
      'urgent', 'immediate', 'expire', 'suspended', 'verify now',
      'act now', 'limited time', 'within 24 hours', 'account will be closed',
    ],

    misspellings: ['recieve', 'seperate', 'occured', 'bussiness', 'adress'],

    scores: {
      urgencySingle:            5,
      urgencyMultiple:         10,
      genericGreeting:         10,
      clickPressure:            6,
      misspellings:             8,
      prizeLure:               12,
      formSubmission:          15,
      obfuscatedFree:           8,
      allCapsSubject:           7,
      excessiveExclamations:    6,
      // Low-context phishing: short body + link + strong CTA
      lowContextHighCTA:       18,  // replaces the old low-weight linkHeavyLowText
      financialUrgency:         8,
      hiddenText:              22,
      attachmentPrompt:         5,
      unsubscribeWithScore:     2,
    },
  },

  // ── Attachment checks ─────────────────────────────────────────────────────
  attachment: {
    scores: {
      riskyType: 20, // per risky attachment
    },
  },
};

// ─── Feed config ──────────────────────────────────────────────────────────────

const PHISHTANK_FEED_URL  = 'https://phishstats.info:2096/api/phishing?_where=(score,gte,5)&_size=500';
const OPENPHISH_FEED_URL  = 'https://openphish.com/feed.txt';
const FEED_CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

// ─── Feed state ───────────────────────────────────────────────────────────────

let phishTankUrls    = new Set();
let openPhishUrls    = new Set();
let lastFeedFetch    = 0;
let feedFetchPending = false;

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Run ALL local heuristic checks.
 * service-worker.js calls this first and must not replicate any sub-check here.
 *
 * @param  {object} emailData
 * @returns {{ score: number, indicators: string[], flags: object }}
 */
function runHeuristicAnalysis(emailData) {
  const indicators = [];
  let score = 0;

  // flags = de-duplication contract read by service-worker.js
  const flags = {
    hasSuspiciousSenderDomain: false,
    hasBrandImpersonation:     false,
    hasCredentialRequest:      false,
    hasAccountThreat:          false,
    hasExcessiveSubdomains:    false,
    hasShippingScam:           false,
  };

  const urlResult = checkUrls(emailData);
  score += urlResult.score;
  indicators.push(...urlResult.indicators);
  if (urlResult.flags.hasBrandImpersonation)  flags.hasBrandImpersonation  = true;
  if (urlResult.flags.hasExcessiveSubdomains) flags.hasExcessiveSubdomains = true;

  const senderResult = checkSender(emailData);
  score += senderResult.score;
  indicators.push(...senderResult.indicators);
  if (senderResult.flags.hasSuspiciousSenderDomain) flags.hasSuspiciousSenderDomain = true;
  if (senderResult.flags.hasBrandImpersonation)     flags.hasBrandImpersonation     = true;
  if (senderResult.flags.hasExcessiveSubdomains)    flags.hasExcessiveSubdomains    = true;
  if (senderResult.flags.hasShippingScam)           flags.hasShippingScam           = true;

  const behaviorResult = checkBehaviorPatterns(emailData);
  score += behaviorResult.score;
  indicators.push(...behaviorResult.indicators);
  if (behaviorResult.flags.hasCredentialRequest) flags.hasCredentialRequest = true;
  if (behaviorResult.flags.hasAccountThreat)     flags.hasAccountThreat     = true;

  const contentResult = checkContent(emailData);
  score += contentResult.score;
  indicators.push(...contentResult.indicators);

  const attachResult = checkAttachments(emailData);
  score += attachResult.score;
  indicators.push(...attachResult.indicators);

  // Guarantee score never goes negative
  score = Math.max(0, score);

  if (indicators.length === 0) {
    indicators.push('✓ No significant phishing indicators detected');
  }

  return { score, indicators, flags };
}

/**
 * Dataset-backed checks (PhishTank + OpenPhish feed lookups +
 * Nazario-derived sender patterns).
 * Call AFTER runHeuristicAnalysis(); intentionally non-overlapping with it.
 *
 * @param  {object}   emailData
 * @param  {string[]} urls — already-normalised URLs from normalizeLinks()
 * @returns {Promise<{ score: number, indicators: string[] }>}
 */
async function runDatasetChecks(emailData, urls) {
  const indicators = [];
  let score = 0;

  refreshFeedsIfStale(); // fire-and-forget; next call benefits from fresh data

  for (const url of urls) {
    const normalized = normalizeUrl(url);
    if (phishTankUrls.has(normalized)) {
      indicators.push(`🚨 PhishTank: confirmed phishing URL — ${url}`);
      score += 50;
    } else if (openPhishUrls.has(normalized)) {
      indicators.push(`🚨 OpenPhish: active phishing URL — ${url}`);
      score += 45;
    }
  }

  const senderDataset = analyzeSenderDatasetFeatures(emailData);
  score      += senderDataset.score;
  indicators.push(...senderDataset.indicators);

  return {
    score:      Math.min(score, 60), // dataset layer capped at 60 pts
    indicators,
  };
}

// ─── URL checks ───────────────────────────────────────────────────────────────

function checkUrls(emailData) {
  const indicators = [];
  let score = 0;
  const flags       = { hasBrandImpersonation: false, hasExcessiveSubdomains: false };
  const firedBrands = new Set();

  if (!emailData.links || emailData.links.length === 0) {
    return { score, indicators, flags };
  }

  const cfg = RULE_CONFIG.url;

  for (const link of emailData.links) {
    const url = typeof link === 'string' ? link : (link.href || '');
    if (!url) continue;

    // ── Resolve hostname first — all host-dependent checks follow ────────────
    let host = '';
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      // Malformed URL — skip host-dependent checks, run string-level checks
    }

    const trusted = host ? isTrustedDomain(host) : false;

    // ── String-level checks (always run) ─────────────────────────────────────

    if (cfg.suspiciousTLDs.test(url)) {
      indicators.push('⚠️ Suspicious domain extension (.tk, .ml, .ga, …)');
      score += cfg.scores.suspiciousTLD;
    }

    if (cfg.ipAddress.test(url)) {
      indicators.push('⚠️ IP address used instead of a domain name');
      score += cfg.scores.ipAddress;
    }

    if (cfg.urlShorteners.test(url)) {
      indicators.push('⚠️ URL shortener detected (hides real destination)');
      score += cfg.scores.urlShortener;
    }

    // ── Host-level checks ─────────────────────────────────────────────────────

    if (host) {
      const labelCount = host.split('.').length;
      if (labelCount > cfg.excessiveSubdomains) {
        indicators.push('⚠️ Excessive subdomains in link (suspicious structure)');
        score += cfg.scores.excessiveSubdomains;
        flags.hasExcessiveSubdomains = true;
      }

      // Brand typosquatting — only meaningful on untrusted hosts.
      // A trusted host containing a brand name is almost certainly legitimate.
      if (!trusted) {
        const brandHit = checkUrlBrandImpersonation(host, cfg.brands, firedBrands);
        if (brandHit) {
          indicators.push(`🚨 Possible ${brandHit.toUpperCase()} brand impersonation in URL`);
          score += cfg.scores.brandImpersonation;
          flags.hasBrandImpersonation = true;
          firedBrands.add(brandHit);
        }
      } else if (score > 0) {
        // Trusted host, but other flags already fired — soften minor pile-ons.
        score = Math.max(0, score - cfg.trustedScoreReduction);
      }
    }

    // ── Displayed vs. actual domain mismatch (always strong signal) ───────────
    if (link.displayedDomain && link.actualDomain &&
        link.displayedDomain !== link.actualDomain) {
      indicators.push(`🚨 Link text shows "${link.displayedDomain}" but goes to "${link.actualDomain}"`);
      score += cfg.scores.domainMismatch;
      flags.hasBrandImpersonation = true;
    }
  }

  return { score, indicators, flags };
}

/**
 * Check whether a URL hostname typosquats a known brand.
 * Only called on untrusted hosts.
 *
 * @param  {string}   host    — lowercased hostname
 * @param  {object[]} brands  — brand list from RULE_CONFIG.url.brands
 * @param  {Set}      fired   — brands already flagged this email (dedupe)
 * @returns {string|null}
 */
function checkUrlBrandImpersonation(host, brands, fired) {
  for (const { name, canonical } of brands) {
    if (fired.has(name)) continue;

    // Allow the canonical primary domain and legitimate subdomains of it
    if (host === canonical || host.endsWith(`.${canonical}`)) continue;

    // Leet-speak / homoglyph pattern for the brand name
    const pattern = new RegExp(
      name.replace(/o/g, '[o0]').replace(/l/g, '[l1]').replace(/a/g, '[a4]'),
      'i'
    );
    if (pattern.test(host)) return name;
  }
  return null;
}

// ─── Sender checks ────────────────────────────────────────────────────────────

function checkSender(emailData) {
  const indicators = [];
  let score = 0;
  const flags = {
    hasSuspiciousSenderDomain: false,
    hasBrandImpersonation:     false,
    hasExcessiveSubdomains:    false,
    hasShippingScam:           false,
  };

  const cfg         = RULE_CONFIG.sender;
  const senderEmail = (emailData.sender      || '').toLowerCase();
  const displayName = (emailData.displayName || '').toLowerCase();
  const domain      = senderEmail.split('@')[1] || '';
  const domainBase  = domain.split('.')[0];

  // If the sender's own domain is trusted, suppress weaker checks to avoid
  // false positives on real corporate senders (apple.com, ups.com, etc.).
  const senderTrusted = domain ? isTrustedDomain(domain) : false;

  // ── Corporate name from a free provider — strong signal always ────────────
  if (cfg.freeProviders.some(p => senderEmail.includes(p))) {
    if (cfg.corporateTerms.some(c => displayName.includes(c))) {
      indicators.push('🚨 Corporate name in display name but sent from a free email provider');
      score += cfg.scores.corporateFreeProvider;
      flags.hasBrandImpersonation = true;
    }
  }

  // ── Shipping brand claimed in display name, sender domain unrelated ────────
  //
  // This catches the classic "UPS Notifications <no-reply@track-pkg.store>"
  // pattern.  We score this strongly because a legitimate shipping carrier will
  // always send from a domain related to their own brand.
  if (!senderTrusted) {
    const claimsShippingBrand = cfg.shippingBrands.some(b => displayName.includes(b));
    const domainIsRelated     = cfg.shippingBrands.some(b => domain.includes(b));

    if (claimsShippingBrand && !domainIsRelated) {
      const matchedBrand = cfg.shippingBrands.find(b => displayName.includes(b)) || 'shipping carrier';
      indicators.push(`🚨 Sender claims to be ${matchedBrand.toUpperCase()} but domain is unrelated: ${domain}`);
      score += cfg.scores.shippingBrandUntrustedDomain;
      flags.hasBrandImpersonation = true;
      flags.hasShippingScam       = true;
    }
  }

  // ── Display name vs. domain mismatch — skip for trusted sender domains ────
  if (!senderTrusted && displayName && domainBase && !displayName.includes(domainBase)) {
    if (cfg.corporateTerms.some(c => displayName.includes(c))) {
      indicators.push('⚠️ Display name does not match sender domain');
      score += cfg.scores.displayNameDomainMismatch;
    }
  }

  // ── Suspicious compound / abused TLD ─────────────────────────────────────
  if (cfg.suspiciousCompoundTLD.test(domain)) {
    indicators.push('⚠️ Sender uses a TLD commonly associated with phishing campaigns');
    score += cfg.scores.suspiciousCompoundTLD;
    flags.hasSuspiciousSenderDomain = true;
  }

  // ── Excessive subdomains ──────────────────────────────────────────────────
  const dotCount = (domain.match(/\./g) || []).length;
  if (dotCount > cfg.excessiveSubdomains) {
    indicators.push('🚨 Sender domain has excessive subdomains (bulk-mailer pattern)');
    score += cfg.scores.excessiveSubdomains;
    flags.hasExcessiveSubdomains = true;
  }

  // ── Brand domain impersonation — skip for trusted sender domains ──────────
  if (!senderTrusted) {
    for (const pattern of cfg.brandDomainPatterns) {
      if (pattern.test(domain)) {
        indicators.push(`🚨 Sender domain impersonates a well-known brand: ${domain}`);
        score += cfg.scores.brandDomainImpersonation;
        flags.hasBrandImpersonation = true;
        break;
      }
    }
  }

  return { score, indicators, flags };
}

// ─── Behavior-pattern checks ──────────────────────────────────────────────────
//
// Models "scare + hook" phishing structure instead of matching exact phrases.
//
// PROBLEM CONCEPT — something bad happened / is at risk
// ACTION CONCEPT  — user must do something about it
//
// When both are present, the email matches the core phishing template regardless
// of the exact wording used.  This catches novel templates that escape narrow
// keyword lists.

function checkBehaviorPatterns(emailData) {
  const indicators = [];
  let score = 0;
  const flags = { hasCredentialRequest: false, hasAccountThreat: false };

  const bcfg    = RULE_CONFIG.behavior;
  const body    = emailData.body    || '';
  const subject = emailData.subject || '';
  const full    = (body + ' ' + subject).toLowerCase();

  const hasProblem    = bcfg.problemConcept.test(full);
  const hasAction     = bcfg.actionConcept.test(full);
  const hasDelivery   = bcfg.deliveryProblem.test(full);
  const hasCredential = bcfg.credentialRequest.test(full);

  // ── Problem + action pairing (core scare+hook pattern) ───────────────────
  if (hasProblem && hasAction) {
    indicators.push('🚨 Problem + action pattern detected (scare and hook phishing template)');
    score += bcfg.scores.problemActionPair;
    flags.hasAccountThreat = true;
  } else if (hasProblem) {
    // Problem concept present but no explicit action prompt — lower weight
    indicators.push('⚠️ Problematic account / delivery situation language detected');
    score += bcfg.scores.problemOnly;
  }

  // ── Delivery / shipping scam language ────────────────────────────────────
  if (hasDelivery) {
    indicators.push('🚨 Delivery or shipping failure language detected');
    score += bcfg.scores.deliveryScam;
    // Note: if checkSender() also flagged a shipping brand, the coordinator
    // will see flags.hasShippingScam and knows this is corroborated.
  }

  // ── Credential / sensitive information request ────────────────────────────
  if (hasCredential) {
    indicators.push('🚨 Requests sensitive information or credential verification');
    score += bcfg.scores.credentialRequest;
    flags.hasCredentialRequest = true;
  }

  return { score, indicators, flags };
}

// ─── Content checks ───────────────────────────────────────────────────────────
//
// Stylistic / presentation signals that complement the behavior layer.
// Credential and account-threat checks have moved to checkBehaviorPatterns().

function checkContent(emailData) {
  const indicators = [];
  let score = 0;

  const cfg     = RULE_CONFIG.content;
  const body    = emailData.body    || '';
  const subject = emailData.subject || '';
  const full    = (body + ' ' + subject).toLowerCase();
  const links   = emailData.links || [];

  // ── Urgency language ──────────────────────────────────────────────────────
  const urgencyCount = cfg.urgencyPhrases.filter(w => full.includes(w)).length;
  if (urgencyCount >= 2) {
    indicators.push(`⚠️ Multiple urgency phrases detected (${urgencyCount})`);
    score += cfg.scores.urgencyMultiple;
  } else if (urgencyCount === 1) {
    indicators.push('⚠️ Urgency language detected');
    score += cfg.scores.urgencySingle;
  }

  // ── Generic / impersonal greeting ─────────────────────────────────────────
  if (/dear\s+(?:customer|user|member|sir|madam|valued\s+customer)/i.test(body)) {
    indicators.push('⚠️ Generic greeting (no personalisation)');
    score += cfg.scores.genericGreeting;
  }

  // ── Click pressure (surface-level CTA language) ───────────────────────────
  if (/click.*here|click.*below|update.*now|verify.*now/i.test(full) && links.length > 0) {
    indicators.push('⚠️ Pressures user to click links');
    score += cfg.scores.clickPressure;
  }

  // ── Misspellings (SpamAssassin corpus) ───────────────────────────────────
  if (cfg.misspellings.some(w => full.includes(w))) {
    indicators.push('⚠️ Spelling errors detected (common in phishing templates)');
    score += cfg.scores.misspellings;
  }

  // ── Prize / reward lure (Nazario corpus) ─────────────────────────────────
  if (/(?:you(?:'ve|\s+have)\s+(?:been\s+selected|won)|congratulations|prize|reward|gift\s+card|claim\s+your)/i.test(full)) {
    indicators.push('⚠️ Prize or reward lure language');
    score += cfg.scores.prizeLure;
  }

  // ── In-email form submission request (Nazario corpus) ─────────────────────
  if (/(?:fill\s+(?:out|in)\s+(?:the\s+)?form|complete\s+(?:the\s+)?form|submit\s+(?:your\s+)?(?:information|details))/i.test(body)) {
    indicators.push('⚠️ Requests form submission within the email body');
    score += cfg.scores.formSubmission;
  }

  // ── Obfuscated "free" (SpamAssassin SUBJ_FREE_OFFER family) ──────────────
  if (/f[\W_]*r[\W_]*e[\W_]*e/i.test(full) && !/feel\s+free/i.test(full)) {
    indicators.push('⚠️ Obfuscated "free" text (spam filter evasion)');
    score += cfg.scores.obfuscatedFree;
  }

  // ── ALL-CAPS subject (SpamAssassin SUBJ_ALL_CAPS) ─────────────────────────
  if (subject.length > 5 && subject === subject.toUpperCase() && /[A-Z]{4,}/.test(subject)) {
    indicators.push('⚠️ Subject line in ALL CAPS');
    score += cfg.scores.allCapsSubject;
  }

  // ── Excessive exclamation marks ───────────────────────────────────────────
  const exclamationCount = (full.match(/!/g) || []).length;
  if (exclamationCount >= 3) {
    indicators.push(`⚠️ Excessive exclamation marks (${exclamationCount})`);
    score += cfg.scores.excessiveExclamations;
  }

  // ── Low-context phishing: very short body + link(s) + strong CTA ─────────
  //
  // Many phishing emails (especially delivery scams) are deliberately short:
  // a sentence or two, a link, and a button.  This pattern is rare in
  // legitimate transactional email, which typically includes order details,
  // tracking numbers, or personalisation.
  //
  // Fires when: word count < 60 AND at least one link AND action concept present.
  const wordCount = body.trim().split(/\s+/).length;
  if (wordCount < 60 && links.length >= 1 &&
      RULE_CONFIG.behavior.actionConcept.test(full)) {
    indicators.push('⚠️ Minimal body text with a call-to-action link (short-form phishing pattern)');
    score += cfg.scores.lowContextHighCTA;
  }

  // ── Financial amount + urgency pairing (SpamAssassin) ────────────────────
  if (/\$[\d,]+|\d+\s*(?:dollars?|USD)/i.test(body) &&
      /(?:urgent|immediately|today|now|expire|deadline)/i.test(full)) {
    indicators.push('⚠️ Financial amount paired with urgency language');
    score += cfg.scores.financialUrgency;
  }

  // ── Hidden text (Nazario corpus — CSS visibility tricks) ──────────────────
  if (/(?:color:\s*(?:white|#fff|#ffffff)|display:\s*none|visibility:\s*hidden)/i.test(body)) {
    indicators.push('🚨 Hidden text detected (anti-spam filter evasion)');
    score += cfg.scores.hiddenText;
  }

  // ── Attachment prompt ─────────────────────────────────────────────────────
  if (/(?:open|download|view)\s+(?:the\s+)?(?:attachment|file|document|invoice|receipt)/i.test(full)) {
    indicators.push('⚠️ Prompts user to open an attachment');
    score += cfg.scores.attachmentPrompt;
  }

  // ── Unsubscribe link alongside other signals (SpamAssassin) ──────────────
  if (/unsubscribe/i.test(body) && score > 25) {
    indicators.push('⚠️ Unsubscribe link present alongside other suspicious signals');
    score += cfg.scores.unsubscribeWithScore;
  }

  return { score, indicators };
}

// ─── Attachment checks ────────────────────────────────────────────────────────

function checkAttachments(emailData) {
  const indicators = [];
  let score = 0;

  if (!emailData.hasAttachments) return { score, indicators };

  const riskyAttachments = (emailData.attachments || []).filter(a => a.isRiskyType);
  if (riskyAttachments.length > 0) {
    const names = riskyAttachments.map(a => a.filename).join(', ');
    indicators.push(`🚨 Risky attachment type(s): ${names}`);
    score += RULE_CONFIG.attachment.scores.riskyType * riskyAttachments.length;
  }

  return { score, indicators };
}

// ─── Dataset-only sender features ────────────────────────────────────────────
//
// Nazario corpus patterns intentionally absent from heuristic sender checks
// to keep the two layers non-overlapping.

function analyzeSenderDatasetFeatures(emailData) {
  const indicators = [];
  let score = 0;

  const sender      = (emailData.sender      || '').toLowerCase();
  const displayName = (emailData.displayName || '').toLowerCase();
  const subject     = (emailData.subject     || '').toLowerCase();
  const domain      = sender.split('@')[1] || '';
  const localPart   = sender.split('@')[0] || '';
  const cfg         = RULE_CONFIG.sender;

  // Random-looking local part (UUID-style hex string before @)
  if (localPart.length > cfg.randomLocalPartMinLen && /[a-f0-9]{6,}/.test(localPart)) {
    indicators.push('⚠️ Sender address has a random-looking local part (machine-generated)');
    score += cfg.scores.randomLocalPart;
  }

  // Random alphanumeric segments inside the domain labels
  if (/\b[a-z]{2,6}\d{3,}\b|\b[a-z0-9]{8,}\b/.test(domain)) {
    indicators.push('⚠️ Sender domain contains random-looking alphanumeric segments');
    score += cfg.scores.randomDomainSegments;
  }

  // Display name claims no-reply but address doesn't match
  if (/(?:no.?reply|do.?not.?reply|automated|system|notification|alert|mailer.?daemon)/i.test(displayName) &&
      !sender.includes('noreply') && !sender.includes('no-reply')) {
    indicators.push('⚠️ Display name claims to be no-reply but address does not match');
    score += cfg.scores.noReplyMismatch;
  }

  // Subject instructs recipient to reply elsewhere
  if (/reply\s+to|respond\s+to|write\s+back\s+to/i.test(subject)) {
    indicators.push('⚠️ Subject instructs recipient to reply to a different address');
    score += cfg.scores.replyToMismatch;
  }

  return { score, indicators };
}

// ─── Feed refresh ─────────────────────────────────────────────────────────────

async function refreshFeedsIfStale() {
  const now = Date.now();
  if (feedFetchPending || (now - lastFeedFetch < FEED_CACHE_DURATION)) return;

  feedFetchPending = true;
  try {
    await Promise.allSettled([fetchPhishTankFeed(), fetchOpenPhishFeed()]);
    lastFeedFetch = Date.now();
  } finally {
    feedFetchPending = false;
  }
}

async function fetchPhishTankFeed() {
  try {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 8000);
    const response   = await fetch(PHISHTANK_FEED_URL, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn('[PhishGuard] PhishStats feed fetch failed:', response.status);
      return;
    }

    const data   = await response.json();
    const newSet = new Set();
    for (const entry of data) {
      if (entry.url) newSet.add(normalizeUrl(entry.url));
    }
    phishTankUrls = newSet;
    console.log(`[PhishGuard] PhishStats feed loaded: ${phishTankUrls.size} URLs`);
  } catch (err) {
    if (err.name !== 'AbortError') console.warn('[PhishGuard] PhishStats fetch error:', err.message);
  }
}

async function fetchOpenPhishFeed() {
  try {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 5000);
    const response   = await fetch(OPENPHISH_FEED_URL, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn('[PhishGuard] OpenPhish feed fetch failed:', response.status);
      return;
    }

    const text   = await response.text();
    const newSet = new Set();
    for (const line of text.split('\n')) {
      const url = line.trim();
      if (url && url.startsWith('http')) newSet.add(normalizeUrl(url));
    }
    openPhishUrls = newSet;
    console.log(`[PhishGuard] OpenPhish feed loaded: ${openPhishUrls.size} URLs`);
  } catch (err) {
    if (err.name !== 'AbortError') console.warn('[PhishGuard] OpenPhish fetch error:', err.message);
  }
}

// ─── URL normalization ────────────────────────────────────────────────────────

function normalizeUrl(url) {
  try {
    const u = new URL(url.trim());
    return `${u.protocol}//${u.hostname}${u.pathname}${u.search}`.replace(/\/$/, '');
  } catch {
    return url.trim().toLowerCase();
  }
}

// ─── Module init ──────────────────────────────────────────────────────────────
// Load the trusted domain list once at service-worker startup.
// Fire-and-forget: detection works immediately with no suppression until
// the async load completes, after which suppression activates automatically.

(async () => { await loadTrustedDomains(); })();

// ─── Exports ──────────────────────────────────────────────────────────────────

self.runHeuristicAnalysis = runHeuristicAnalysis;
self.runDatasetChecks     = runDatasetChecks;
self.normalizeUrl         = normalizeUrl;