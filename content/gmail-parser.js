// PhishGuard Gmail Parser
// This file runs as a content script inside Gmail and pulls out the email data
// so we can send it to the service worker for analysis.
// Basically we're just poking around the Gmail DOM and grabbing what we need.

// set this to true if something breaks and you want to see what's going on in the console
const DEBUG = false;

// ─── Message listener ────────────────────────────────────────────────────────

// The popup can't directly touch the Gmail page, so it sends us a message
// and we do the DOM stuff on its behalf, then send the data back
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'EXTRACT_EMAIL') {
    extractEmailData()
      .then(sendResponse)
      .catch(error => sendResponse({ error: error.message }));

    // return true tells Chrome we're going to call sendResponse asynchronously
    // (without this the message port closes before we finish and things break)
    return true;
  }
});

// ─── Container scoping ───────────────────────────────────────────────────────

// Gmail threads show multiple emails stacked on top of each other.
// If we just use document.querySelector we might accidentally grab info
// from an old collapsed message instead of the one the user is looking at.
// So this function finds the specific message that's currently expanded/visible.
function getActiveMessageContainer() {
  // every message in a thread gets wrapped in a div.adn
  // (adn = "a dn" something? Gmail's class names are minified so who knows lol)
  const allMessages = document.querySelectorAll('div.adn');

  let activeContainer = null;

  for (const msg of allMessages) {
    // if a message has a body div inside it, that means it's expanded
    // collapsed messages don't render their body at all
    if (msg.querySelector('div.a3s.aiL') || msg.querySelector('div.ii.gt')) {
      activeContainer = msg;
      // don't break here! in a thread the newest reply is at the bottom,
      // so we keep looping and end up with the last expanded one
    }
  }

  if (DEBUG) {
    console.debug('[PhishGuard] picked container:', activeContainer);
  }

  return activeContainer; // could be null if nothing is expanded yet
}

// ─── Main extraction function (MutationObserver) ──────────────────────────────

// Gmail is a single-page app — it never does a full page reload when you open
// a new email, it just swaps DOM nodes in and out. So instead of retrying on a
// fixed timer, we watch for the email body to actually appear in the DOM.

async function extractEmailData() {
  return new Promise((resolve, reject) => {

    // quick sanity check — if there's no main content area we're not in an email at all
    const emailView = document.querySelector('div[role="main"]');
    if (!emailView) {
      reject(new Error('No email open. Please open an email to analyze.'));
      return;
    }

    // helper that tries to grab all the fields and resolves if everything looks good
    function tryExtract() {
      const container = getActiveMessageContainer();

      if (DEBUG) {
        console.debug('[PhishGuard] trying extraction — container:', container || 'none, falling back to document');
      }

      const attachmentInfo = extractAttachments(container);

      const data = {
        sender:          extractSender(container),
        displayName:     extractDisplayName(container),
        subject:         extractSubject(container),
        body:            extractBody(container),        // bodyClean, for compatibility
        bodyFull:        extractBodyFull(container),    // raw full text including quoted replies
        links:           extractLinks(container),
        attachments:     attachmentInfo.attachments,
        hasAttachments:  attachmentInfo.hasAttachments,
        attachmentCount: attachmentInfo.attachmentCount,
        timestamp:       Date.now()
      };

      // only resolve if we actually got the important stuff
      // if the body isn't loaded yet these will be empty strings
      if (data.sender && data.subject && data.body) {
        return data;
      }

      return null; // not ready yet
    }

    // try immediately in case the email is already fully loaded
    // (e.g. user clicked analyze after the email has been open for a while)
    const immediate = tryExtract();
    if (immediate) {
      resolve(immediate);
      return;
    }

    // email isn't ready yet — set up a MutationObserver to watch for DOM changes.
    // Gmail injects the email body asynchronously, so we just wait for it to show up.
    const observer = new MutationObserver(() => {
      // every time Gmail touches the DOM, check if our email body is there yet
      const data = tryExtract();
      if (data) {
        observer.disconnect(); // stop watching, we got what we needed
        resolve(data);
      }
    });

    // watch the whole main content area for any DOM additions/changes
    // subtree: true means we catch changes at any depth, not just direct children
    observer.observe(emailView, { childList: true, subtree: true });

    // safety net: if the email never loads after 5 seconds, give up
    // (this shouldn't happen in normal use, but better than hanging forever)
    setTimeout(() => {
      observer.disconnect();
      reject(new Error('Timed out waiting for email to load. Please make sure an email is open.'));
    }, 5000);
  });
}

// ─── Individual field extractors ──────────────────────────────────────────────

// each function takes an optional `root` element to search inside.
// if root is null (no container found) we fall back to searching the whole document.

function extractSender(root) {
  const scope = root || document; // if we didn't find a container, just search the whole page
  let sender = null;

  // best case: Gmail puts the real email address in an 'email' attribute on a span
  // e.g. <span email="bob@example.com">Bob</span>  — super convenient
  const emailSpan = scope.querySelector('span[email]');
  if (emailSpan) {
    sender = emailSpan.getAttribute('email');
  }

  // sometimes the email shows up as visible text like "Bob <bob@example.com>"
  // so we pull the part inside the angle brackets with a regex
  if (!sender) {
    const emailText = scope.querySelector('span.gD');
    if (emailText) {
      const match = emailText.textContent.match(/<(.+?)>/);
      if (match) {
        sender = match[1]; // match[1] is the captured group inside < >
      }
    }
  }

  // last ditch effort — just find anything that looks like an email address in the sender table
  if (!sender) {
    const senderInfo = scope.querySelector('table.cf.gJ');
    if (senderInfo) {
      const emailMatch = senderInfo.textContent.match(/[\w\.-]+@[\w\.-]+\.\w+/);
      if (emailMatch) {
        sender = emailMatch[0];
      }
    }
  }

  return sender;
}

function extractDisplayName(root) {
  const scope = root || document;

  // span.go usually holds the friendly display name like "PayPal Support"
  const nameSpan = scope.querySelector('span.go');
  if (nameSpan) {
    return nameSpan.textContent.trim();
  }

  // fallback: in the sender table, the name element sits right before the email span
  const senderLine = scope.querySelector('table.cf.gJ span[email]');
  if (senderLine && senderLine.previousElementSibling) {
    return senderLine.previousElementSibling.textContent.trim();
  }

  return ''; // couldn't find a display name, that's okay — it's optional
}

function extractSubject(root) {
  const scope = root || document;
  let subject = null;

  // the subject is actually a thread-level thing, not per-message,
  // so it might live outside our container — we try scoped first, then fall back to document

  // in thread view the subject is usually an h2 with class hP
  subject = (scope.querySelector('h2.hP') || document.querySelector('h2.hP'))?.textContent.trim() || null;

  if (!subject) {
    // sometimes it's a span instead of h2 for some reason ¯\_(ツ)_/¯
    subject = (scope.querySelector('span.hP') || document.querySelector('span.hP'))?.textContent.trim() || null;
  }

  if (!subject) {
    // older Gmail layout puts it inside a div.ha
    subject = (scope.querySelector('div.ha h2') || document.querySelector('div.ha h2'))?.textContent.trim() || null;
  }

  return subject || '';
}

// ─── Part E: DOM-based quote removal ─────────────────────────────────────────

// Old approach: grab innerText, then run regex over the plain text to find quote markers.
// Problem: regex on plain text is fragile. "On Mon wrote:" might appear in a legit sentence.
// Also, multi-line quoted blocks don't always have consistent markers across email clients.
//
// Better approach: work on the DOM *before* calling innerText.
// Gmail actually marks up quoted sections with real HTML elements (blockquote, .gmail_quote, etc.)
// We can clone the body div, surgically remove those elements, then read innerText from the clone.
// That way we're removing whole semantic blocks, not guessing from line patterns.
// The original DOM is untouched because we're working on a clone — no side effects.

// quote selectors — elements that reliably wrap reply/history content in Gmail HTML
const QUOTE_SELECTORS = [
  'blockquote',               // standard HTML blockquote (most email clients use this)
  '.gmail_quote',             // Gmail's own class for quoted sections
  '.gmail_extra',             // Gmail appends this div after the reply area
  '[id*="gmail_quote"]',      // some Gmail versions use an id instead of class
  '.yahoo_quoted',            // Yahoo Mail quoted replies
  '.WordSection1 > div > div' // Outlook-generated forwarded content (rough heuristic)
];

// extractBody returns bodyClean — the "real" new message without reply history.
// This is what we use for phishing analysis because reply chains add noise.
// The field is still called "body" in the output for backward compatibility.
function extractBody(root) {
  const scope = root || document;

  const bodyDiv = findBodyDiv(scope);
  if (!bodyDiv) return '';

  // clone the element so we can mutate it without touching the actual Gmail page
  const clone = bodyDiv.cloneNode(true); // true = deep clone, copies all children

  // remove all quote/history elements from the clone
  // querySelectorAll on the clone works fine even though it's detached from the document
  QUOTE_SELECTORS.forEach(selector => {
    clone.querySelectorAll(selector).forEach(el => el.remove());
  });

  return clone.innerText.trim();
}

// extractBodyFull returns the entire body text including quoted replies.
// Useful if we ever want to analyze the full thread context or display it.
function extractBodyFull(root) {
  const scope = root || document;

  const bodyDiv = findBodyDiv(scope);
  if (!bodyDiv) return '';

  // no clone needed — we're just reading, not modifying
  return bodyDiv.innerText.trim();
}

// shared helper so extractBody and extractBodyFull both find the div the same way
function findBodyDiv(scope) {
  // primary selector
  const primary = scope.querySelector('div.a3s.aiL');
  if (primary) return primary;

  // fallback for some email layouts
  const alt = scope.querySelector('div.ii.gt');
  if (alt) return alt;

  // some rich HTML emails load inside an iframe (same-origin so we can access it)
  const iframe = scope.querySelector('iframe.adn');
  if (iframe && iframe.contentDocument) {
    return iframe.contentDocument.body;
  }

  return null;
}

// ─── Part D: Attachment extraction ───────────────────────────────────────────

// We're not downloading anything — just reading the filenames Gmail displays in the UI.
// This is useful for phishing detection because dangerous file types (.exe, .js, .zip, etc.)
// attached to urgent emails are a huge red flag.

// file extensions that are commonly used to deliver malware
// (not exhaustive, just the most common ones worth flagging)
const RISKY_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'pif', 'scr', // Windows executables
  'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh',  // scripts
  'ps1', 'psm1',                              // PowerShell
  'jar', 'class',                             // Java
  'zip', 'rar', '7z', 'tar', 'gz',           // archives (often contain malware)
  'iso', 'img',                               // disk images
  'doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm', // macro-enabled Office files (the m suffix)
  'htm', 'html',                              // html attachments can run scripts
]);

function extractAttachments(root) {
  const scope = root || document;
  const attachments = [];

  // Gmail shows attachment chips/tiles in a few different places depending on the layout.
  // We try a few selectors and use whatever works.
  // span.aV3 is the filename span inside each attachment chip in most Gmail versions.
  const filenameEls = scope.querySelectorAll('span.aV3');

  // fallback: some layouts use a different class or a data attribute
  const fallbackEls = filenameEls.length === 0
    ? scope.querySelectorAll('[download-url], [data-tooltip*="."]')
    : [];

  const allEls = filenameEls.length > 0 ? filenameEls : fallbackEls;

  allEls.forEach(el => {
    // get the filename — could be in textContent or a data attribute
    const filename = (
      el.textContent.trim() ||
      el.getAttribute('aria-label') ||
      el.getAttribute('download-url') ||
      ''
    ).trim();

    if (!filename) return;

    // pull out the extension (everything after the last dot, lowercased)
    const dotIndex = filename.lastIndexOf('.');
    const extension = dotIndex !== -1 ? filename.slice(dotIndex + 1).toLowerCase() : '';

    // check if this is the kind of file you'd never expect in a legit email
    const isRiskyType = RISKY_EXTENSIONS.has(extension);

    attachments.push({ filename, extension, isRiskyType });
  });

  return {
    attachments,
    hasAttachments:  attachments.length > 0,
    attachmentCount: attachments.length
  };
}

// ─── Part B: Richer link extraction ──────────────────────────────────────────

// Previously we returned a flat array of URL strings.
// Now we return objects that include the visible link text alongside the real URL.
// This matters a lot for phishing detection! A classic trick is to show the user
// "www.paypal.com" as the link text but actually point to "evil-site.ru".
// With just the URL we'd miss that the displayed text is trying to impersonate PayPal.

function extractLinks(root) {
  const scope = root || document;
  const links = [];
  const seenHrefs = new Set(); // track destinations so we don't add the same link twice

  // look for links only inside the body, not the whole page
  // (otherwise we'd grab Gmail's own nav links and that would throw off everything)
  const bodyDiv = scope.querySelector('div.a3s.aiL') || scope.querySelector('div.ii.gt');
  if (!bodyDiv) return links;

  const anchors = bodyDiv.querySelectorAll('a[href]');

  anchors.forEach(anchor => {
    const rawHref = anchor.getAttribute('href');

    // skip anchor links (#section) and mailto: links — those aren't phishing URLs
    if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('mailto:')) return;

    // Gmail redirects every link through google.com/url?q=... for click tracking.
    // unwrap it so we see the real destination URL.
    const href = cleanGoogleUrl(rawHref);
    if (!href) return;

    // deduplicate by actual destination — same URL might appear multiple times in an email
    if (seenHrefs.has(href)) return;
    seenHrefs.add(href);

    // grab the visible text the user sees for this link.
    // trim it because Gmail sometimes pads with whitespace.
    const text = anchor.textContent.trim();

    // title attribute is sometimes set on links, can be informative
    const title = anchor.getAttribute('title') || null;

    // parse the domains out of both the displayed text and the real href.
    // we need the actual domain from the href to compare against what the user sees.
    // using new URL() is cleaner than regex for this — it handles edge cases better.
    const displayedDomain = extractDomainFromText(text);  // what user thinks they're clicking
    const actualDomain    = extractDomainFromUrl(href);   // where they'd actually end up

    links.push({
      href,            // the real destination (unwrapped from Gmail redirect)
      text,            // visible link text, e.g. "Click here" or "www.paypal.com"
      title,           // optional title attribute (often null)
      displayedDomain, // domain parsed from visible text if it looks like a URL
      actualDomain,    // domain parsed from the real href
    });
  });

  return links;
}

// try to parse the hostname out of a URL string using the URL API.
// returns just the hostname like "example.com" or null if it fails.
function extractDomainFromUrl(url) {
  try {
    // URL() constructor throws if the string isn't a valid absolute URL
    return new URL(url).hostname;
  } catch {
    return null; // wasn't a valid URL, no big deal
  }
}

// check if the visible link text itself looks like a URL and if so parse its domain.
// phishing emails often use a legit-looking URL as the display text to fool people.
// e.g. anchor text = "https://paypal.com" but href points somewhere else entirely.
function extractDomainFromText(text) {
  if (!text) return null;

  // if the text starts with http/https, try parsing it directly as a URL
  if (text.startsWith('http://') || text.startsWith('https://')) {
    return extractDomainFromUrl(text);
  }

  // sometimes the text is just a bare domain like "www.paypal.com"
  // we can try prepending https:// and seeing if URL() accepts it
  if (text.includes('.') && !text.includes(' ')) {
    return extractDomainFromUrl('https://' + text);
  }

  // text doesn't look like a URL (e.g. "Click here to verify"), return null
  return null;
}

// ─── Part C: Stronger redirect unwrapping ────────────────────────────────────

// Gmail wraps every outgoing link in a redirect like:
// https://www.google.com/url?q=https%3A%2F%2Factually-sketchy.com&...
//
// Sometimes the inner URL is encoded multiple times — like the attacker
// ran their URL through encodeURIComponent twice to try to slip past scanners.
// We loop up to 3 times to fully unwrap it.
//
// If anything goes wrong at any step we return the original URL rather than
// crashing or returning null — better to have a messy URL than nothing.

function cleanGoogleUrl(url) {
  // only bother unwrapping if it's actually a Google redirect
  if (!url.includes('google.com/url?')) {
    return url;
  }

  try {
    // pull out the ?q= or ?url= parameter — that's where the real destination lives
    const queryString = url.split('?')[1];
    if (!queryString) return url;

    const urlParams = new URLSearchParams(queryString);
    const rawTarget = urlParams.get('q') || urlParams.get('url');
    if (!rawTarget) return url;

    // decode up to 3 times to handle nested/double encoding.
    // we stop early if the string stops changing (means it's fully decoded).
    let decoded = rawTarget;
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break; // nothing left to decode, we're done
        decoded = next;
      } catch {
        // decodeURIComponent throws on malformed % sequences like "%zz"
        // just stop decoding and use what we have
        break;
      }
    }

    return decoded;

  } catch {
    // something unexpected went wrong — fall back to the original URL
    return url;
  }
}

// just a debug helper — call this manually in the console if you want to see what got extracted
function logExtraction(data) {
  console.log('PhishGuard: Extracted email data', {
    sender:          data.sender,
    subject:         data.subject,
    bodyLength:      data.body.length,
    bodyFullLength:  data.bodyFull.length,
    linkCount:       data.links.length,
    attachmentCount: data.attachmentCount
  });
}