// ─────────────────────────────────────────────────────────────────────────────
// PhishGuard Parser Tests
// HOW TO RUN:
//   1. Open Gmail and navigate to any email
//   2. Open DevTools (F12) → Console
//   3. Make sure the context dropdown says the Gmail tab (not an extension)
//      You need the content script context — look for "top" in the dropdown
//   4. Paste this entire file and hit Enter
//   5. Then call: runParserTests()
// ─────────────────────────────────────────────────────────────────────────────

function runParserTests() {
  // tiny test framework — just counts passes/fails and logs nicely
  let passed = 0;
  let failed = 0;

  function expect(label, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) {
      console.log(`  %c✓ ${label}`, 'color: #3ddc84');
      passed++;
    } else {
      console.warn(`  ✗ ${label}`);
      console.warn(`    expected:`, expected);
      console.warn(`    got:     `, actual);
      failed++;
    }
  }

  function expectTruthy(label, actual) {
    if (actual) {
      console.log(`  %c✓ ${label}`, 'color: #3ddc84');
      passed++;
    } else {
      console.warn(`  ✗ ${label} — got falsy:`, actual);
      failed++;
    }
  }

  function section(name) {
    console.log(`\n%c── ${name} ──`, 'color: #60a5fa; font-weight: bold');
  }

  // ── helpers ────────────────────────────────────────────────────────────────

  // build a detached DOM node from an HTML string so we can pass it to extractors
  // as if it were a real Gmail container — no actual page needed
  function html(str) {
    const div = document.createElement('div');
    div.innerHTML = str;
    return div;
  }

  // ── C: cleanGoogleUrl ──────────────────────────────────────────────────────

  section('C — cleanGoogleUrl (redirect unwrapping)');

  // basic case: single encoding with ?q=
  expect(
    'unwraps ?q= redirect',
    cleanGoogleUrl('https://www.google.com/url?q=https%3A%2F%2Fevil.com&sa=D'),
    'https://evil.com'
  );

  // ?url= variant
  expect(
    'unwraps ?url= redirect',
    cleanGoogleUrl('https://www.google.com/url?url=https%3A%2F%2Fsketchy.ru'),
    'https://sketchy.ru'
  );

  // double-encoded — attacker ran encodeURIComponent twice
  expect(
    'unwraps double-encoded redirect',
    cleanGoogleUrl('https://www.google.com/url?q=https%253A%252F%252Fmalicious.com'),
    'https://malicious.com'
  );

  // not a redirect at all — should come back unchanged
  expect(
    'passes through non-redirect URLs unchanged',
    cleanGoogleUrl('https://paypal.com/login'),
    'https://paypal.com/login'
  );

  // malformed encoding — should not throw, just return what it can
  expectTruthy(
    'handles malformed encoding without throwing',
    (() => {
      try {
        // %zz is invalid percent-encoding — decodeURIComponent would throw
        const result = cleanGoogleUrl('https://www.google.com/url?q=https%3A%2F%2Fsite.com%3Fk%3D%zz');
        return typeof result === 'string'; // just make sure we got something back
      } catch {
        return false;
      }
    })()
  );

  // missing q/url param — should return original
  expect(
    'returns original if no q or url param',
    cleanGoogleUrl('https://www.google.com/url?sa=D&source=email'),
    'https://www.google.com/url?sa=D&source=email'
  );

  // ── E: extractBody (DOM-based quote removal) ───────────────────────────────

  section('E — extractBody (DOM-based quote removal)');

  // basic: body with a blockquote that should be stripped
  const bodyWithBlockquote = html(`
    <div class="a3s aiL">
      <p>Hey, please verify your account immediately.</p>
      <blockquote>
        On Mon Jan 1, Bob wrote: blah blah old stuff
      </blockquote>
    </div>
  `);

  const cleanBody = extractBody(bodyWithBlockquote);
  expectTruthy(
    'bodyClean contains the new message',
    cleanBody.includes('verify your account')
  );
  expect(
    'bodyClean strips blockquote content',
    cleanBody.includes('Bob wrote'),
    false
  );

  // gmail_quote class
  const bodyWithGmailQuote = html(`
    <div class="a3s aiL">
      <p>Click here to reset your password.</p>
      <div class="gmail_quote">
        Previous conversation history here...
      </div>
    </div>
  `);

  const cleanBody2 = extractBody(bodyWithGmailQuote);
  expectTruthy('bodyClean contains actual message', cleanBody2.includes('reset your password'));
  expect('bodyClean strips .gmail_quote', cleanBody2.includes('Previous conversation'), false);

  // bodyFull should keep everything
  const bodyFull = extractBodyFull(bodyWithBlockquote);
  expectTruthy('bodyFull includes quoted content', bodyFull.includes('Bob wrote'));

  // both should work — bodyFull always >= bodyClean in length
  expectTruthy(
    'bodyFull length >= bodyClean length',
    extractBodyFull(bodyWithBlockquote).length >= extractBody(bodyWithBlockquote).length
  );

  // no quotes at all — both should be the same
  const bodyNoQuotes = html(`<div class="a3s aiL"><p>Simple message, no replies.</p></div>`);
  expect(
    'body without quotes: clean and full match',
    extractBody(bodyNoQuotes),
    extractBodyFull(bodyNoQuotes)
  );

  // make sure the real DOM isn't modified — the blockquote should still be there
  expect(
    'original DOM is not modified by clone-based removal',
    !!bodyWithBlockquote.querySelector('blockquote'),
    true
  );

  // ── D: extractAttachments ──────────────────────────────────────────────────

  section('D — extractAttachments');

  // no attachments
  const noAttachments = html('<div></div>');
  const none = extractAttachments(noAttachments);
  expect('no attachments: hasAttachments = false', none.hasAttachments, false);
  expect('no attachments: count = 0', none.attachmentCount, 0);
  expect('no attachments: array is empty', none.attachments, []);

  // single safe attachment
  const safeAttachment = html(`
    <div>
      <span class="aV3">budget_2024.pdf</span>
    </div>
  `);
  const safeResult = extractAttachments(safeAttachment);
  expect('safe attachment: hasAttachments = true', safeResult.hasAttachments, true);
  expect('safe attachment: count = 1', safeResult.attachmentCount, 1);
  expect('safe attachment: filename correct', safeResult.attachments[0].filename, 'budget_2024.pdf');
  expect('safe attachment: extension correct', safeResult.attachments[0].extension, 'pdf');
  expect('safe attachment: isRiskyType = false', safeResult.attachments[0].isRiskyType, false);

  // risky attachment
  const riskyAttachment = html(`
    <div>
      <span class="aV3">invoice.exe</span>
    </div>
  `);
  const riskyResult = extractAttachments(riskyAttachment);
  expect('risky attachment: isRiskyType = true', riskyResult.attachments[0].isRiskyType, true);
  expect('risky attachment: extension = exe', riskyResult.attachments[0].extension, 'exe');

  // multiple attachments, mixed types
  const mixedAttachments = html(`
    <div>
      <span class="aV3">report.docx</span>
      <span class="aV3">run_me.js</span>
      <span class="aV3">photo.jpg</span>
      <span class="aV3">payload.zip</span>
    </div>
  `);
  const mixed = extractAttachments(mixedAttachments);
  expect('mixed: count = 4', mixed.attachmentCount, 4);
  const riskyOnes = mixed.attachments.filter(a => a.isRiskyType);
  // .js and .zip are risky, .docx and .jpg are not
  expect('mixed: 2 risky attachments (.js and .zip)', riskyOnes.length, 2);

  // risky: macro-enabled office doc (the m suffix makes it risky)
  const macroDoc = html(`<div><span class="aV3">invoice.xlsm</span></div>`);
  expect(
    'macro Office file (.xlsm) flagged as risky',
    extractAttachments(macroDoc).attachments[0].isRiskyType,
    true
  );

  // edge case: file with no extension
  const noExt = html(`<div><span class="aV3">README</span></div>`);
  const noExtResult = extractAttachments(noExt);
  expect('file with no extension: extension = empty string', noExtResult.attachments[0].extension, '');
  expect('file with no extension: isRiskyType = false', noExtResult.attachments[0].isRiskyType, false);

  // ── B: extractLinks (link objects with domain comparison) ──────────────────

  section('B — extractLinks (richer link objects)');

  // standard link
  const simpleLink = html(`
    <div class="a3s aiL">
      <a href="https://example.com">Click here</a>
    </div>
  `);
  const simpleLinks = extractLinks(simpleLink);
  expect('simple link: href correct', simpleLinks[0].href, 'https://example.com');
  expect('simple link: text correct', simpleLinks[0].text, 'Click here');
  expect('simple link: actualDomain', simpleLinks[0].actualDomain, 'example.com');

  // domain mismatch — the core phishing signal
  const mismatchLink = html(`
    <div class="a3s aiL">
      <a href="https://evil-site.ru/steal">www.paypal.com</a>
    </div>
  `);
  const mismatchLinks = extractLinks(mismatchLink);
  expect('mismatch: displayedDomain = paypal.com', mismatchLinks[0].displayedDomain, 'www.paypal.com');
  expect('mismatch: actualDomain = evil-site.ru', mismatchLinks[0].actualDomain, 'evil-site.ru');
  expectTruthy(
    'mismatch: displayed and actual domains differ (phishing signal)',
    mismatchLinks[0].displayedDomain !== mismatchLinks[0].actualDomain
  );

  // Gmail redirect gets unwrapped
  const redirectLink = html(`
    <div class="a3s aiL">
      <a href="https://www.google.com/url?q=https%3A%2F%2Fgithub.com&sa=D">GitHub</a>
    </div>
  `);
  const redirectLinks = extractLinks(redirectLink);
  expect('redirect link: unwrapped to real URL', redirectLinks[0].href, 'https://github.com');

  // mailto and # links should be skipped
  const skipLinks = html(`
    <div class="a3s aiL">
      <a href="mailto:bob@example.com">Email Bob</a>
      <a href="#section2">Jump to section</a>
      <a href="https://real.com">Real link</a>
    </div>
  `);
  const skipped = extractLinks(skipLinks);
  expect('skips mailto and # links, keeps real ones', skipped.length, 1);
  expect('kept link is the real one', skipped[0].href, 'https://real.com');

  // deduplication — same href appearing twice
  const dupLinks = html(`
    <div class="a3s aiL">
      <a href="https://same.com">Link A</a>
      <a href="https://same.com">Link B</a>
    </div>
  `);
  expect('deduplicates identical hrefs', extractLinks(dupLinks).length, 1);

  // title attribute
  const titleLink = html(`
    <div class="a3s aiL">
      <a href="https://example.com" title="Go to example">Click</a>
    </div>
  `);
  expect('captures title attribute', extractLinks(titleLink)[0].title, 'Go to example');

  // ── summary ────────────────────────────────────────────────────────────────

  const total = passed + failed;
  console.log(`\n%c── Results: ${passed}/${total} passed ──`, `
    color: ${failed === 0 ? '#3ddc84' : '#ff5f5f'};
    font-weight: bold;
    font-size: 14px;
  `);

  if (failed === 0) {
    console.log('%c  All tests passed! Parser is working correctly ✓', 'color: #3ddc84');
  } else {
    console.warn(`  ${failed} test(s) failed — check the output above for details`);
  }
}

// auto-run so you don't have to call it manually after pasting
runParserTests();
