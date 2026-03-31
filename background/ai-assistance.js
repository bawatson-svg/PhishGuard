// ─── ai-assistance.js ────────────────────────────────────────────────────────
//
// AI Explanation Layer for PhishGuard.
//
// WHAT THIS FILE DOES:
//   - Takes the already-computed phishing analysis result from service-worker.js
//   - Sends a compact summary to the OpenAI Chat Completions API
//   - Gets back a plain-English explanation for non-technical users
//   - Returns { explanation, recommendation } to attach to the result object
//
// WHAT THIS FILE DOES NOT DO:
//   - It does NOT perform phishing detection
//   - It does NOT change scores, indicators, or the verdict
//   - It does NOT invent facts about the email
//
// HOW TO PLUG IN:
//   In service-worker.js, at the top, add:
//     importScripts('ai-assistance.js');
//   Then after your final score is computed, call:
//     const aiResult = await generateAIExplanation(result, emailData);
//     result.aiExplanation    = aiResult.explanation;
//     result.aiRecommendation = aiResult.recommendation;
// ─────────────────────────────────────────────────────────────────────────────

// ─── API Config ───────────────────────────────────────────────────────────────

// Replace this with your real OpenAI API key.
// Get one at: https://platform.openai.com/api-keys
// If this stays as the placeholder, AI explanations are silently skipped
// and the extension still works fine using the fallback text.
const OPENAI_API_KEY = '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';

// We use gpt-4o-mini — it's fast, cheap, and more than capable for short explanations.
// Do not switch to a larger model; this task does not need it.
const OPENAI_MODEL = 'gpt-4o-mini';

// Max tokens for the response. Short explanations only — we don't need essays.
const MAX_TOKENS = 220;

// How long to wait for OpenAI before giving up (ms).
// We want the popup to feel snappy, so we bail early if the API is slow.
const AI_TIMEOUT_MS = 8000;

// ─── System prompt ───────────────────────────────────────────────────────────
//
// This is the instruction that shapes the AI's behavior.
// It is strict about what the AI can and cannot do.
// Do not remove the "do NOT detect" and "do NOT invent" lines —
// those are what prevent the AI from hallucinating new threats.

const SYSTEM_PROMPT = `You are a cybersecurity assistant embedded in a phishing detection Chrome extension called PhishGuard.

Your ONLY job is to explain an already-computed phishing analysis result to a non-technical user in plain, calm English.

STRICT RULES you must follow:
1. Do NOT perform your own phishing detection. Detection is already done.
2. Do NOT add facts, threats, or observations that are not in the data you receive.
3. Do NOT contradict the verdict or the risk score.
4. Do NOT use technical jargon (no "SPF records", "MIME headers", etc.).
5. Keep your entire response short — 3 to 5 sentences for the explanation, 1 sentence for the recommendation.
6. Be calm, clear, and helpful. Avoid alarming or fear-based language.
7. Address the user directly (use "you" / "this email").

Response format — respond ONLY with a valid JSON object, no markdown, no preamble:
{
  "explanation": "...",
  "recommendation": "..."
}`;

// ─── Verdict helper ───────────────────────────────────────────────────────────

/**
 * Converts a numeric risk score into a human-readable verdict string.
 * This is passed to the AI so it has the right label to work with.
 *
 * @param {number} score  — 0–100
 * @returns {string}
 */
function scoreToVerdict(score) {
  if (score <= 30) return 'likely safe';
  if (score <= 60) return 'suspicious — treat with caution';
  return 'likely phishing';
}

// ─── Fallback explanation ─────────────────────────────────────────────────────
//
// Returned when: API key is missing, OpenAI request fails, response is malformed,
// or anything else goes wrong. The extension must never crash because of AI.

function buildFallbackExplanation(analysisResult) {
  const verdict = scoreToVerdict(analysisResult.riskScore || 0);
  const score   = analysisResult.riskScore || 0;

  // Build a simple canned explanation that still reflects the real result.
  let explanation = `PhishGuard analyzed this email and found a risk score of ${score}/100, which means it is ${verdict}.`;

  if (score > 60) {
    explanation += ' Several phishing indicators were detected. Please be careful before clicking any links or entering information.';
  } else if (score > 30) {
    explanation += ' Some suspicious signals were found. Review the indicators below before acting on this email.';
  } else {
    explanation += ' No major phishing signals were found, but always stay cautious with unexpected emails.';
  }

  const recommendation =
    score > 60
      ? 'Do not click links or provide any personal information. Verify the sender through official channels if needed.'
      : score > 30
      ? 'Proceed with caution. Double-check the sender and avoid clicking unfamiliar links.'
      : 'This email appears safe, but always verify before sharing sensitive information.';

  return { explanation, recommendation };
}

// ─── Main exported function ───────────────────────────────────────────────────

/**
 * generateAIExplanation
 *
 * Calls the OpenAI API to produce a user-friendly explanation of the
 * already-computed phishing analysis result.
 *
 * @param {object} analysisResult  — the result object from service-worker.js
 *   Expected fields: riskScore, ruleScore, datasetScore, indicators
 * @param {object} emailData       — the raw email object from gmail-parser.js
 *   Expected fields: sender, subject, links
 *
 * @returns {Promise<{ explanation: string, recommendation: string }>}
 *   Always returns something — never throws.
 */
async function generateAIExplanation(analysisResult, emailData) {
  // ── Guard: skip entirely if no API key is configured ──────────────────────
  if (!OPENAI_API_KEY || OPENAI_API_KEY === 'PLEASE_ADD_YOUR_OPENAI_API_KEY') {
    console.log('[PhishGuard AI] No API key set — skipping AI explanation');
    return buildFallbackExplanation(analysisResult);
  }

  // ── Build a compact payload to send to the AI ─────────────────────────────
  // We only send fields that are relevant to the explanation.
  // We intentionally omit the full email body for privacy.
  const payload = {
    riskScore:    analysisResult.riskScore  || 0,
    ruleScore:    analysisResult.ruleScore  || 0,
    datasetScore: analysisResult.datasetScore || 0,
    verdict:      scoreToVerdict(analysisResult.riskScore || 0),
    indicators:   (analysisResult.indicators || []).slice(0, 10), // cap at 10 to save tokens
    sender:       emailData.sender  || 'unknown',
    subject:      emailData.subject || '(no subject)',
    linkCount:    (emailData.links  || []).length,
  };

  // ── Set up a fetch timeout so a slow API doesn't hang the popup ───────────
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method:  'POST',
      signal:  controller.signal,
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model:      OPENAI_MODEL,
        max_tokens: MAX_TOKENS,
        // temperature 0 = deterministic, consistent explanations
        temperature: 0,
        messages: [
          {
            role:    'system',
            content: SYSTEM_PROMPT,
          },
          {
            role: 'user',
            // Give the AI the data as a JSON string so it's unambiguous
            content: `Here is the phishing analysis result. Explain it to the user.\n\n${JSON.stringify(payload, null, 2)}`,
          },
        ],
      }),
    });

    clearTimeout(timeoutId);

    // ── Handle HTTP errors (bad key, quota exceeded, etc.) ────────────────
    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      console.warn(`[PhishGuard AI] OpenAI returned ${response.status}:`, errText);
      return buildFallbackExplanation(analysisResult);
    }

    const data = await response.json();

    // ── Pull out the text content from the response ───────────────────────
    const raw = data?.choices?.[0]?.message?.content?.trim();
    if (!raw) {
      console.warn('[PhishGuard AI] Empty response from OpenAI');
      return buildFallbackExplanation(analysisResult);
    }

    // ── Parse the JSON the AI was asked to return ─────────────────────────
    // Strip markdown code fences if the model accidentally added them
    const cleaned = raw.replace(/^```json\s*/i, '').replace(/```\s*$/, '').trim();
    const parsed  = JSON.parse(cleaned);

    // Validate that we got both fields back
    if (typeof parsed.explanation !== 'string' || typeof parsed.recommendation !== 'string') {
      console.warn('[PhishGuard AI] Unexpected response shape:', parsed);
      return buildFallbackExplanation(analysisResult);
    }

    console.log('[PhishGuard AI] Explanation generated successfully');
    return {
      explanation:    parsed.explanation.trim(),
      recommendation: parsed.recommendation.trim(),
    };

  } catch (err) {
    clearTimeout(timeoutId);

    if (err.name === 'AbortError') {
      console.warn('[PhishGuard AI] Request timed out — using fallback');
    } else if (err instanceof SyntaxError) {
      console.warn('[PhishGuard AI] JSON parse error — using fallback:', err.message);
    } else {
      console.warn('[PhishGuard AI] Unexpected error — using fallback:', err.message);
    }

    return buildFallbackExplanation(analysisResult);
  }
}
