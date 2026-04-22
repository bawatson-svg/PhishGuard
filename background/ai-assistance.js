// ─── ai-assistance.js ────────────────────────────────────────────────────────
// ROLE: The "Translator." Turns technical security flags into human language.
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

// REPLACE WITH YOUR KEY: https://platform.openai.com/api-keys
const OPENAI_API_KEY = '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'; 
const OPENAI_ENDPOINT = 'https://api.openai.com/v1/chat/completions';

/**
 * Generates a user-friendly explanation based on the detection results.
 * @param {Object} analysisResult - The object containing score and indicators.
 * @param {Object} emailData - The raw email data (sender, subject).
 */
async function generateAIExplanation(analysisResult, emailData) {
  if (!OPENAI_API_KEY || OPENAI_API_KEY === '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') {
    return buildFallbackExplanation(analysisResult);
  }

  // We only send the indicators and metadata, NOT the full email body.
  // This saves money and keeps the AI focused on the "why".
  const summaryForAI = {
    score: analysisResult.riskScore,
    threatsFound: analysisResult.indicators,
    sender: emailData.sender,
    subject: emailData.subject
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout

  try {
    const response = await fetch(OPENAI_ENDPOINT, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo", // or "gpt-4-turbo-preview"
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity assistant. Your job is to explain phishing risks to non-technical elderly users. Be calm, helpful, and avoid jargon. Return a JSON object with two fields: 'explanation' and 'recommendation'."
          },
          {
            role: "user",
            content: `Explain why this email got a risk score of ${summaryForAI.score}/100. 
            Threats detected: ${summaryForAI.threatsFound.join(', ')}. 
            Sender: ${summaryForAI.sender}.`
          }
        ],
        response_format: { type: "json_object" }
      })
    });

    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`API Error: ${response.status}`);

    const data = await response.json();
    const result = JSON.parse(data.choices[0].message.content);

    return {
      explanation: result.explanation,
      recommendation: result.recommendation
    };

  } catch (err) {
    console.warn('[PhishGuard AI] Using fallback due to error:', err.message);
    return buildFallbackExplanation(analysisResult);
  }
}

/**
 * Fallback logic if the AI is offline or the API key is missing.
 * Uses the indicators to build a simple bulleted list.
 */
function buildFallbackExplanation(result) {
  if (result.riskScore < 30) {
    return {
      explanation: "This email doesn't show any common signs of phishing.",
      recommendation: "You can proceed, but always be careful with unexpected attachments."
    };
  }

  const list = result.indicators.map(i => `• ${i}`).join('\n');
  return {
    explanation: `We found several red flags in this email:\n${list}`,
    recommendation: "We recommend not clicking any links. If you know the sender, contact them through a different channel to verify."
  };
}

self.generateAIExplanation = generateAIExplanation;