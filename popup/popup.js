// State management
let currentState = 'idle';
let analysisResult = null;

// DOM elements
const states = {
  idle: document.getElementById('idle-state'),
  analyzing: document.getElementById('analyzing-state'),
  results: document.getElementById('results-state'),
  error: document.getElementById('error-state')
};

const analyzeBtn = document.getElementById('analyze-btn');
const retryBtn = document.getElementById('retry-btn');
const analyzeAgainBtn = document.getElementById('analyze-again-btn');
const toggleDetailsBtn = document.getElementById('toggle-details');
const detailsContent = document.getElementById('details-content');

document.addEventListener('DOMContentLoaded', init);

function init() {
  checkGmailContext();
  analyzeBtn.addEventListener('click', handleAnalyze);
  retryBtn.addEventListener('click', handleAnalyze);
  analyzeAgainBtn.addEventListener('click', resetToIdle);
  toggleDetailsBtn.addEventListener('click', toggleDetails);
}

async function checkGmailContext() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab.url || !tab.url.includes('mail.google.com')) {
      showError('Not on Gmail', 'Please open a Gmail email to use PhishGuard');
      analyzeBtn.disabled = true;
    } else {
      analyzeBtn.disabled = false;
    }
  } catch (error) {
    console.error('Error checking context:', error);
  }
}

async function handleAnalyze() {
  setState('analyzing');
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab.url || !tab.url.includes('mail.google.com')) {
      throw new Error('Please navigate to Gmail');
    }
    
    // Try to get email data with timeout
    let emailData;
    try {
      emailData = await Promise.race([
        chrome.tabs.sendMessage(tab.id, { type: 'EXTRACT_EMAIL' }),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout - please refresh Gmail and try again')), 5000)
        )
      ]);
    } catch (msgError) {
      // Content script not responding - try to inject it
      console.log('Content script not responding, attempting to inject...');
      
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['content/gmail-parser.js']
        });
        
        // Wait a bit and retry
        await new Promise(resolve => setTimeout(resolve, 500));
        emailData = await chrome.tabs.sendMessage(tab.id, { type: 'EXTRACT_EMAIL' });
      } catch (injectError) {
        throw new Error('Could not access email. Please refresh Gmail and try again.');
      }
    }
    
    if (!emailData || emailData.error) {
      throw new Error(emailData?.error || 'Failed to extract email data. Make sure an email is open.');
    }
    
    // Send to service worker for analysis
    const result = await chrome.runtime.sendMessage({
      type: 'ANALYZE_EMAIL',
      data: emailData
    });
    
    if (result.error) {
      throw new Error(result.error);
    }
    
    displayResults(result);
    
  } catch (error) {
    console.error('Analysis error:', error);
    showError('Analysis Failed', error.message || 'Could not analyze email. Try refreshing Gmail.');
  }
}

function displayResults(result) {
  analysisResult = result;
  
  const riskScore = Math.round(result.riskScore);
  const riskLevel = getRiskLevel(riskScore);
  
  document.getElementById('risk-score').textContent = riskScore;
  
  const riskFill = document.querySelector('.risk-fill');
  riskFill.style.setProperty('--risk-percent', riskScore);
  riskFill.setAttribute('data-level', riskLevel);
  
  const riskLevelElem = document.getElementById('risk-level');
  riskLevelElem.textContent = getRiskLevelText(riskLevel);
  riskLevelElem.setAttribute('data-level', riskLevel);
  
  document.getElementById('rule-score').textContent = `${Math.round(result.ruleScore)}%`;
  document.getElementById('llm-score').textContent = result.llmScore > 0 ? `${Math.round(result.llmScore)}%` : 'N/A';
  
  const indicatorsList = document.getElementById('indicators-list');
  indicatorsList.innerHTML = '';
  
  if (result.indicators && result.indicators.length > 0) {
    result.indicators.forEach(indicator => {
      const li = document.createElement('li');
      li.textContent = indicator;
      
      if (indicator.includes('🚨')) {
        li.classList.add('high-risk');
      } else if (indicator.includes('✓')) {
        li.classList.add('low-risk');
      }
      
      indicatorsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = '✓ No significant phishing indicators detected';
    li.classList.add('low-risk');
    indicatorsList.appendChild(li);
  }
  
  setState('results');
}

function getRiskLevel(score) {
  if (score <= 30) return 'low';
  if (score <= 60) return 'medium';
  return 'high';
}

function getRiskLevelText(level) {
  const texts = {
    low: 'Low Risk - Likely Safe',
    medium: 'Medium Risk - Exercise Caution',
    high: 'High Risk - Likely Phishing'
  };
  return texts[level] || 'Unknown';
}

function toggleDetails() {
  const isExpanded = detailsContent.classList.toggle('expanded');
  toggleDetailsBtn.classList.toggle('expanded');
  toggleDetailsBtn.querySelector('span:first-child').textContent = 
    isExpanded ? 'Hide Details' : 'View Details';
}

function showError(title, message) {
  document.querySelector('.error-title').textContent = title;
  document.getElementById('error-message').textContent = message;
  setState('error');
}

function resetToIdle() {
  analysisResult = null;
  detailsContent.classList.remove('expanded');
  toggleDetailsBtn.classList.remove('expanded');
  setState('idle');
}

function setState(newState) {
  Object.values(states).forEach(state => state.classList.remove('active'));
  
  if (states[newState]) {
    states[newState].classList.add('active');
    currentState = newState;
  }
}
