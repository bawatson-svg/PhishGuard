PhishGuard 🛡️

A Real-Time Browser Mitigation Tool for Evolving Phishing Threats

PhishGuard is a lightweight Google Chrome extension designed to provide real-time phishing detection directly at the browser level. It analyzes URLs, webpage metadata, and social-engineering signals to warn users before they fall victim to credential harvesting or malicious phishing attacks.

This project was developed as part of the Cybersecurity Engineering Program at George Mason University.

Project Overview

Phishing continues to be one of the most damaging cybersecurity threats, primarily targeting users through social engineering rather than technical exploitation. Despite email filtering systems and antivirus solutions, phishing attacks frequently bypass institutional defenses.

PhishGuard acts as a client-side security layer, operating directly in the browser to:

• Analyze visited URLs in real time
• Detect suspicious structural and lexical indicators
• Identify social-engineering patterns
• Provide clear, actionable warnings
• Minimize false positives
• Maintain low latency and minimal resource overhead

The tool is especially designed to protect:

• Students
• Elderly users
• Non-technical users
• High-risk demographics

Design Goals
Accuracy

PhishGuard focuses on observable phishing indicators such as:

• Sender identity anomalies
• Suspicious URLs
• Social-engineering language
• Technical red flags

Explainability

The system provides clear reasoning explaining why a message or website is suspicious.

Structured Output

The detection engine produces:

• A numerical phishing risk score (0–100)
• A categorical classification:

Legitimate

Suspicious

Phishing

• Evidence-based explanation
• Actionable guidance for the user

Efficiency

• Minimal API latency
• Lightweight execution
• No noticeable browsing slowdown

Privacy-First Architecture

PhishGuard was designed with a privacy-preserving architecture:

• No long-term storage of email or webpage content
• No external enrichment of personal user data
• Analysis is triggered only when the user presses “Analyze”
• Only minimal data (URLs) may be sent externally when reputation checks are enabled

Threat-Driven Detection Model

The detection logic is based on common phishing attack patterns derived from publicly available datasets and industry research.

URL-Based Indicators

• Typosquatting / look-alike domains
• Suspicious top-level domains
• Excessive subdomains
• Long or obfuscated URLs
• URL shorteners

Sender Spoofing Indicators

• Display-name impersonation
• Slight domain alterations
• Fake branding replication

Social Engineering Indicators

• Account suspension threats
• Artificial urgency (“within 24 hours”)
• Requests for credentials or financial information
• Emotional manipulation (fear, panic, curiosity)

Reputation Database Integration

PhishGuard optionally integrates with Google Safe Browsing, a threat-intelligence database maintained by Google that contains millions of known phishing and malware URLs.

When enabled, extracted links from emails are checked against the Safe Browsing database to detect known malicious domains.

If Safe Browsing is not configured, the extension still performs rule-based phishing analysis locally.

Datasets Used for Research & Benchmarking

PhishGuard’s detection indicators were derived from research and evaluation using publicly available phishing datasets:

• PhishTank – Verified phishing URLs repository
• OpenPhish – Structured phishing forensic metadata
• URL-Phish Feature Dataset (111,660 labeled URLs)
• Balanced Phishing vs Legitimate Website Dataset (10,000 labeled samples)

These datasets supported feature extraction, model prototyping, and benchmarking performance metrics.

Technical Architecture
Chrome Extension Stack

• JavaScript
• HTML
• CSS
• Chrome Extensions API

Development & Prototyping

• Python (dataset analysis and detection prototyping)
• Windows & macOS compatibility

Real-Time Workflow

User opens an email in Gmail

The extension extracts sender, body content, links, and metadata

Detection logic evaluates phishing indicators

Reputation checks (optional) query Safe Browsing

A phishing risk score is generated

The user receives a warning and explanation

Evaluation Metrics

PhishGuard is evaluated using the following performance criteria:

Metric	Target
True Positive Rate	≥ 85%
False Positive Rate	≤ 5%
F1 Score	Balanced precision & recall
Detection Latency	≤ 200ms
CPU / Memory Overhead	< 10% increase

Usability testing additionally evaluates:

• Clarity of warnings
• User compliance
• Perceived security improvement

Installation Guide
Step 1 — Download the Project

Download the repository or ZIP file and extract it to your computer.

Step 2 — Open Chrome Extensions

Open Google Chrome and navigate to:

chrome://extensions
Step 3 — Enable Developer Mode

Toggle Developer Mode in the top-right corner.

Step 4 — Load the Extension

Click Load unpacked and select the project folder.

The extension should now appear in your installed extensions list.

Optional Setup: Enable Google Safe Browsing

PhishGuard supports Google Safe Browsing to detect known malicious URLs.

Because Google requires authentication, each user must create their own API key.

The extension will still work without this step, but Safe Browsing checks will be disabled.

How to Get a Google Safe Browsing API Key
Step 1 — Open Google Cloud Console

Go to:

https://console.cloud.google.com/

Step 2 — Create or Select a Project

Create a new project or use an existing one.

Step 3 — Enable the Safe Browsing API

Navigate to:

APIs & Services → Library

Search for:

Safe Browsing API

Click Enable.

Step 4 — Create an API Key

Go to:

APIs & Services → Credentials

Click:

Create Credentials → API Key
Step 5 — Restrict the Key (Recommended)

Open your new API key and set:

Application Restrictions

None

API Restrictions

Restrict Key → Safe Browsing API

Save the configuration.

Note: it may take a few minutes for the restrictions to take effect.

Step 6 — Add the Key to the Extension

Open the file:

service-worker.js

Locate the line:

const SAFE_BROWSING_API_KEY = 'YOUR_API_KEY_HERE';

Replace with your generated key:

const SAFE_BROWSING_API_KEY = 'AIza...YOUR_KEY...';
Step 7 — Reload the Extension

Return to chrome://extensions

Click Reload on the PhishGuard extension

Refresh Gmail

Safe Browsing protection should now be active.

Usage

Open Gmail and view an email

Click the PhishGuard extension icon

Press Analyze

Review the results:

• Risk score
• Classification
• Explanation
• Recommended actions

Expected Outcomes

• Functional Chrome extension prototype
• Real-time phishing detection
• Low-latency performance
• High usability for non-technical users

Future improvements may include:

• Microsoft Edge support
• Firefox compatibility
• Safari compatibility
• Enhanced machine-learning detection models

Authors

Brodie Watson
Jai Althi
Simon Betancur
Carlos Ortiz Collao

Department of Cybersecurity Engineering
George Mason University

References

• AAG IT Support – Phishing Statistics
• E-Bits Phishing Surge Report (2025)
• Phishing Detection and Prevention using Chrome Extension, ISDFS 2022
• Public phishing datasets (PhishTank, OpenPhish)

Disclaimer

PhishGuard is a research prototype developed for academic purposes.

It is not intended to replace enterprise-grade security solutions but demonstrates the effectiveness of lightweight browser-level phishing detection.