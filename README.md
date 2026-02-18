# PhishGuard
A Real-Time Browser Mitigation Tool for Evolving Phishing Threats
PhishGuard is a lightweight Google Chrome extension designed to provide real-time phishing detection directly at the browser level. It analyzes URLs, webpage metadata, and social-engineering signals to warn users before they fall victim to credential harvesting or malicious phishing attacks.
This project was developed as part of the Cybersecurity Engineering program at George Mason University.

Project Overview
Phishing continues to be one of the most damaging cybersecurity threats, primarily targeting users through social engineering rather than technical exploitation. Despite email filtering systems and antivirus solutions, phishing attacks continue to bypass institutional defenses.
PhishGuard acts as a client-side security layer, operating directly in the browser to:
•	Analyze visited URLs in real time
•	Detect suspicious structural and lexical indicators
•	Identify social-engineering patterns
•	Provide clear, actionable warnings
•	Minimize false positives
•	Maintain low latency and low resource overhead
The tool is especially designed to protect:
•	Students
•	Elderly users
•	Non-technical users
•	High-risk demographics

Design Goals
Accuracy
Focus on observable phishing indicators:
•	Sender identity anomalies
•	Suspicious URLs
•	Social-engineering language
•	Technical red flags
Explainability
The system provides clear reasoning explaining why a site or message is suspicious.
Structured Output
The LLM-based analysis returns:
•	A numerical phishing risk score (0–100)
•	A categorical classification:
o	Legitimate
o	Suspicious
o	Phishing
•	Evidence-based explanation
•	Actionable guidance
Efficiency
•	Minimal API latency
•	Lightweight execution
•	No noticeable browsing slowdown
Privacy-First Architecture
PhishGuard is designed as a privacy-preserving Chrome extension:
•	No long-term storage of email or webpage content
•	No external enrichment of user data
•	Analysis triggered only when the user clicks “Analyze”
•	Minimal data sent to the LLM

Threat-Driven Detection Model
The detection logic is based on common phishing attack patterns derived from publicly available datasets.
URL-Based Indicators
•	Typosquatting / look-alike domains
•	Suspicious TLDs
•	Excessive subdomains
•	Long or obfuscated URLs
•	Recently registered domains
Sender Spoofing Indicators
•	Display-name impersonation
•	Slight domain alterations
•	Forged reply-to headers
•	Fake branding replication
Social Engineering Patterns
•	Account suspension threats
•	Artificial urgency (“within 24 hours”)
•	Requests for credentials or payment
•	Emotional manipulation (fear, panic, curiosity)

Datasets Used for Research & Benchmarking
PhishGuard’s detection indicators were derived from research and evaluation using publicly available phishing datasets:
•	PhishTank – Verified phishing URLs repository
•	OpenPhish – Structured phishing forensic metadata
•	URL-Phish Feature Dataset (111,660 labeled URLs)
•	Balanced Phishing vs Legitimate Website Dataset (10,000 labeled samples)
These datasets supported feature extraction, model prototyping, and benchmarking performance metrics.

Technical Architecture
Chrome Extension Stack
•	JavaScript
•	HTML
•	CSS
•	Chrome Extensions API
Development & Prototyping
•	Python (dataset analysis and detection prototyping)
•	Windows & macOS compatibility
Real-Time Workflow
1.	User visits a webpage
2.	Extension extracts URL and metadata
3.	Detection logic evaluates phishing indicators
4.	Risk score is generated
5.	User receives warning (if applicable)

Evaluation Metrics
PhishGuard is evaluated using the following performance criteria:
Metric	Target
True Positive Rate	≥ 85%
False Positive Rate	≤ 5%
F1 Score	Balanced precision & recall
Detection Latency	≤ 200ms
CPU/Memory Overhead	< 10% increase
Additionally, usability testing evaluates:
•	Clarity of warnings
•	User compliance
•	Perceived security improvement

Expected Outcomes
•	Functional Chrome extension prototype
•	Real-time phishing detection
•	Low latency performance
•	High usability for non-technical users
•	Proof-of-concept for lightweight browser-level security
Future expansion may include:
•	Support for Microsoft Edge
•	Firefox compatibility
•	Safari support
•	Enhanced ML-based detection models

Installation Guide
1.	Download the ZIP File
•	Download the extension’s .zip file to your computer.
•	Right click the file and select “Extract All...”
•	Choose a destination folder and extract the contents.
2.	Open Google Chrome
•	Launch the Google Chrome browser
3.	Access Extensions Page
•	Click the three dots in the top right corner of the browser
•	Navigate to: Extensions -> Manage Extensions
4.	Enable Developer Mode
•	In the top right corner of the extensions page, toggle Developer Mode ON.
5.	Load the Extension
•	Click the “Load unpacked” button in the top right corner
•	Select the folder you extracted from the ZIP file
•	Click Select Folder
6.	Verify Installation
•	The extension should now appear in your extensions list
•	Ensure it is enabled and running
Usage
1.	Visit a website.
2.	Click the PhishGuard icon.
3.	Press Analyze.
4.	Review:
o	Risk score
o	Classification
o	Explanation
o	Recommended action

Authors
•	Brodie Watson
•	Jai Althi
•	Simon Betancur 
•	Carlos Ortiz Collao
Department of Cybersecurity Engineering
George Mason University

References
•	Phishing statistics – AAG IT Support
•	E-Bits Phishing Surge Report (2025)
•	“Phishing Detection and Prevention using Chrome Extension,” ISDFS 2022
•	Public phishing datasets (PhishTank, OpenPhish)

Disclaimer
PhishGuard is a research prototype developed for academic purposes.
It is not intended to replace enterprise-grade security solutions but to demonstrate the effectiveness of lightweight browser-based phishing detection.
