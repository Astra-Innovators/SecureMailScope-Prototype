# 3–5 Minute SIH Demo Script

## 1. Open dashboard
Say:
"SecureMailScope is an AI-assisted passive network forensic framework for secure email communications."

Point out:
- PS 26159
- NTRO
- Blockchain & Cybersecurity
- SMTP / IMAP / POP3
- AI Risk Engine
- Evidence Ledger

## 2. Demonstrate a real uploaded PCAP
Go to **PCAP Forensics → Choose PCAP** and select an authorized `.pcap`/`.pcapng`.

Say:
"Unlike the demo buttons, this request sends the actual uploaded PCAP bytes to our backend. The result is calculated from the packets observed in this capture."

Show:
- protocol/session detection
- TLS version and cipher
- certificate fields when visible
- evidence-backed findings
- uploaded evidence SHA-256

## 3. Run Vulnerable Demo
Click **Run Vulnerable Demo**.

Say:
"We are now analyzing a synthetic vulnerable enterprise-email capture."

Show:
- Low posture score
- SMTP/POP3 sessions
- TLS 1.0 / 1.1
- 3DES
- expired certificate
- RSA-1024
- no Forward Secrecy

## 4. Open Findings
Explain:
"Every high-risk finding contains evidence, impact and recommended remediation. The rule engine is deterministic, so the AI cannot invent a vulnerability."

## 5. Open AI Risk Engine
Explain:
"The ML layer consumes verified cryptographic/session features. RandomForest performs risk classification and IsolationForest flags anomalous TLS behavior."

## 6. Open Evidence Ledger
Explain:
"After analysis, the evidence and report are hashed and chained. If the evidence changes later, the integrity check will no longer match."

## 7. Run Secure Demo
Click **Run Secure Demo**.

Show:
- TLS 1.3
- AES-GCM
- ECDHE
- valid certificates
- Forward Secrecy
- improved score

## 8. Report
Export PDF and say:
"The complete forensic result is exportable as JSON, HTML and PDF."

## Judge-facing closing line

"SecureMailScope connects passive email forensics, cryptographic posture assessment, explainable AI and tamper-evident evidence integrity in one workflow."
