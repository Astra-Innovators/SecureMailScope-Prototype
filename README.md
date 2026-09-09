# SecureMailScope — Real PCAP Cryptographic Security Analyzer

**PS 26159 — NTRO | Blockchain & Cybersecurity**

SecureMailScope is a passive forensic prototype that analyzes the **actual PCAP/PCAPNG bytes uploaded by the user**. Built-in JSON fixtures are retained only for optional demo buttons; they are not used when `/api/analyze` receives an uploaded capture.

## Real-file analysis pipeline

`REAL PCAP/PCAPNG`
→ Scapy packet ingestion
→ SMTP / IMAP / POP3 identification
→ directional TCP stream reconstruction
→ STARTTLS detection
→ TLS record + ServerHello parsing
→ negotiated TLS version / cipher / key exchange / Forward Secrecy
→ TLS Certificate handshake extraction (when visible)
→ X.509 parsing and certificate validity/key/signature/chain checks
→ evidence-backed security rules
→ RandomForest risk classification + IsolationForest anomaly signal
→ posture score
→ JSON / HTML / PDF forensic report
→ SHA-256 evidence integrity ledger

## Important passive-analysis limitation

A passive PCAP cannot decrypt TLS 1.3 encrypted handshake messages unless session keys are available. Therefore an X.509 certificate may be extractable from a TLS 1.2 capture but may be **"Not observed"** for TLS 1.3 when the Certificate handshake is encrypted. This is a protocol limitation, not a fabricated result. The dashboard reports what is actually visible in the capture.

The prototype also does not claim that an arbitrary certificate is trusted by a public CA trust store. It verifies observed certificate-chain issuer/subject ordering and, where an issuer certificate is present, verifies the child signature with that issuer.

## Run on Windows

1. Install Python 3.11–3.13 if possible for the smoothest package compatibility.
2. Open this project folder.
3. Run:

```bat
RUN_WINDOWS.bat
```

4. Open `http://127.0.0.1:5000`
5. Go to **PCAP Forensics** → **Choose PCAP**.
6. Select an authorized `.pcap` or `.pcapng` capture.

The backend does the analysis from the uploaded file. The returned `uploaded_sha256` is the SHA-256 hash of the uploaded evidence.

## Generate a controlled PCAP for testing

After dependencies are installed:

```bat
python tools\generate_tls_test_pcap.py
```

This produces `test_data\generated_tls_test.pcap`. It is a **synthetic test capture**, not a real enterprise capture. For a real-world demonstration, capture an authorized SMTP/IMAP/POP3 session with Wireshark/tcpdump.

## Demo fixtures

`test_data\secure_demo.json` and `test_dataulnerable_demo.json` are deterministic UI/demo fixtures. They are intentionally separate from the real upload path.

## Reports

After an analysis, the Reports section can generate:
- JSON — machine-readable evidence
- HTML — shareable forensic report
- PDF — judge-ready report

## Honest prototype scope

Strongly implemented:
- real PCAP/PCAPNG ingestion
- email protocol detection
- directional TCP reconstruction
- STARTTLS detection
- TLS record and ServerHello parsing
- cipher/key-exchange/PFS assessment
- visible X.509 certificate extraction and parsing
- certificate expiry/key/signature/chain checks
- evidence-backed rules
- ML risk/anomaly signals
- posture score and reports
- tamper-evident SHA-256 evidence ledger

Known limitation:
- TLS 1.3 certificate extraction from a passive capture requires decryption/session keys because the certificate is sent after the encrypted handshake begins.
