# SecureMailScope Architecture

```text
                    ┌──────────────────────┐
                    │ PCAP / PCAPNG Upload  │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Passive PCAP Parser   │
                    │ Scapy + TCP grouping  │
                    └──────────┬───────────┘
                               ↓
             ┌─────────────────┼─────────────────┐
             ↓                 ↓                 ↓
          SMTP              IMAP              POP3
             └─────────────────┼─────────────────┘
                               ↓
                    STARTTLS / TLS evidence
                               ↓
                    ┌──────────────────────┐
                    │ TLS + X.509 Analyzer │
                    │ version/cipher/PFS   │
                    │ cert/expiry/key/sig   │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Security Rule Engine │
                    │ evidence-backed      │
                    └──────────┬───────────┘
                               ↓
              ┌────────────────┴────────────────┐
              ↓                                 ↓
       RandomForest                         IsolationForest
       risk classification                 anomaly detection
              └────────────────┬────────────────┘
                               ↓
                    Security Posture Score
                               ↓
                    ┌──────────────────────┐
                    │ Evidence Integrity   │
                    │ SHA-256 hash chain   │
                    └──────────┬───────────┘
                               ↓
                   JSON / HTML / PDF Reports
```

## Why the blockchain layer is separate

The PS asks for cryptographic security assessment of email traffic, not cryptocurrency payments. Therefore blockchain is used where it has a defensible role: evidence integrity and tamper detection. This prevents forced/irrelevant blockchain functionality.

## Data flow

`Uploaded PCAP bytes → directional TCP streams → email sessions → visible TLS/X.509 features → rules + ML → findings → posture → ledger → reports`
