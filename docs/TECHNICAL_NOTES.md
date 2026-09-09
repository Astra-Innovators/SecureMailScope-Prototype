# Technical Notes

## Security rule examples

- TLS 1.0 / 1.1 → HIGH
- Weak/obsolete cipher → HIGH
- Expired certificate → HIGH
- RSA key < 2048 → HIGH
- No Forward Secrecy → MEDIUM
- Certificate expiring soon → MEDIUM
- TLS 1.2 / 1.3 + modern cipher → generally healthy

## Posture score

The displayed 0–100 score is evidence-weighted and is intentionally separate from the ML class. This avoids pretending that a classifier probability is a security score.

## Limitations of the prototype

- The parser focuses on common SMTP/IMAP/POP3 TCP ports and visible TCP/TLS evidence.
- X.509 certificates are extracted when the TLS Certificate handshake bytes are visible in the passive capture. In TLS 1.3, the Certificate message is normally encrypted after ServerHello, so passive extraction requires session keys/decryption support.
- Certificate-chain checks are limited to the certificates actually observed in the PCAP; this is not a claim of validation against every public trust store.
- The ML model uses synthetic training vectors because no official labeled training set is bundled.
- The local ledger is a hash chain rather than a distributed public blockchain.

These limitations should be stated honestly if asked.

## Future production upgrades

1. Integrate TShark/Zeek for broader protocol dissectors.
2. Add TLS 1.3 session-key/SSLKEYLOGFILE support and broader X.509/chain validation.
3. Store sessions in PostgreSQL/Elastic.
4. Replace synthetic ML training with validated labeled enterprise captures.
5. Deploy a permissioned blockchain for multi-team evidence attestation.
6. Add RBAC, encryption-at-rest, audit logs and secure object storage.
