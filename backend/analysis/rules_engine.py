from datetime import datetime, timezone

def _num(value):
    try:
        return int(value)
    except Exception:
        return 0

def evaluate(session):
    findings = []
    tls = session.get("tls", {}) or {}
    cert = session.get("certificate", {}) or {}

    version = str(tls.get("version") or "").upper()
    cipher = str(tls.get("cipher_suite") or "").upper()
    key_exchange = str(tls.get("key_exchange") or "").upper()
    fs = tls.get("forward_secrecy")

    if version in {"TLS 1.0", "TLS 1.1", "SSL 3.0"}:
        findings.append({
            "id": "TLS-LEGACY",
            "severity": "HIGH",
            "title": f"Deprecated TLS version detected: {version}",
            "evidence": f"Session {session.get('session_id')} negotiated {version}.",
            "why": "Legacy protocol versions provide weaker cryptographic protection and should not be used for modern secure email.",
            "recommendation": "Disable TLS 1.0/1.1 and enforce TLS 1.2+; prefer TLS 1.3.",
            "session_id": session.get("session_id")
        })

    weak_terms = ("3DES", "DES", "RC4", "NULL", "EXPORT", "MD5", "RC2")
    if any(t in cipher for t in weak_terms):
        findings.append({
            "id": "WEAK-CIPHER",
            "severity": "HIGH",
            "title": f"Weak or obsolete cipher detected: {cipher}",
            "evidence": f"Session {session.get('session_id')} reports cipher {cipher}.",
            "why": "Obsolete/weak ciphers reduce confidentiality and cryptographic resilience.",
            "recommendation": "Prefer AES-GCM or ChaCha20-Poly1305 with modern TLS.",
            "session_id": session.get("session_id")
        })

    if cert.get("expired") is True:
        findings.append({
            "id": "CERT-EXPIRED",
            "severity": "HIGH",
            "title": "X.509 certificate is expired",
            "evidence": f"Certificate validity ended at {cert.get('valid_to')}.",
            "why": "An expired certificate indicates an invalid or improperly maintained trust configuration.",
            "recommendation": "Renew the certificate and verify the complete certificate chain.",
            "session_id": session.get("session_id")
        })
    elif cert.get("expires_soon") is True:
        findings.append({
            "id": "CERT-SOON",
            "severity": "MEDIUM",
            "title": "X.509 certificate expires soon",
            "evidence": f"Certificate validity ends at {cert.get('valid_to')}.",
            "why": "Upcoming certificate expiry can cause service interruption or invalid trust decisions.",
            "recommendation": "Renew before the expiry window and verify automated certificate rotation.",
            "session_id": session.get("session_id")
        })

    key_len = _num(cert.get("key_length"))
    if key_len and key_len < 2048:
        findings.append({
            "id": "WEAK-KEY",
            "severity": "HIGH",
            "title": f"Weak public-key length detected: {key_len} bits",
            "evidence": f"Certificate public key length is {key_len} bits.",
            "why": "Short public keys provide less security against modern cryptanalytic attacks.",
            "recommendation": "Use RSA 2048+ or an appropriate modern elliptic-curve key.",
            "session_id": session.get("session_id")
        })


    if cert.get("chain_order_valid") is False:
        findings.append({
            "id": "CERT-CHAIN-ORDER",
            "severity": "HIGH",
            "title": "Certificate chain order is inconsistent",
            "evidence": "Observed X.509 issuer/subject relationships do not form the expected chain order.",
            "why": "A malformed or incorrectly ordered certificate chain can prevent clients from establishing trust.",
            "recommendation": "Serve the correct leaf-to-intermediate certificate chain and verify the server configuration.",
            "session_id": session.get("session_id")
        })

    if cert.get("chain_signature_valid") is False:
        findings.append({
            "id": "CERT-CHAIN-SIGNATURE",
            "severity": "HIGH",
            "title": "Certificate chain signature verification failed",
            "evidence": "One or more observed child certificates could not be verified with the next issuer certificate.",
            "why": "A failed chain signature check indicates an inconsistent or potentially tampered certificate chain.",
            "recommendation": "Replace the invalid certificate chain and verify every certificate signature before deployment.",
            "session_id": session.get("session_id")
        })

    sig = str(cert.get("signature_algorithm") or "").upper()
    if sig and any(x in sig for x in ("MD5", "SHA1")):
        findings.append({
            "id": "WEAK-CERT-SIGNATURE",
            "severity": "HIGH",
            "title": f"Weak certificate signature algorithm detected: {cert.get('signature_algorithm')}",
            "evidence": f"Leaf X.509 certificate uses {cert.get('signature_algorithm')}.",
            "why": "Legacy hash algorithms such as MD5/SHA-1 are no longer recommended for certificate signatures.",
            "recommendation": "Use a certificate signed with a modern SHA-256-or-stronger signature algorithm.",
            "session_id": session.get("session_id")
        })

    if fs is False or (key_exchange and key_exchange in {"RSA", "STATIC RSA"}):
        findings.append({
            "id": "NO-PFS",
            "severity": "MEDIUM",
            "title": "Forward Secrecy not demonstrated",
            "evidence": f"Key exchange: {key_exchange or 'not observed'}.",
            "why": "Without ephemeral key exchange, compromise of a long-term key can increase historical-session exposure.",
            "recommendation": "Prefer ECDHE/DHE based cipher suites and modern TLS configurations.",
            "session_id": session.get("session_id")
        })

    if session.get("starttls_detected") and not session.get("encrypted"):
        findings.append({
            "id": "STARTTLS-NO-UPGRADE",
            "severity": "HIGH",
            "title": "STARTTLS advertised/requested but encrypted transition was not observed",
            "evidence": f"STARTTLS indicator found in {session.get('session_id')} without a visible encrypted transition.",
            "why": "An incomplete or failed upgrade can expose email traffic to downgrade or interception risk.",
            "recommendation": "Require STARTTLS where appropriate and verify successful TLS negotiation.",
            "session_id": session.get("session_id")
        })

    return findings

def summarize(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
