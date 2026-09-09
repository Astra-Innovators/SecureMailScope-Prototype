from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, padding

def _name(cert_name):
    try:
        return cert_name.rfc4514_string()
    except Exception:
        return str(cert_name)

def _sig_name(cert):
    return cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string

def _verify_signature(child, issuer):
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, dsa.DSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, child.signature_hash_algorithm)
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
        return True
    except Exception:
        return False

def extract_x509_certificates(cert_der_list):
    """Decode certificates captured from a TLS Certificate handshake."""
    if not cert_der_list:
        return {
            "extracted": False,
            "chain_length": 0,
            "chain": [],
            "chain_signature_valid": None,
            "chain_order_valid": None,
            "reason": "No X.509 certificate bytes were observed in the captured TLS handshake."
        }

    certs = []
    errors = []
    for idx, der in enumerate(cert_der_list, 1):
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except Exception as exc:
            errors.append(f"Certificate {idx}: {exc}")

    if not certs:
        return {"extracted": False, "chain_length": 0, "chain": [], "errors": errors}

    now = datetime.now(timezone.utc)
    chain_info = []
    for cert in certs:
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            algorithm, key_length = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            algorithm, key_length = "EC", pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            algorithm, key_length = "DSA", pub.key_size
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            algorithm, key_length = ("Ed25519" if isinstance(pub, ed25519.Ed25519PublicKey) else "Ed448"), None
        else:
            algorithm, key_length = type(pub).__name__, None
        expired = now > not_after
        days = int((not_after - now).total_seconds() / 86400)
        chain_info.append({
            "subject": _name(cert.subject),
            "issuer": _name(cert.issuer),
            "serial_number": str(cert.serial_number),
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "days_to_expiry": days,
            "expired": expired,
            "expires_soon": (not expired and days <= 30),
            "public_key_algorithm": algorithm,
            "key_length": key_length,
            "signature_algorithm": _sig_name(cert),
            "self_signed": cert.subject == cert.issuer,
        })

    order_ok = True
    signatures_ok = True
    for child, issuer in zip(certs, certs[1:]):
        if child.issuer != issuer.subject:
            order_ok = False
        if not _verify_signature(child, issuer):
            signatures_ok = False

    leaf = chain_info[0]
    result = dict(leaf)
    result.update({
        "extracted": True,
        "chain_length": len(certs),
        "chain": chain_info,
        "chain_order_valid": order_ok,
        "chain_signature_valid": signatures_ok if len(certs) > 1 else None,
        "errors": errors,
    })
    return result

def extract_certificate_handshake(handshake_messages):
    """Extract DER certificates from TLS Certificate handshake bodies.

    Supports the TLS 1.2 and TLS 1.3 Certificate message layout.
    """
    cert_der = []
    for ht, body, _offset in handshake_messages:
        if ht != 11 or len(body) < 3:
            continue
        try:
            total = int.from_bytes(body[:3], "big")
            end = min(len(body), 3 + total)
            p = 3
            while p + 3 <= end:
                ln = int.from_bytes(body[p:p+3], "big")
                p += 3
                if p + ln > end:
                    break
                cert_der.append(body[p:p+ln])
                p += ln
                # TLS 1.3 certificate_entry has extensions length after each cert.
                if p + 2 <= end:
                    ext_len = int.from_bytes(body[p:p+2], "big")
                    if p + 2 + ext_len <= end:
                        p += 2 + ext_len
                    else:
                        # TLS 1.2 list has no per-certificate extensions.
                        pass
            if cert_der:
                break
        except Exception:
            continue
    return extract_x509_certificates(cert_der)
