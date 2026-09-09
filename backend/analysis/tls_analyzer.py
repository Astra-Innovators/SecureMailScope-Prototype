import re
from datetime import datetime, timezone

TLS_VERSIONS = {
    b"\x03\x00": "SSL 3.0",
    b"\x03\x01": "TLS 1.0",
    b"\x03\x02": "TLS 1.1",
    b"\x03\x03": "TLS 1.2",
    b"\x03\x04": "TLS 1.3",
}

CIPHERS = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

def _u16(b, i):
    return int.from_bytes(b[i:i+2], "big")

def _u24(b, i):
    return int.from_bytes(b[i:i+3], "big")

def _parse_extensions(ext):
    out = {}
    i = 0
    while i + 4 <= len(ext):
        typ = _u16(ext, i); ln = _u16(ext, i+2); i += 4
        if i + ln > len(ext):
            break
        out[typ] = ext[i:i+ln]
        i += ln
    return out

def _parse_server_hello(body):
    result = {"cipher_suite": "", "version": "", "key_exchange": "", "forward_secrecy": None}
    if len(body) < 38:
        return result
    legacy_version = body[:2]
    result["version"] = TLS_VERSIONS.get(legacy_version, "")
    p = 34
    sid_len = body[p]; p += 1
    if p + sid_len + 3 > len(body):
        return result
    p += sid_len
    cipher_id = _u16(body, p); p += 2
    p += 1  # compression
    result["cipher_suite"] = CIPHERS.get(cipher_id, f"UNKNOWN(0x{cipher_id:04x})")
    if p + 2 <= len(body):
        ext_len = _u16(body, p); p += 2
        exts = _parse_extensions(body[p:p+ext_len])
        if 43 in exts and len(exts[43]) >= 2:  # supported_versions
            result["version"] = TLS_VERSIONS.get(exts[43][-2:], result["version"])
    cipher = result["cipher_suite"].upper()
    if "ECDHE" in cipher or "DHE" in cipher:
        result["key_exchange"] = "ECDHE/DHE"
        result["forward_secrecy"] = True
    elif "RSA" in cipher:
        result["key_exchange"] = "RSA"
        result["forward_secrecy"] = False
    return result

def parse_tls_stream(stream: bytes):
    """Parse TLS records and reassemble handshake messages across records."""
    records = []
    handshake_bytes = bytearray()
    i = 0
    scanned = 0
    while i + 5 <= len(stream) and scanned < len(stream):
        typ = stream[i]
        ver = stream[i+1:i+3]
        ln = int.from_bytes(stream[i+3:i+5], "big")
        plausible = typ in (20, 21, 22, 23) and ver[:1] == b"\x03" and 0 < ln <= 18432
        if not plausible:
            i += 1
            scanned += 1
            continue
        if i + 5 + ln > len(stream):
            break
        payload = stream[i+5:i+5+ln]
        records.append({"type": typ, "version": TLS_VERSIONS.get(ver, f"TLS legacy 0x{ver.hex()}"), "offset": i, "length": ln})
        if typ == 22:
            handshake_bytes.extend(payload)
        i += 5 + ln
        scanned = i

    handshakes = []
    p = 0
    while p + 4 <= len(handshake_bytes):
        ht = handshake_bytes[p]
        hln = _u24(handshake_bytes, p+1)
        if p + 4 + hln > len(handshake_bytes):
            break
        body = bytes(handshake_bytes[p+4:p+4+hln])
        # Locate evidence offset in the reassembled handshake buffer, not packet offset.
        handshakes.append((ht, body, p))
        p += 4 + hln
    return records, handshakes

def inspect_payload(payload: bytes):
    out = {
        "tls_detected": False,
        "version": "",
        "cipher_suite": "",
        "key_exchange": "",
        "handshake_status": "",
        "forward_secrecy": None,
        "record_count": 0,
        "certificate_handshake_observed": False,
        "evidence": []
    }
    if not payload:
        return out

    records, handshakes = parse_tls_stream(payload)
    out["record_count"] = len(records)
    if records:
        out["tls_detected"] = True
        out["version"] = records[0]["version"]
        out["handshake_status"] = f"{len(records)} TLS record(s) observed"
        out["evidence"].append(f"TLS record detected at payload offset {records[0]['offset']}")
        for ht, body, offset in handshakes:
            if ht == 2:  # ServerHello
                hello = _parse_server_hello(body)
                for k, v in hello.items():
                    if v:
                        out[k] = v
                out["evidence"].append(f"ServerHello handshake parsed at payload offset {offset}")
                break
        if any(ht == 11 for ht, _, _ in handshakes):
            out["certificate_handshake_observed"] = True
            out["evidence"].append("TLS Certificate handshake observed")
        if not out["cipher_suite"]:
            # Compatibility fallback for captures where ServerHello is fragmented/partial.
            for code, name in CIPHERS.items():
                raw = code.to_bytes(2, "big")
                if raw in payload[:16384]:
                    out["cipher_suite"] = name
                    break
        if not out["key_exchange"]:
            cipher = out["cipher_suite"].upper()
            if "ECDHE" in cipher or "DHE" in cipher:
                out["key_exchange"], out["forward_secrecy"] = "ECDHE/DHE", True
            elif "RSA" in cipher:
                out["key_exchange"], out["forward_secrecy"] = "RSA", False
        return out

    # Text fallback is deliberately marked as a weak indicator, not a full TLS parse.
    txt = payload[:16384].decode("latin1", errors="ignore")
    m = re.search(r"TLS\s*1\.[0-3]", txt, re.I)
    if m:
        out["tls_detected"] = True
        out["version"] = m.group(0).upper().replace(" ", "")
        out["handshake_status"] = "TLS version text indicator observed (partial)"
        out["evidence"].append("Textual TLS version indicator observed; binary handshake not reconstructed")
    return out
