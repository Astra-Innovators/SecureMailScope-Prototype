from collections import defaultdict
from pathlib import Path
import hashlib

EMAIL_PORTS = {
    25: "SMTP", 465: "SMTP", 587: "SMTP",
    110: "POP3", 995: "POP3",
    143: "IMAP", 993: "IMAP",
}
EMAIL_SERVER_PORTS = set(EMAIL_PORTS)
STARTTLS_PATTERNS = [b"STARTTLS", b"starttls"]

def _reassemble(chunks):
    """Best-effort TCP byte-stream reconstruction with overlap/retransmission removal."""
    if not chunks:
        return b""
    chunks = sorted(chunks, key=lambda x: x[0])
    out = bytearray()
    next_seq = None
    for seq, payload in chunks:
        if not payload:
            continue
        if next_seq is None:
            out.extend(payload)
            next_seq = seq + len(payload)
            continue
        if seq >= next_seq:
            out.extend(payload)
            next_seq = seq + len(payload)
        else:
            overlap = next_seq - seq
            if overlap < len(payload):
                out.extend(payload[overlap:])
                next_seq += len(payload) - overlap
    return bytes(out)

class PCAPParser:
    def __init__(self, path):
        self.path = Path(path)

    def parse(self):
        try:
            from scapy.all import rdpcap, TCP, IP, IPv6, Raw
        except Exception as exc:
            raise RuntimeError("Scapy is required for PCAP parsing. Install requirements.txt.") from exc

        try:
            packets = rdpcap(str(self.path))
        except Exception as exc:
            raise RuntimeError(f"Unable to read PCAP/PCAPNG: {exc}") from exc

        # Key by protocol + unordered endpoint pair. Keep each direction separately.
        flows = defaultdict(lambda: {
            "dirs": defaultdict(list), "packets": 0, "bytes": 0,
            "first_ts": None, "last_ts": None
        })

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            proto = EMAIL_PORTS.get(dport) or EMAIL_PORTS.get(sport)
            if not proto and raw:
                text = raw[:4096].decode("latin1", errors="ignore").upper()
                if any(x in text for x in ("EHLO", "HELO", "MAIL FROM", "IMAP", "POP3")):
                    proto = "SMTP" if ("EHLO" in text or "MAIL FROM" in text) else ("IMAP" if "IMAP" in text else "POP3")
            if not proto:
                continue

            src = str(pkt[IP].src) if pkt.haslayer(IP) else (str(pkt[IPv6].src) if pkt.haslayer(IPv6) else "")
            dst = str(pkt[IP].dst) if pkt.haslayer(IP) else (str(pkt[IPv6].dst) if pkt.haslayer(IPv6) else "")
            a, b = (src, sport), (dst, dport)
            flow_key = tuple(sorted([a, b], key=str))
            key = (proto, flow_key)
            f = flows[key]
            f["dirs"][(src, sport, dst, dport)].append((int(tcp.seq), raw))
            f["packets"] += 1
            f["bytes"] += len(raw)
            ts = float(getattr(pkt, "time", 0))
            f["first_ts"] = ts if f["first_ts"] is None else min(f["first_ts"], ts)
            f["last_ts"] = ts if f["last_ts"] is None else max(f["last_ts"], ts)

        sessions = []
        from backend.analysis.tls_analyzer import inspect_payload, parse_tls_stream
        from backend.analysis.certificate_analyzer import extract_certificate_handshake

        for idx, ((proto, flow), f) in enumerate(flows.items(), start=1):
            endpoints = list(flow)
            # Server endpoint is the endpoint using the well-known email port when available.
            server = next((e for e in endpoints if e[1] in EMAIL_SERVER_PORTS), endpoints[1] if len(endpoints) > 1 else endpoints[0])
            client = endpoints[0] if endpoints[0] != server else (endpoints[1] if len(endpoints) > 1 else endpoints[0])

            direction_streams = {}
            for direction, chunks in f["dirs"].items():
                direction_streams[direction] = _reassemble(chunks)

            combined = b"".join(direction_streams.values())
            starttls = any(p in combined for p in STARTTLS_PATTERNS)

            # TLS normally appears client->server and server->client. Prefer server response
            # for certificate/cipher extraction; inspect both directions for robust detection.
            server_key = next((k for k in direction_streams if k[0] == server[0] and k[1] == server[1]), None)
            client_key = next((k for k in direction_streams if k[0] == client[0] and k[1] == client[1]), None)
            server_stream = direction_streams.get(server_key, b"")
            client_stream = direction_streams.get(client_key, b"")
            server_tls = inspect_payload(server_stream)
            client_tls = inspect_payload(client_stream)
            tls = server_tls if server_tls.get("tls_detected") else client_tls
            if server_tls.get("tls_detected") and client_tls.get("tls_detected"):
                # ServerHello is the authoritative source for negotiated version/cipher.
                for k in ("version", "cipher_suite", "key_exchange", "forward_secrecy"):
                    if server_tls.get(k) not in ("", None):
                        tls[k] = server_tls[k]
                tls["evidence"] = list(dict.fromkeys(client_tls.get("evidence", []) + server_tls.get("evidence", [])))

            server_records, server_handshakes = parse_tls_stream(server_stream)
            cert = extract_certificate_handshake(server_handshakes)

            encrypted = bool(
                server_tls.get("tls_detected") or client_tls.get("tls_detected")
                or (proto == "SMTP" and (server[1] == 465 or client[1] == 465))
                or (proto == "IMAP" and (server[1] == 993 or client[1] == 993))
                or (proto == "POP3" and (server[1] == 995 or client[1] == 995))
            )

            sessions.append({
                "session_id": f"SESSION_{idx:03d}",
                "protocol": proto,
                "source": client[0],
                "destination": server[0],
                "source_port": client[1],
                "destination_port": server[1],
                "packets": f["packets"],
                "payload_bytes": f["bytes"],
                "starttls_detected": starttls,
                "encrypted": encrypted,
                "tls": tls,
                "certificate": cert,
                "tcp_reconstructed": True,
                "server_certificate_observed": bool(cert.get("extracted")),
                "evidence": [
                    f"{f['packets']} TCP packets grouped into a bidirectional {proto} flow",
                    f"{f['bytes']} payload bytes observed",
                    f"Client→server stream: {len(client_stream)} bytes; server→client stream: {len(server_stream)} bytes",
                ],
            })

        return {
            "file_name": self.path.name,
            "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
            "packet_count": len(packets),
            "sessions": sessions,
            "parser": "Scapy passive TCP-flow parser with directional TCP reassembly and TLS/X.509 extraction"
        }
