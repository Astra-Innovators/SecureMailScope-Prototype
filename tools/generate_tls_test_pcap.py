"""Generate a controlled SMTP STARTTLS PCAP for SecureMailScope testing.
Requires project dependencies (Scapy + cryptography).
This is synthetic traffic, not a real enterprise capture.
"""
from pathlib import Path
from datetime import datetime, timezone, timedelta
from scapy.all import IP, TCP, Raw, wrpcap
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "test_data" / "generated_tls_test.pcap"

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.test.local")])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=90))
        .sign(key, hashes.SHA256()))
der = cert.public_bytes(serialization.Encoding.DER)

def tls_record(data):
    return b"\x16\x03\x03" + len(data).to_bytes(2, "big") + data

# Minimal ServerHello with ECDHE_RSA AES-128-GCM.
server_hello_body = (b"\x03\x03" + b"\x01"*32 + b"\x00" +
                     b"\xc0\x2f" + b"\x00" + b"\x00\x00")
server_hello = b"\x02" + len(server_hello_body).to_bytes(3,"big") + server_hello_body

# TLS 1.2 Certificate handshake.
cert_body = (len(der)+3).to_bytes(3,"big") + len(der).to_bytes(3,"big") + der
certificate = b"\x0b" + len(cert_body).to_bytes(3,"big") + cert_body

client_ip, server_ip = "10.10.10.20", "10.10.10.10"
client_port, server_port = 51000, 587
cseq, sseq = 1000, 2000

packets = [
    IP(src=client_ip,dst=server_ip)/TCP(sport=client_port,dport=server_port,seq=cseq,flags="PA")/
        Raw(load=b"EHLO client.test\r\nSTARTTLS\r\n"),
    IP(src=server_ip,dst=client_ip)/TCP(sport=server_port,dport=client_port,seq=sseq,flags="PA")/
        Raw(load=b"220 Ready to start TLS\r\n"),
    IP(src=server_ip,dst=client_ip)/TCP(sport=server_port,dport=client_port,
        seq=sseq+len(b"220 Ready to start TLS\r\n"),flags="PA")/
        Raw(load=tls_record(server_hello)+tls_record(certificate)),
]
wrpcap(str(OUT), packets)
print(f"Generated: {OUT}")
