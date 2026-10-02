"""Deterministic synthetic PCAP generator for BADNET tests and demos.

ALL DATA PRODUCED BY THIS SCRIPT IS SYNTHETIC.  Every hostname, credential,
token and "flag" is invented for testing; nothing here corresponds to a real
system, service or person.  The generator is deterministic (fixed seed, fixed
base timestamp) so hashes of the output are stable across runs and machines,
which is what makes the acceptance tests meaningful.

The capture contains, by design:

* several DNS queries including a tunnelling-like burst of long unique labels;
* an HTTP GET, an HTTP POST carrying a fake credential, and a form login;
* a Base64-encoded blob and a Base32-encoded blob;
* a plaintext CTF flag, plus a flag hidden inside the Base64 blob;
* an HTTP file download carrying a real PNG (magic bytes valid) and a ZIP;
* a TLS ClientHello with SNI and a TLS ServerHello + self-signed certificate;
* multiple TCP streams with proper 3-way handshakes and sequence numbers;
* a few distinct connections, a retransmitted segment and an out-of-order pair;
* one malformed/truncated packet.

Usage::

    python tools/make_sample_pcap.py examples/sample.pcap
    python tools/make_sample_pcap.py examples/sample.pcap --tunnel-burst 400
"""

from __future__ import annotations

import argparse
import base64
import datetime
import struct
import sys
import zlib
from pathlib import Path

# Allow running the script straight from a checkout without installing BADNET.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

#: Fixed base timestamp (2026-01-01 12:00:00 UTC) so output is reproducible.
BASE_TS = 1767268800.0

CLIENT_IP = "10.10.10.50"
SERVER_IP = "93.184.216.34"  # TEST-NET style documentation address
DNS_SERVER = "10.10.10.1"
SECOND_SERVER = "198.51.100.7"  # TEST-NET-2

#: Invented flag - synthetic by construction.
PLAIN_FLAG = "flag{unit_testing_is_great}"
B64_FLAG = "flag{b64_in_http_post_wins}"
B32_SECRET = "S3CRET_B32_N0T_4_FLAG"

#: Populated by :func:`_build_fixture_blobs` on first use.
_FIXTURES: dict[str, bytes] = {}


def png_bytes() -> bytes:
    """Synthetic but structurally valid PNG image."""
    return _FIXTURES.setdefault("png", _make_png())


def zip_bytes() -> bytes:
    """Synthetic ZIP archive containing a readme with a flag inside."""
    return _FIXTURES.setdefault("zip", _make_zip())


def _make_png(width: int = 8, height: int = 8) -> bytes:
    """Build a minimal but genuinely valid 8x8 PNG (real magic bytes + chunks)."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    raw = b""
    for y in range(height):
        row = b"\x00"  # filter type 0 (None)
        for x in range(width):
            row += bytes([(x * 31) % 256, (y * 31) % 256, 0x80])
        raw += row
    idat = zlib.compress(raw, 9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _make_png(width: int = 8, height: int = 8) -> bytes:
    """Build a minimal but genuinely valid 8x8 PNG (real magic bytes + chunks)."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    # Proper scanlines: one filter byte (0 = None) then 3 bytes per pixel.
    raw = b""
    for y in range(height):
        row = b"\x00"
        for x in range(width):
            row += bytes([(x * 31) % 256, (y * 31) % 256, 0x80])
        raw += row
    idat = zlib.compress(raw, 9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


#: Fixed MS-DOS timestamp stored in the synthetic ZIP entries.
_ZIP_DATE_TIME = (2026, 1, 1, 12, 0, 0)


def _make_zip() -> bytes:
    """Build a small valid ZIP archive with a fixed timestamp.

    ``ZipFile.writestr`` stamps entries with the current time, which would make
    the sample PCAP differ on every run; ``ZipInfo`` pins the timestamps instead.
    """
    import io
    import zipfile

    entries = (
        ("readme.txt", "synthetic challenge archive\nflag{inside_the_zip}\n"),
        ("config.json", '{"hint": "the zip held a flag"}'),
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries:
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, text)
    return buf.getvalue()


CTF_HOST = "ctf-challenge.lab"
API_HOST = "api.ctf-challenge.lab"


class FlowBuilder:
    """Accumulates packets for one TCP conversation with correct sequence numbers."""

    def __init__(
        self, client_ip: str, client_port: int, server_ip: str, server_port: int, start_ts: float
    ):
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.ts = start_ts
        self.cseq = 1000
        self.sseq = 5000
        self.packets: list[Ether] = []

    def _next_ts(self, step: float = 0.001) -> float:
        self.ts += step
        return self.ts

    def handshake(self) -> None:
        """Emit SYN, SYN-ACK, ACK."""
        self.packets.append(
            _eth(
                IP(src=self.client_ip, dst=self.server_ip)
                / TCP(
                    sport=self.client_port,
                    dport=self.server_port,
                    flags="S",
                    seq=self.cseq,
                    window=64240,
                ),
                self._next_ts(0.0001),
            )
        )
        self.cseq += 1
        self.packets.append(
            _eth(
                IP(src=self.server_ip, dst=self.client_ip)
                / TCP(
                    sport=self.server_port,
                    dport=self.client_port,
                    flags="SA",
                    seq=self.sseq,
                    ack=self.cseq,
                    window=65535,
                ),
                self._next_ts(0.0001),
            )
        )
        self.sseq += 1
        self.packets.append(
            _eth(
                IP(src=self.client_ip, dst=self.server_ip)
                / TCP(
                    sport=self.client_port,
                    dport=self.server_port,
                    flags="A",
                    seq=self.cseq,
                    ack=self.sseq,
                    window=64240,
                ),
                self._next_ts(0.0001),
            )
        )

    def client_data(self, payload: bytes, *, step: float = 0.001) -> None:
        """Send payload from client to server, updating the sequence space."""
        self.packets.append(
            _eth(
                IP(src=self.client_ip, dst=self.server_ip)
                / TCP(
                    sport=self.client_port,
                    dport=self.server_port,
                    flags="PA",
                    seq=self.cseq,
                    ack=self.sseq,
                    window=64240,
                )
                / Raw(load=payload),
                self._next_ts(step),
            )
        )
        self.cseq += len(payload)

    def server_data(self, payload: bytes, *, step: float = 0.001) -> None:
        """Send payload from server to client, updating the sequence space."""
        self.packets.append(
            _eth(
                IP(src=self.server_ip, dst=self.client_ip)
                / TCP(
                    sport=self.server_port,
                    dport=self.client_port,
                    flags="PA",
                    seq=self.sseq,
                    ack=self.cseq,
                    window=65535,
                )
                / Raw(load=payload),
                self._next_ts(step),
            )
        )
        self.sseq += len(payload)

    def teardown(self) -> None:
        """Emit FIN/ACK exchange and a final ACK."""
        self.packets.append(
            _eth(
                IP(src=self.client_ip, dst=self.server_ip)
                / TCP(
                    sport=self.client_port,
                    dport=self.server_port,
                    flags="FA",
                    seq=self.cseq,
                    ack=self.sseq,
                ),
                self._next_ts(0.001),
            )
        )
        self.cseq += 1
        self.packets.append(
            _eth(
                IP(src=self.server_ip, dst=self.client_ip)
                / TCP(
                    sport=self.server_port,
                    dport=self.client_port,
                    flags="FA",
                    seq=self.sseq,
                    ack=self.cseq,
                ),
                self._next_ts(0.001),
            )
        )
        self.sseq += 1
        self.packets.append(
            _eth(
                IP(src=self.client_ip, dst=self.server_ip)
                / TCP(
                    sport=self.client_port,
                    dport=self.server_port,
                    flags="A",
                    seq=self.cseq,
                    ack=self.sseq,
                ),
                self._next_ts(0.001),
            )
        )


def _eth(payload, ts: float) -> Ether:
    pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / payload
    pkt.time = ts
    return pkt


def _http_response(
    status: int, reason: str, headers: list[tuple[str, str]], body: bytes = b""
) -> bytes:
    head = f"HTTP/1.1 {status} {reason}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    head += f"Content-Length: {len(body)}\r\n" if body else "Connection: close\r\n"
    head += "\r\n"
    return head.encode() + body


def build_packets(
    *, tunnel_burst: int = 60, include_ftp: bool = True, include_smb: bool = True
) -> list[Ether]:
    """Assemble the full synthetic capture as a list of packets."""
    packets: list[Ether] = []
    ts = BASE_TS

    # ------------------------------------------------------------------ DNS
    dns_ts = ts
    dns_queries = [
        (CTF_HOST, "A"),
        (f"www.{CTF_HOST}", "A"),
        (API_HOST, "A"),
        ("mail.ctf-challenge.lab", "MX"),
        (SECOND_SERVER and "version.ctf-challenge.lab", "TXT"),
        # a few normal-looking infrastructure names
        ("cdn.example.com", "A"),
        ("updates.example.org", "A"),
    ]
    qid = 0x1000
    for name, qtype in dns_queries:
        qid += 1
        dns_ts += 0.02
        query = DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        packets.append(
            _eth(
                IP(src=CLIENT_IP, dst=DNS_SERVER)
                / UDP(sport=40000 + (qid % 1000), dport=53)
                / query,
                dns_ts,
            )
        )
        dns_ts += 0.01
        resp_id = qid
        answer_rr = None
        if qtype == "A":
            answer_rr = DNSRR(rrname=name, type="A", ttl=300, rdata=SERVER_IP)
        elif qtype == "MX":
            answer_rr = DNSRR(rrname=name, type="MX", ttl=300, rdata=f"10 mail.{CTF_HOST}")
        elif qtype == "TXT":
            answer_rr = DNSRR(rrname=name, type="TXT", ttl=300, rdata="v1.4.2 challenge build")
        response = DNS(
            id=resp_id, qr=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype=qtype), an=answer_rr
        )
        packets.append(
            _eth(
                IP(src=DNS_SERVER, dst=CLIENT_IP)
                / UDP(sport=53, dport=40000 + (qid % 1000))
                / response,
                dns_ts,
            )
        )

    # DNS tunnelling burst: many long, unique, high-entropy labels under one parent.
    tunnel_ts = dns_ts + 0.5
    for i in range(tunnel_burst):
        # Deterministic pseudo-base32 label (6 bytes -> 10 base32 chars).
        label = (
            base64.b32encode(struct.pack(">Q", 0xC0FFEE0000 + i * 2654435761))
            .decode()
            .rstrip("=")
            .lower()
        )
        qname = f"{label}.tun.exfil-c2.lab"
        qid += 1
        tunnel_ts += 0.005
        query = DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        packets.append(
            _eth(
                IP(src=CLIENT_IP, dst=DNS_SERVER)
                / UDP(sport=40000 + (qid % 1000), dport=53)
                / query,
                tunnel_ts,
            )
        )
        # Most tunnel queries get a reply (to look like exfil), a few are NXDOMAIN.
        if i % 7 != 0:
            tunnel_ts += 0.004
            resp = DNS(
                id=qid,
                qr=1,
                rd=1,
                ra=1,
                rcode=0,
                qd=DNSQR(qname=qname, qtype="TXT"),
                an=DNSRR(rrname=qname, type="TXT", ttl=1, rdata="ok"),
            )
            packets.append(
                _eth(
                    IP(src=DNS_SERVER, dst=CLIENT_IP)
                    / UDP(sport=53, dport=40000 + (qid % 1000))
                    / resp,
                    tunnel_ts,
                )
            )

    # -------------------------------------------------------- HTTP (GET/POST)
    http_ts = tunnel_ts + 1.0

    # Stream 0: GET index (hosts the plaintext flag in the body).
    fb = FlowBuilder(CLIENT_IP, 49152, SERVER_IP, 80, http_ts)
    fb.handshake()
    get_req = (
        f"GET /index.html HTTP/1.1\r\n"
        f"Host: {CTF_HOST}\r\n"
        f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) BADNET-Test/1.0\r\n"
        f"Accept: text/html\r\n"
        f"Referer: http://{CTF_HOST}/\r\n"
        f"\r\n"
    ).encode()
    fb.client_data(get_req)
    index_body = (
        "<html><head><title>CTF Challenge</title></head><body>"
        f"<h1>Welcome</h1><p>Find the flag. {PLAIN_FLAG}</p>"
        "</body></html>"
    ).encode()
    fb.server_data(
        _http_response(
            200,
            "OK",
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Server", "nginx/1.18.0"),
                ("Set-Cookie", "session=s3cr3tsess1onvalue123456; Path=/; HttpOnly"),
            ],
            index_body,
        )
    )

    # Stream 0 (same conversation): GET /.git/config and POST with credentials.
    git_req = (
        f"GET /.git/config HTTP/1.1\r\nHost: {CTF_HOST}\r\nUser-Agent: curl/7.88.1\r\n\r\n"
    ).encode()
    fb.client_data(git_req)
    fb.server_data(
        _http_response(
            200,
            "OK",
            [("Content-Type", "text/plain")],
            b'[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@lab.internal:ctf.git\n',
        )
    )

    b64_blob = base64.b64encode(f"user=admin; {B64_FLAG}".encode()).decode()
    post_req = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: {CTF_HOST}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQxMjM=\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Cookie: PHPSESSID=abc123def456; role=admin\r\n"
        f"Content-Length: {len('user=admin&pass=supersecret123&payload=' + b64_blob)}\r\n"
        f"\r\n"
        f"user=admin&pass=supersecret123&payload={b64_blob}"
    ).encode()
    fb.client_data(post_req)
    fb.server_data(
        _http_response(
            200,
            "OK",
            [("Content-Type", "text/html")],
            b"<html><body>Welcome admin. Decoded payload above.</body></html>",
        )
    )

    # Stream 0: GET /backup.sql and /admin (interesting endpoints).
    sql_req = (
        f"GET /backup.sql HTTP/1.1\r\nHost: {CTF_HOST}\r\nUser-Agent: curl/7.88.1\r\n\r\n"
    ).encode()
    fb.client_data(sql_req)
    fb.server_data(
        _http_response(
            200,
            "OK",
            [("Content-Type", "application/sql")],
            b"-- synthetic dump\nINSERT INTO users VALUES ('admin','hunter2');\n-- api_key=AKIAIOSFODNN7EXAMPLE\n",
        )
    )

    admin_req = (
        f"GET /admin HTTP/1.1\r\nHost: {CTF_HOST}\r\nUser-Agent: curl/7.88.1\r\n\r\n"
    ).encode()
    fb.client_data(admin_req)
    fb.server_data(
        _http_response(403, "Forbidden", [("Content-Type", "text/html")], b"<h1>403</h1>")
    )
    fb.teardown()
    packets.extend(fb.packets)
    http_ts = fb.ts + 0.5

    # ------------------------------------------------------- HTTP file download
    dl_ts = http_ts + 0.5
    fb2 = FlowBuilder(CLIENT_IP, 49200, SERVER_IP, 80, dl_ts)
    fb2.handshake()
    png_req = (
        f"GET /static/logo.png HTTP/1.1\r\n"
        f"Host: {CTF_HOST}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: image/png\r\n"
        f"\r\n"
    ).encode()
    fb2.client_data(png_req)
    fb2.server_data(
        _http_response(
            200,
            "OK",
            [
                ("Content-Type", "image/png"),
                ("Content-Disposition", 'attachment; filename="logo.png"'),
            ],
            png_bytes(),
        )
    )
    zip_req = (
        f"GET /download/challenge.zip HTTP/1.1\r\n"
        f"Host: {CTF_HOST}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    ).encode()
    fb2.client_data(zip_req)
    fb2.server_data(
        _http_response(
            200,
            "OK",
            [
                ("Content-Type", "application/zip"),
                ("Content-Disposition", 'attachment; filename="challenge.zip"'),
            ],
            zip_bytes(),
        )
    )
    fb2.teardown()
    packets.extend(fb2.packets)
    dl_ts = fb2.ts + 0.5

    # ------------------------------------- HTTP base32 secret in a raw TCP "stream"
    fb3 = FlowBuilder(CLIENT_IP, 49250, SERVER_IP, 8080, dl_ts)
    fb3.handshake()
    b32_blob = base64.b32encode(B32_SECRET.encode()).decode().rstrip("=")
    fb3.client_data(f"GET /status HTTP/1.1\r\nHost: {CTF_HOST}:8080\r\nX-Token: {b32_blob}\r\n\r\n")
    fb3.server_data(
        _http_response(
            200,
            "OK",
            [("Content-Type", "text/plain")],
            f"status=ok token={b32_blob}\n".encode(),
        )
    )
    fb3.teardown()
    packets.extend(fb3.packets)
    dl_ts = fb3.ts + 0.5

    # ------------------------------------------------- TLS: ClientHello + server
    tls_ts = dl_ts + 0.5
    fb4 = FlowBuilder(CLIENT_IP, 49300, SERVER_IP, 443, tls_ts)
    fb4.handshake()
    client_hello = _build_client_hello(f"{CTF_HOST}")
    fb4.client_data(client_hello)
    server_hello = _build_server_hello()
    fb4.server_data(server_hello)
    cert_msg = _build_certificate_message()
    fb4.server_data(cert_msg)
    fb4.server_data(_build_server_hello_done())
    fb4.teardown()
    packets.extend(fb4.packets)
    tls_ts = fb4.ts + 0.5

    # ------------------------------------------------------ Retransmission/OoO
    # A separate stream where we deliberately retransmit and reorder to exercise
    # the reassembler.
    ooo_ts = tls_ts + 0.5
    fb5 = FlowBuilder(CLIENT_IP, 49400, SECOND_SERVER, 9001, ooo_ts)
    fb5.handshake()
    body = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4  # 104 bytes, split into segments
    seg1, seg2 = body[:52], body[52:]
    pkt1 = _eth(
        IP(src=fb5.client_ip, dst=fb5.server_ip)
        / TCP(sport=49400, dport=9001, flags="PA", seq=fb5.cseq, ack=fb5.sseq, window=64240)
        / Raw(load=seg1),
        ooo_ts + 0.001,
    )
    pkt2 = _eth(
        IP(src=fb5.client_ip, dst=fb5.server_ip)
        / TCP(sport=49400, dport=9001, flags="PA", seq=fb5.cseq + 52, ack=fb5.sseq, window=64240)
        / Raw(load=seg2),
        ooo_ts + 0.002,
    )
    # Deliver out of order: second segment first.
    packets.append(pkt2)
    packets.append(pkt1)
    # Retransmit the first segment.
    packets.append(pkt1)
    fb5.cseq += len(body)
    reply = b"ACK:" + body[:20]
    fb5.server_data(reply)
    fb5.teardown()
    packets.extend(fb5.packets)
    ooo_ts = fb5.ts + 0.5

    # ------------------------------------------------------------- optional: FTP
    if include_ftp:
        ftp_ts = ooo_ts + 0.5
        fb6 = FlowBuilder(CLIENT_IP, 49500, SERVER_IP, 21, ftp_ts)
        fb6.handshake()
        fb6.server_data(b"220 (vsFTPd 3.0.5) synthetic\r\n")
        fb6.client_data(b"USER anonymous\r\n")
        fb6.server_data(b"331 Please specify the password.\r\n")
        fb6.client_data(b"PASS syntheticpass123\r\n")
        fb6.server_data(b"230 Login successful.\r\n")
        fb6.client_data(b"RETR secret.txt\r\n")
        fb6.server_data(b"150 Opening BINARY mode data connection.\r\n")
        fb6.client_data(b"QUIT\r\n")
        fb6.server_data(b"221 Goodbye.\r\n")
        fb6.teardown()
        packets.extend(fb6.packets)
        ooo_ts = fb6.ts + 0.5

    # ------------------------------------------------------------- optional: SMB
    if include_smb:
        smb_ts = ooo_ts + 0.5
        fb7 = FlowBuilder(CLIENT_IP, 49600, SECOND_SERVER, 445, smb_ts)
        fb7.handshake()
        # NetBIOS session request + minimal SMB negotiate (raw bytes, synthetic).
        nb_req = b"\x00\x00\x00\x85\xffSMB\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00SMBv2\x00\x00"
        fb7.client_data(nb_req)
        nb_resp = b"\x00\x00\x00\x89\xffSMB\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00SMBv2\x00\x00"
        fb7.server_data(nb_resp)
        fb7.teardown()
        packets.extend(fb7.packets)
        ooo_ts = fb7.ts + 0.5

    # ------------------------------------------------- malformed / truncated pkt
    malformed_ts = ooo_ts + 0.5
    # A frame with a valid Ethernet/IP header but a truncated TCP header (claims
    # more header bytes than the payload holds). This exercises malformed counting.
    weird_ip = IP(src=CLIENT_IP, dst="203.0.113.99") / Raw(
        load=struct.pack("!HH", 0x1F90, 445) + b"\x00\x00\x00\x01"  # ports+partial seq
    )
    pkt = _eth(weird_ip, malformed_ts)
    # Chop the captured length so IP total length exceeds the frame: truncation.
    truncated = pkt.__class__(bytes(pkt)[:34])
    truncated.time = malformed_ts
    packets.append(truncated)

    # A frame that is pure noise (unknown ethertype) to ensure robustness.
    noise = _eth(Raw(load=b"\xde\xad\xbe\xef" * 8), malformed_ts + 0.1)
    packets.append(noise)

    # ---------------------------------------------------- internal hostname DNS
    extra_ts = malformed_ts + 0.2
    for name in ["intranet.corp.lab", "db.staging.lab", "grafana.monitoring.lab"]:
        extra_ts += 0.02
        qid += 1
        query = DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="A"))
        packets.append(
            _eth(
                IP(src=CLIENT_IP, dst=DNS_SERVER)
                / UDP(sport=40000 + (qid % 1000), dport=53)
                / query,
                extra_ts,
            )
        )
        resp = DNS(
            id=qid,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=name, qtype="A"),
            an=DNSRR(rrname=name, type="A", ttl=60, rdata="10.10.10.7"),
        )
        packets.append(
            _eth(
                IP(src=DNS_SERVER, dst=CLIENT_IP)
                / UDP(sport=53, dport=40000 + (qid % 1000))
                / resp,
                extra_ts,
            )
        )

    # --------------------------------------------------------- DHCP (handshake)
    dhcp_ts = extra_ts + 0.1
    dhcp_discover = (
        Ether(src="02:00:00:00:00:01")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / Raw(load=bytes.fromhex("010106003c464e74277365726f7665720000000000000000000000006320"))
    )
    dhcp_discover.time = dhcp_ts
    packets.append(dhcp_discover)

    # Keep frames in timestamp order for a tidy timeline (stable, deterministic).
    packets.sort(key=lambda p: float(p.time))
    return packets


# --------------------------------------------------------------- TLS builders


def _build_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 ClientHello record with an SNI extension."""
    import random

    random.seed(0xBADBEEF)
    client_random = bytes(random.getrandbits(8) for _ in range(32))
    session_id = bytes(random.getrandbits(8) for _ in range(32))

    # SNI extension
    server_name = sni.encode()
    sni_entry = b"\x00" + struct.pack(">H", len(server_name)) + server_name
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext_body = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list
    sni_ext = struct.pack(">HH", 0x0000, len(sni_ext_body)) + sni_ext_body

    # Supported versions (TLS 1.2)
    versions = b"\x03\x03\x03\x01"
    ver_ext_body = bytes([len(versions)]) + versions
    ver_ext = struct.pack(">HH", 0x002B, len(ver_ext_body)) + ver_ext_body

    extensions = sni_ext + ver_ext

    ciphers = struct.pack(">H", 8) + struct.pack(">H", 0xC02F) + struct.pack(">H", 0xC030)
    compression = struct.pack(">B", 1) + b"\x00"

    body = (
        struct.pack(">H", 0x0303)
        + client_random
        + struct.pack(">B", len(session_id))
        + session_id
        + ciphers
        + compression
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body  # ClientHello (type 1)
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def _build_server_hello() -> bytes:
    import random

    random.seed(0xC0FFEE)
    server_random = bytes(random.getrandbits(8) for _ in range(32))
    session_id = b"\x11" * 32
    cipher = struct.pack(">H", 0xC02F)  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    compression = b"\x00"
    body = (
        struct.pack(">H", 0x0303)
        + server_random
        + struct.pack(">B", len(session_id))
        + session_id
        + cipher
        + compression
        + struct.pack(">H", 0)
    )
    handshake = b"\x02" + struct.pack(">I", len(body))[1:] + body  # ServerHello
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def _build_certificate_message() -> bytes:
    """Build a Certificate handshake message carrying a self-signed cert DER."""
    der = make_test_certificate_der()
    cert_list = struct.pack(">I", len(der))[1:] + der
    body = struct.pack(">I", len(cert_list))[1:] + cert_list
    handshake = b"\x0b" + struct.pack(">I", len(body))[1:] + body  # Certificate (type 11)
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def _build_server_hello_done() -> bytes:
    body = b""  # ServerHelloDone has no body
    handshake = b"\x0e" + struct.pack(">I", 0)[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


#: A throwaway RSA-2048 key, embedded so the sample PCAP is byte-identical on
#: every run.  It protects nothing and is public in this repository by design.
_SAMPLE_RSA_PKCS8_B64 = (
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtbL6U/ua7VnU0XcwLN3BKiI6O"
    "orBEvNxGGf81o1ZgkmIYYQlqsHo2LFSFdoqAjxXGAXANJP/AYyemeEvYs12ZjK5i4zzAI46lUjC3"
    "GcG9KjTLQoRmjLTdZi2Ian44grvxYQu4+p/yV38EmmhHZP4BksE1PVq/l5tl6pgBLyL32xhhN+2w"
    "5TqlA4R9UjhOV4kYZ1rA22g74HB7VZMVhLcqmKcXmqE2aO7B5jqa56DlJ9x2cG/DrVzKRZf3d+CP"
    "DYdMhAJz8xi7yz8SO+8pdDy6NBRjapCqYdejyAp2mlBRxP1KFukwX/ygFqo7STmagED4Qwi0C5mG"
    "b6p+jxOMsQylAgMBAAECggEACmOMv1DxYFclz8HJm4q0eNPFhnZAnPFf+MKgc9oO0zD0kTkwbqEE"
    "PU9D74cYA7dpw31CnZX13uw3yu/5RE/Xk6V1PVHQ0bN8mr1K8RLJHcbgAoOJmZcklDTUCeO8XCqp"
    "oKPsyGOnELVFaI/Sakqqq/+eQVR1nmvlhS3Lsu7mFSRFNyeFVtDjMWOINnxCikmct1f+lY/oR+1G"
    "F2shlKW0sy85IhWZqt6aSUFMYjS6ygPCZ7Ee0ggPtf0Xxcm1RgPDL4r75+9bcn7K3WEQNOPGUi9S"
    "SDf8+YvCq2bG72wvKDgPXK/ZfJ2nEtKKw53FcO7bIWNj7X7SWAy3t4hnhIxvrQKBgQD2poDq1E7U"
    "+i12DhX9LIWhTwXKsCi6mf5Wm5QWjWEsvRyvDt9Q51cBNj7SKOoHofctC4s570BVrIuTqiScQv8C"
    "z+xC6jTt7AOfANT7YSDuzNiBFS/k3CJi3ZSF1LkiwsgMucap/qiV8MKy0tDicGNOyW3P9LtV7JjB"
    "c7j2FcWhfwKBgQD2bLclSk+xjYzM4M43gyvj87EUfnUnl3LO2q1e6d19ymwjuEM8ghvpkh5ZdlM1"
    "zrOrCGHgWpxsjbCxxEBGu28mi9Av4NF5prkw0h2E4dQxdApTowM/BpJmTD8nHioH8HuIrLZqxslu"
    "js7eyOyn3L95Mtz1xj1SuqBTsvP0+Cib2wKBgQDR9bLQM6JXkg+Y6yy0s22dfxNDEunYzrW/K/jH"
    "qdoKp4D/U/2tdQCPO4oGhGWT0cADTExcKNnvFE5MiQ1ZJ37E+hH4dD5SOhJrC95BjtDl9uJmH48B"
    "lpJ+7ng75HUkrgJ1Mr92fh0sZiKW7vZ5i4o9yyH7YC0IW7s9EjFk6euuKQKBgAbrJnk1jOc/QiS+"
    "awvD8weDYAVjR4bFCcQk/5kal81gUYjvM3QPcxkrsQ5x9AQeuYyjv5u874dcswlKqUNTH9vFMSMm"
    "/Lqdo7VrMMj6TirVRzTx7rVmSdX1bhB7GFMAvXco4jY9PoqMF+LJYVuVJwsQEoQT/MTF2JqA+7h0"
    "/y7hAoGAIsF67t/J+t3nwqgEEvNYGwKLx5xeTc83LVPKFs+UFmqv9WuWAzzxpm2G1OLmOzCHjQDY"
    "fmiis3GN6MlWvFkMDFsk/E65e7T35KGw5mqTO68K0ZiaEBicANnFpFszKnKkrXQXHn2VzY9SxFJV"
    "Iwv1hGtxhUW26GOF1cZy36BctfI="
)

#: Fixed serial number and validity window for the synthetic certificate.
_SAMPLE_CERT_SERIAL = 0x0BADBEEFCAFE0001
_SAMPLE_CERT_NOT_BEFORE = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
_SAMPLE_CERT_NOT_AFTER = datetime.datetime(2035, 1, 1, tzinfo=datetime.UTC)


def sample_signing_key():
    """Load the embedded throwaway RSA key (deterministic across runs)."""
    from cryptography.hazmat.primitives import serialization

    der = base64.b64decode(_SAMPLE_RSA_PKCS8_B64)
    return serialization.load_der_private_key(der, password=None)


def make_test_certificate_der() -> bytes:
    """Build a self-signed DER certificate (synthetic) for the TLS stream.

    Deterministic: fixed key, serial and validity dates, so regenerating the
    sample PCAP reproduces the same bytes.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = sample_signing_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synthetic CTF Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ctf-challenge.lab"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_SAMPLE_CERT_SERIAL)
        .not_valid_before(_SAMPLE_CERT_NOT_BEFORE)
        .not_valid_after(_SAMPLE_CERT_NOT_AFTER)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def write_pcap(path: str | Path, packets: list[Ether]) -> Path:
    """Write packets to a classic little-endian pcap file deterministically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target), packets, linktype=1)  # EN10MB
    return target


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate BADNET's synthetic sample PCAP (all data is fake)."
    )
    parser.add_argument("output", help="path of the pcap to write")
    parser.add_argument(
        "--tunnel-burst", type=int, default=60, help="number of tunnelling-like DNS labels"
    )
    parser.add_argument("--no-ftp", action="store_true", help="skip the FTP conversation")
    parser.add_argument("--no-smb", action="store_true", help="skip the SMB conversation")
    args = parser.parse_args(argv)

    packets = build_packets(
        tunnel_burst=max(5, args.tunnel_burst),
        include_ftp=not args.no_ftp,
        include_smb=not args.no_smb,
    )
    out = write_pcap(args.output, packets)
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(packets)} packets)")
    print("NOTE: every byte of this capture is synthetic test data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
