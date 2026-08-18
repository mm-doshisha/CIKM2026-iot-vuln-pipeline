"""Generate pcap files from HTTP request dictionaries.

Uses scapy to construct proper TCP streams so Suricata's HTTP parser
can reassemble and inspect the traffic.
"""

import logging
import posixpath
import re
import struct
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlencode


def _quote_for_query(string, safe='', encoding=None, errors=None):
    """Like quote() but preserves '/' per RFC 3986 §3.4 (allowed unencoded in query)."""
    return quote(string, safe=safe + '/', encoding=encoding, errors=errors)

logger = logging.getLogger("pcap_generator")

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_RAW_IP = 101


def _build_http_payload(http_req: dict) -> bytes:
    """Build raw HTTP request bytes from a structured request dict."""
    method = http_req.get("method", "GET")
    path = http_req.get("path", "/")
    params = http_req.get("params", {})
    headers = http_req.get("headers", {})
    body = http_req.get("body") or ""

    if "?" in path:
        request_line = f"{method} {path} HTTP/1.1\r\n"
    elif params:
        query = urlencode(params, quote_via=_quote_for_query)
        request_line = f"{method} {path}?{query} HTTP/1.1\r\n"
    else:
        request_line = f"{method} {path} HTTP/1.1\r\n"

    header_lines = "Host: 192.168.1.100\r\n"
    for k, v in headers.items():
        header_lines += f"{k}: {v}\r\n"

    if body and "Content-Length" not in headers:
        if isinstance(body, dict):
            body = urlencode(body, quote_via=_quote_for_query)
        header_lines += f"Content-Length: {len(body)}\r\n"
        if "Content-Type" not in headers:
            header_lines += "Content-Type: application/x-www-form-urlencoded\r\n"

    raw = request_line + header_lines + "\r\n"
    if body:
        if isinstance(body, dict):
            body = urlencode(body, quote_via=_quote_for_query)
        raw += body

    return raw.encode("utf-8", errors="replace")


def wire_buffers(http_req: dict) -> dict:
    """On-wire byte content (as str) for each Suricata buffer, using the SAME
    serialization rules as ``_build_http_payload`` (the PCAP writer). This is the
    single source of truth for the rule template: any ``content:"..."`` it emits
    must be a contiguous substring of the corresponding buffer here, so that a rule
    built from a request is guaranteed to fire on that request's PCAP. The mapping
    is derived purely from HTTP/wire encoding rules (RFC 3986, Suricata buffer
    normalization), independent of any specific attack or dataset.
    """
    path = http_req.get("path", "/")
    params = http_req.get("params", {})
    headers = http_req.get("headers", {}) or {}
    body = http_req.get("body") or ""

    if "?" in path:
        uri_raw = path
    elif params:
        uri_raw = f"{path}?{urlencode(params, quote_via=_quote_for_query)}"
    else:
        uri_raw = path

    if isinstance(body, dict):
        body_wire = urlencode(body, quote_via=_quote_for_query)
    else:
        body_wire = str(body)

    # Suricata's http.uri is percent-decoded AND path-normalized (libhtp resolves
    # './' and '../' and collapses '//'), so model that to keep the substring
    # invariant faithful. Only the path part is normalized; the query is kept.
    uri_dec = unquote(uri_raw)
    if "?" in uri_dec:
        _p, _q = uri_dec.split("?", 1)
        uri_norm = (posixpath.normpath(_p) if _p.startswith("/") else _p) + "?" + _q
    else:
        uri_norm = posixpath.normpath(uri_dec) if uri_dec.startswith("/") else uri_dec

    bufs = {
        "http.uri.raw": uri_raw,
        "http.uri": uri_norm,
        "http.request_body": body_wire,
        "http.header": "".join(f"{k}: {v}\r\n" for k, v in headers.items()),
    }
    for k, v in headers.items():
        kl = str(k).lower()
        if kl == "cookie":
            bufs["http.cookie"] = str(v)
        elif kl == "host":
            bufs["http.host"] = str(v)
        elif kl in ("user-agent", "user_agent"):
            bufs["http.user_agent"] = str(v)
    return bufs


def _ip_checksum(header_bytes: bytes) -> int:
    if len(header_bytes) % 2 != 0:
        header_bytes += b'\x00'
    s = 0
    for i in range(0, len(header_bytes), 2):
        s += (header_bytes[i] << 8) + header_bytes[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, payload_len: int,
                     protocol: int = 6) -> bytes:
    """Build an IPv4 header (no options)."""
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64

    src = _ip_to_bytes(src_ip)
    dst = _ip_to_bytes(dst_ip)

    header = struct.pack("!BBHHHBBH4s4s",
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, 0,
                         src, dst)
    chksum = _ip_checksum(header)
    header = struct.pack("!BBHHHBBH4s4s",
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, chksum,
                         src, dst)
    return header


def _ip_to_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split("."))


def _build_tcp_header(sport: int, dport: int, seq: int, ack: int,
                      flags: int, payload: bytes = b"",
                      src_ip: str = "203.0.113.1", dst_ip: str = "192.168.1.100") -> bytes:
    """Build a TCP header with correct checksum."""
    data_offset = 5
    offset_flags = (data_offset << 12) | flags
    window = 65535
    urgent = 0

    tcp_header = struct.pack("!HHIIHHHH",
                             sport, dport, seq, ack,
                             offset_flags, window, 0, urgent)

    pseudo = _ip_to_bytes(src_ip) + _ip_to_bytes(dst_ip)
    pseudo += struct.pack("!BBH", 0, 6, len(tcp_header) + len(payload))
    chksum = _ip_checksum(pseudo + tcp_header + payload)

    tcp_header = struct.pack("!HHIIHHHH",
                             sport, dport, seq, ack,
                             offset_flags, window, chksum, urgent)

    return tcp_header


# TCP flags
TCP_SYN = 0x002
TCP_ACK = 0x010
TCP_SYNACK = 0x012
TCP_PSH_ACK = 0x018
TCP_FIN_ACK = 0x011


def _build_tcp_stream(http_payload: bytes,
                      src_ip: str = "203.0.113.1", dst_ip: str = "192.168.1.100",
                      sport: int = 12345, dport: int = 80) -> list:
    """Build a complete TCP stream (handshake + data + teardown) as raw IP packets."""
    packets = []
    client_seq = 1000
    server_seq = 2000

    # SYN
    tcp = _build_tcp_header(sport, dport, client_seq, 0, TCP_SYN,
                            src_ip=src_ip, dst_ip=dst_ip)
    ip = _build_ip_header(src_ip, dst_ip, len(tcp))
    packets.append(ip + tcp)
    client_seq += 1

    # SYN-ACK
    tcp = _build_tcp_header(dport, sport, server_seq, client_seq, TCP_SYNACK,
                            src_ip=dst_ip, dst_ip=src_ip)
    ip = _build_ip_header(dst_ip, src_ip, len(tcp))
    packets.append(ip + tcp)
    server_seq += 1

    # ACK
    tcp = _build_tcp_header(sport, dport, client_seq, server_seq, TCP_ACK,
                            src_ip=src_ip, dst_ip=dst_ip)
    ip = _build_ip_header(src_ip, dst_ip, len(tcp))
    packets.append(ip + tcp)

    # HTTP request — split into MSS-sized segments if needed
    MSS = 1460
    offset = 0
    while offset < len(http_payload):
        chunk = http_payload[offset:offset + MSS]
        is_last = (offset + MSS >= len(http_payload))
        flags = TCP_PSH_ACK if is_last else TCP_ACK
        tcp = _build_tcp_header(sport, dport, client_seq, server_seq, flags,
                                payload=chunk, src_ip=src_ip, dst_ip=dst_ip)
        ip = _build_ip_header(src_ip, dst_ip, len(tcp) + len(chunk))
        packets.append(ip + tcp + chunk)
        client_seq += len(chunk)
        offset += MSS

    # Server ACK
    tcp = _build_tcp_header(dport, sport, server_seq, client_seq, TCP_ACK,
                            src_ip=dst_ip, dst_ip=src_ip)
    ip = _build_ip_header(dst_ip, src_ip, len(tcp))
    packets.append(ip + tcp)

    # HTTP response (minimal 200 OK)
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    tcp = _build_tcp_header(dport, sport, server_seq, client_seq, TCP_PSH_ACK,
                            payload=response, src_ip=dst_ip, dst_ip=src_ip)
    ip = _build_ip_header(dst_ip, src_ip, len(tcp) + len(response))
    packets.append(ip + tcp + response)
    server_seq += len(response)

    # Client ACK
    tcp = _build_tcp_header(sport, dport, client_seq, server_seq, TCP_ACK,
                            src_ip=src_ip, dst_ip=dst_ip)
    ip = _build_ip_header(src_ip, dst_ip, len(tcp))
    packets.append(ip + tcp)

    # FIN from client
    tcp = _build_tcp_header(sport, dport, client_seq, server_seq, TCP_FIN_ACK,
                            src_ip=src_ip, dst_ip=dst_ip)
    ip = _build_ip_header(src_ip, dst_ip, len(tcp))
    packets.append(ip + tcp)

    return packets


def _write_pcap(packets: list, output_path: str):
    """Write raw IP packets to a pcap file (linktype RAW_IP)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1e6)

    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack("<IHHiIII",
                            PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
                            0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE_RAW_IP))

        for i, pkt in enumerate(packets):
            pkt_ts = ts_sec + i
            # Packet header
            f.write(struct.pack("<IIII", pkt_ts, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)


def generate_attack_pcap(http_req: dict, output_path: str,
                         sport: int = 12345) -> str:
    """Generate a pcap file containing the attack HTTP request."""
    http_payload = _build_http_payload(http_req)
    packets = _build_tcp_stream(http_payload, sport=sport)
    _write_pcap(packets, output_path)
    logger.info("Attack pcap written: %s (%d bytes payload)", output_path, len(http_payload))
    return output_path


def _extract_params_from_path(path: str) -> tuple:
    """Split path into base path and params dict."""
    if "?" in path:
        base, query = path.split("?", 1)
        params = {}
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v
            else:
                params[part] = ""
        return base, params
    return path, {}


def generate_variant_pcaps(http_req: dict, output_dir: str,
                           case_id: str) -> list:
    """Generate variant attack pcaps for robustness testing.

    Variants:
    1. URL-encoded parameters
    2. Reordered query parameters
    3. Different path traversal depths (if applicable)
    """
    out = Path(output_dir) / case_id
    out.mkdir(parents=True, exist_ok=True)
    generated = []

    base_path, path_params = _extract_params_from_path(http_req.get("path", "/"))
    effective_params = http_req.get("params", {})
    if path_params and not effective_params:
        effective_params = path_params

    # Variant 1: URL-encode parameter values. Decode first (unquote) so values that
    # are ALREADY percent-encoded in the source (e.g. nuclei XSS payloads carrying
    # %3C literals) are encoded once, not double-encoded into %253C — which no rule
    # can match and which makes the variant an unfaithful re-rendering of the attack.
    # No-op for un-encoded values (benchmark traces), so benchmark variant-DR is unchanged.
    if effective_params:
        encoded_params = {
            k: quote(unquote(str(v)), safe="") for k, v in effective_params.items()
        }
        encoded_req = dict(http_req)
        encoded_req["path"] = base_path
        encoded_req["params"] = encoded_params
        path = str(out / "variant_urlencoded.pcap")
        generate_attack_pcap(encoded_req, path, sport=12346)
        generated.append({"type": "urlencoded", "path": path})

    # Variant 2: Reverse parameter order. Decode values first (same double-encoding
    # fix as Variant 1) so the reorder is a faithful permutation of the same attack
    # rather than a re-encoded one.
    if effective_params and len(effective_params) > 1:
        items = [(k, unquote(str(v))) for k, v in effective_params.items()]
        items.reverse()
        reordered_req = dict(http_req)
        reordered_req["path"] = base_path
        reordered_req["params"] = dict(items)
        path = str(out / "variant_reordered.pcap")
        generate_attack_pcap(reordered_req, path, sport=12347)
        generated.append({"type": "reordered", "path": path})

    # Variant 3: Extra traversal depth (for PT attacks)
    req_path = http_req.get("path", "")
    if "../" in req_path:
        deeper_req = dict(http_req)
        deeper_req["path"] = "/../.." + req_path
        path = str(out / "variant_deeper_traversal.pcap")
        generate_attack_pcap(deeper_req, path, sport=12348)
        generated.append({"type": "deeper_traversal", "path": path})

    # Variant 4: URL-encoded path traversal. Percent-encode each "../" in the path
    # to "%2e%2e%2f". The deployed rule matches the literal raw path on
    # http.uri.raw, so the same attack in this alternate spelling evades a
    # byte-exact content match. Sent raw on the wire (http.uri.raw = /%2e%2e%2f...).
    # NEW robustness metric — see docs/spec-encoded-traversal-preregistration.md;
    # NOT part of the original variant set. Generated only for path-traversal cases.
    if "../" in req_path:
        enc_req = dict(http_req)
        enc_req["path"] = req_path.replace("../", "%2e%2e%2f")
        path = str(out / "variant_encoded_traversal.pcap")
        generate_attack_pcap(enc_req, path, sport=12349)
        generated.append({"type": "encoded_traversal", "path": path})

    # Variant 5: payload substitution within the same mechanism class. Replace the
    # attack value with a DIFFERENT instance of the same class while keeping the
    # mechanism trigger the rule's pcre matches (shell ;cat /etc/passwd;->;id;,
    # sql union select 1,2->union select 9,8,7, template {{7*7}}->{{9*9}}). A
    # literal-content rule keyed to the observed payload fails here; a mechanism-pcre
    # rule (GENERALIZE_MECH) still fires. This is the direct test of class-level
    # generalisation -- the metric that separates "memorised the instance" from
    # "catches the class". NOT part of the original variant set (post-hoc, see
    # docs/spec-mechanism-generalization-preregistration.md). path_traversal is
    # already covered by the deeper/encoded variants, so it is not re-substituted.
    def _alt_payload(value: str):
        s = str(value)
        low = s.lower()
        if "../" in s or "%2e%2e" in low:
            return None  # covered by deeper_traversal / encoded_traversal
        if re.search(r"\b(union|select)\b", low):
            return "union select 9,8,7 from dual"
        if "{{" in s and "}}" in s:
            return "{{9*9}}"
        if any(m in s for m in (";", "|", "`", "$(")):
            return ";id;"
        return None

    subst_params = {}
    subst_hit = False
    for k, v in effective_params.items():
        nv = _alt_payload(v)
        subst_params[k] = nv if nv is not None else v
        subst_hit = subst_hit or (nv is not None and nv != str(v))

    body = http_req.get("body")
    subst_body = body
    if isinstance(body, str) and body:
        # body like "cmd=;cat /etc/passwd;": substitute each param value in place.
        def _sub(m):
            alt = _alt_payload(m.group(1))
            return "=" + alt if alt is not None else m.group(0)
        nb = re.sub(r"=([^&]*)", _sub, body)
        if nb != body:
            subst_body = nb
            subst_hit = True

    if subst_hit:
        subst_req = dict(http_req)
        subst_req["path"] = base_path
        subst_req["params"] = subst_params
        if subst_body is not body:
            subst_req["body"] = subst_body
        path = str(out / "variant_payload_substitution.pcap")
        generate_attack_pcap(subst_req, path, sport=12350)
        generated.append({"type": "payload_substitution", "path": path})

    return generated


def generate_benign_pcap(http_req: dict, output_path: str,
                         sport: int = 23456,
                         vuln_class: str = None) -> str:
    """Generate a benign pcap for the same endpoint with safe parameters.

    For InfoLeak/AuthBypass (no payload injection), generates a request
    to a different endpoint since the attack IS the URL access itself.
    """
    base_path = http_req.get("path", "/").split("?")[0]

    has_injection = bool(http_req.get("params") or http_req.get("body")
                         or "../" in http_req.get("path", ""))

    if vuln_class in ("InfoLeak", "AuthBypass") or not has_injection:
        benign_req = {
            "method": "GET",
            "path": "/index.html",
            "headers": {},
            "params": {},
            "body": None,
        }
    else:
        benign_req = {
            "method": http_req.get("method", "GET"),
            "path": base_path,
            "headers": {},
            "params": {},
            "body": None,
        }

        safe_path = benign_req["path"]
        while "../" in safe_path:
            safe_path = safe_path.replace("../", "")
        if not safe_path.startswith("/"):
            safe_path = "/" + safe_path
        benign_req["path"] = safe_path

        if http_req.get("params"):
            for k in http_req["params"]:
                benign_req["params"][k] = _safe_benign_value(k)

        if http_req.get("body"):
            if isinstance(http_req["body"], dict):
                benign_req["body"] = {
                    k: _safe_benign_value(k) for k in http_req["body"]
                }
            else:
                benign_req["body"] = "message=hello"

    http_payload = _build_http_payload(benign_req)
    packets = _build_tcp_stream(http_payload, sport=sport)
    _write_pcap(packets, output_path)
    logger.info("Benign pcap written: %s", output_path)
    return output_path


def _safe_benign_value(name: str) -> str:
    """Return endpoint-preserving but attack-neutral values for benign PCAPs."""
    key = str(name).lower()
    if any(token in key for token in ("ip", "addr", "host", "server", "gateway")):
        return "192.168.1.1"
    if any(token in key for token in ("port", "id", "num", "count", "size", "index")):
        return "1"
    if any(token in key for token in ("path", "file", "dir", "folder", "url")):
        return "/tmp/test.txt"
    if any(token in key for token in ("user", "name", "login")):
        return "admin"
    if "pass" in key:
        return "admin123"
    return "hello"


def generate_common_benign_pcaps(output_dir: str) -> list:
    """Generate common IoT benign traffic patterns."""
    out = Path(output_dir) / "common_benign"
    out.mkdir(parents=True, exist_ok=True)
    generated = []

    common_requests = [
        {"method": "GET", "path": "/", "params": {}, "headers": {}, "body": None},
        {"method": "GET", "path": "/index.html", "params": {}, "headers": {}, "body": None},
        {"method": "GET", "path": "/status", "params": {}, "headers": {}, "body": None},
        {"method": "GET", "path": "/api/status", "params": {}, "headers": {}, "body": None},
        {"method": "GET", "path": "/favicon.ico", "params": {}, "headers": {}, "body": None},
        {"method": "POST", "path": "/login", "params": {},
         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "body": "username=admin&password=admin123"},
        {"method": "GET", "path": "/cgi-bin/status.cgi", "params": {}, "headers": {}, "body": None},
        {"method": "GET", "path": "/firmware/check", "params": {"version": "1.0.0"},
         "headers": {}, "body": None},
    ]

    for i, req in enumerate(common_requests):
        path = str(out / f"benign_{i:02d}.pcap")
        generate_attack_pcap(req, path, sport=30000 + i)
        generated.append({"type": "common_benign", "path": path,
                          "request": f"{req['method']} {req['path']}"})

    return generated
