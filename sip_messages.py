"""Helpers to build and read SIP messages (shared by the fuzzer and bob).

A SIP message is plain text: a first line, then headers ("Name: value"),
then an empty line. This file turns Python values into that text and back,
and computes digest authentication (the username/password check SIP uses).
"""

import hashlib
import os
import re
import uuid

# Where requests are sent. On your PC this is Kamailio's port published by
# Docker; inside the bob container it is Kamailio's container address.
TARGET_HOST = os.environ.get("SF_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("SF_TARGET_PORT", "5060"))
# Our own address, written into Via and Contact headers.
LOCAL_HOST = os.environ.get("SF_LOCAL_HOST", "127.0.0.1")

DOMAIN = "statefuzz.local"
# Must match route[PASSWD] in docker/kamailio.cfg.
USERS = {"alice": "alice-secret", "bob": "bob-secret"}

# Short header names some SIP servers use, and their full names.
COMPACT = {"v": "Via", "f": "From", "t": "To", "i": "Call-ID", "m": "Contact",
           "l": "Content-Length", "c": "Content-Type"}
CANONICAL = {name.lower(): name for name in (
    "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Record-Route", "Route",
    "Content-Length", "Content-Type", "WWW-Authenticate", "Proxy-Authenticate",
    "Authorization", "Proxy-Authorization", "Expires", "Max-Forwards")}


def new_id():
    """A short random id, used for Call-IDs, tags and branches."""
    return uuid.uuid4().hex[:10]


def new_branch():
    return "z9hG4bK" + new_id()


def build_request(method, request_uri, *, call_id, cseq, from_user, from_tag,
                  to_user, local_port, to_tag=None, branch=None, routes=(),
                  contact=None, extra_headers=(), cseq_method=None):
    """Build a SIP request such as REGISTER, INVITE, ACK or BYE."""
    to_header = f"<sip:{to_user}@{DOMAIN}>" + (f";tag={to_tag}" if to_tag else "")
    lines = [
        f"{method} {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {LOCAL_HOST}:{local_port};branch={branch or new_branch()};rport",
        "Max-Forwards: 70",
    ]
    lines += [f"Route: {route}" for route in routes]
    lines += [
        f"From: <sip:{from_user}@{DOMAIN}>;tag={from_tag}",
        f"To: {to_header}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {cseq_method or method}",
        f"Contact: {contact or f'<sip:{from_user}@{LOCAL_HOST}:{local_port}>'}",
        "User-Agent: StateFuzz-demo",
    ]
    lines += list(extra_headers)
    lines.append("Content-Length: 0")
    return "\r\n".join(lines) + "\r\n\r\n"


def build_response(request, code, reason, to_tag=None, extra_headers=()):
    """Build a reply to a request, copying the headers SIP requires.

    Every Via is copied in order: when Kamailio forwards a request it adds
    its own Via, and the reply must carry all of them to find its way back.
    """
    lines = [f"SIP/2.0 {code} {reason}"]
    for value in values(request, "Via"):
        lines.append(f"Via: {value}")
    for value in values(request, "Record-Route"):
        lines.append(f"Record-Route: {value}")
    to_value = header(request, "To")
    if to_tag and "tag=" not in to_value:
        to_value += f";tag={to_tag}"
    lines += [
        f"From: {header(request, 'From')}",
        f"To: {to_value}",
        f"Call-ID: {header(request, 'Call-ID')}",
        f"CSeq: {header(request, 'CSeq')}",
    ]
    lines += list(extra_headers)
    lines.append("Content-Length: 0")
    return "\r\n".join(lines) + "\r\n\r\n"


def parse(text):
    """Read a SIP message into a dict: first line, method or code, headers."""
    head = text.split("\r\n\r\n", 1)[0]
    first, *header_lines = head.split("\r\n")
    all_headers = []
    for line in header_lines:
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            name = COMPACT.get(name, CANONICAL.get(name.lower(), name))
            all_headers.append((name, value.strip()))
    message = {"first_line": first, "all": all_headers,
               "headers": {}, "method": None, "code": None, "uri": None}
    for name, value in all_headers:
        message["headers"].setdefault(name, value)  # first value of each
    parts = first.split()
    if first.startswith("SIP/2.0") and len(parts) > 1 and parts[1].isdigit():
        message["code"] = int(parts[1])
    elif parts:
        message["method"] = parts[0]
        message["uri"] = parts[1] if len(parts) > 1 else None
    return message


def header(message, name):
    """First value of a header, or ''."""
    return message["headers"].get(name, "")


def values(message, name):
    """All values of a header, in order (headers may repeat or hold lists)."""
    result = []
    for header_name, value in message["all"]:
        if header_name == name:
            # "<a>, <b>" in one header line is two values
            result += [v.strip() for v in re.split(r",(?=\s*<)", value)]
    return result


def tag_of(header_value):
    """Return the tag in a From/To header, or None."""
    match = re.search(r";\s*tag=([^;>\s]+)", header_value)
    return match.group(1) if match else None


def uri_in(header_value):
    """The URI inside <...> of a Contact header (or the bare value)."""
    match = re.search(r"<([^>]+)>", header_value)
    return match.group(1) if match else header_value.split(";")[0].strip()


def reason_of(message):
    """'401 Unauthorized' from 'SIP/2.0 401 Unauthorized'."""
    return message["first_line"][8:]


# ---------- digest authentication (RFC 2617 / RFC 3261) ----------

def _md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def parse_challenge(value):
    """Read 'Digest realm="x", nonce="y", qop="auth"' into a dict."""
    params = {}
    for key, quoted, plain in re.findall(r'(\w+)\s*=\s*(?:"([^"]*)"|([^\s,]+))', value):
        params[key.lower()] = quoted if quoted else plain
    return params


def digest_credentials(challenge_value, method, uri, username, password):
    """The value of an Authorization / Proxy-Authorization header."""
    c = parse_challenge(challenge_value)
    realm, nonce = c.get("realm", ""), c.get("nonce", "")
    ha1 = _md5(f"{username}:{realm}:{password}")
    ha2 = _md5(f"{method}:{uri}")
    fields = [f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"',
              f'uri="{uri}"']
    qops = [q.strip() for q in c.get("qop", "").split(",") if q.strip()]
    if "auth" in qops:
        nc, cnonce = "00000001", new_id()
        response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        fields += [f'response="{response}"', "algorithm=MD5", "qop=auth",
                   f"nc={nc}", f'cnonce="{cnonce}"']
    else:
        response = _md5(f"{ha1}:{nonce}:{ha2}")
        fields += [f'response="{response}"', "algorithm=MD5"]
    if "opaque" in c:
        fields.append(f'opaque="{c["opaque"]}"')
    return "Digest " + ", ".join(fields)
