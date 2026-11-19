"""Turn the downloaded datasets into sequences our fuzzer can send.

    python datasets/importer.py        (after fetch_datasets.py)

Output: datasets/seeds.json
  seeds     whole sequences (the message ORDER), from
              builtin       the 2 normal sequences of learning_fuzzer.py
              profuzzbench  the recorded Kamailio flow (sip-1.raw)
              sipp          the client side of each SIPp scenario
  variants  message FORMAT styles from RFC 4475 section 3.1.1 (valid but
            unusual messages); the mutator can apply one to any sequence

Adapting a flow to our setup:
  * users and domain are ours: a REGISTER is for alice (the fuzzer), a call
    goes to bob, everything in statefuzz.local
  * our client answers a password challenge by itself, so a SIPp
    "REGISTER, 401, REGISTER with credentials" becomes one REGISTER(valid);
    our Kamailio asks for a password, so every REGISTER/INVITE is "valid"
  * only methods our client and rules use are kept (INVITE, ACK, BYE,
    REGISTER); e.g. PRACK and NOTIFY are skipped and reported
"""

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
OUT = os.path.join(HERE, "seeds.json")

KEEP = ("INVITE", "ACK", "BYE", "REGISTER")
REQUEST_LINE = re.compile(r"^\s*([A-Z]+) \S+ SIP/2\.0\s*$", re.M)

# RFC 4475 3.1.1 sections our client can reproduce on its own messages.
VARIANTS = [  # (section, our variant)
    ("3.1.1.1", "compact_headers"),      # A Short Tortuous INVITE uses v:, f:, t:, i:, m:
    ("3.1.1.1", "unknown_header"),       # ... and an unknown header (NewFangledHeader)
    ("3.1.1.6", "no_lws_display_name"),  # No LWS between Display Name and <
    ("3.1.1.7", "long_values"),          # Long Values in Header Fields
    ("3.1.1.8", "trailing_octets"),      # Extra Trailing Octets in a UDP Datagram
]


def adapt(methods):
    """Method list -> our steps: keep known methods, merge challenge retries."""
    steps, skipped = [], []
    for m in methods:
        if m not in KEEP:
            skipped.append(m)
            continue
        if m == "REGISTER" and steps and steps[-1]["method"] == "REGISTER":
            continue  # the retry with credentials: our client does this itself
        step = {"method": m, "to": "alice" if m == "REGISTER" else "bob"}
        if m in ("INVITE", "REGISTER"):
            step["auth"] = "valid"
        steps.append(step)
    return steps, skipped


def from_profuzzbench():
    path = os.path.join(RAW, "profuzzbench", "sip-1.raw")
    with open(path, errors="replace") as f:
        methods = REQUEST_LINE.findall(f.read())
    steps, skipped = adapt(methods)
    return [{"id": "pfb_sip-1", "source": "profuzzbench", "file": "sip-1.raw",
             "original": methods, "skipped": skipped, "steps": steps}]


def from_sipp():
    seeds = []
    folder = os.path.join(RAW, "sipp")
    for name in sorted(os.listdir(folder)):
        with open(os.path.join(folder, name), errors="replace") as f:
            xml = f.read()
        received = re.findall(r'<recv\s+request="([A-Z]+)"', xml)
        if received:  # a server scenario: the client's messages are what it receives
            methods = received
        else:         # a client scenario: the requests it sends
            methods = [REQUEST_LINE.search(body).group(1)
                       for body in re.findall(r"<send[^>]*>(.*?)</send>", xml, re.S)
                       if REQUEST_LINE.search(body)]
        steps, skipped = adapt(methods)
        if steps:
            seeds.append({"id": f"sipp_{name[:-4]}", "source": "sipp", "file": name,
                          "original": methods, "skipped": skipped, "steps": steps})
    return seeds


def from_rfc4475():
    with open(os.path.join(RAW, "rfc4475", "rfc4475.txt"), errors="replace") as f:
        text = f.read()
    titles = dict(re.findall(r"^(3\.1\.[12]\.\d+)\.\s+(.+?)\s*$", text, re.M))
    variants = [{"id": vid, "rfc_section": sec, "title": titles[sec]}
                for sec, vid in VARIANTS if sec in titles]
    return variants, len(titles)


def main():
    builtin = [
        {"id": "builtin_call", "source": "builtin", "steps": [
            {"method": "INVITE", "auth": "valid", "to": "bob"},
            {"method": "ACK", "to": "bob"}, {"method": "BYE", "to": "bob"}]},
        {"id": "builtin_register", "source": "builtin", "steps": [
            {"method": "REGISTER", "auth": "valid", "to": "alice"}]},
    ]
    imported = from_profuzzbench() + from_sipp()
    # Same message order from the same source = one seed (e.g. two SIPp
    # REGISTER scenarios); the other files are listed in "also".
    seeds, seen = list(builtin), {}
    for seed in imported:
        key = (seed["source"], json.dumps(seed["steps"]))
        if key in seen:
            seen[key].setdefault("also", []).append(seed["file"])
        else:
            seen[key] = seed
            seeds.append(seed)
    variants, n_sections = from_rfc4475()

    with open(OUT, "w") as f:
        json.dump({"seeds": seeds, "variants": variants}, f, indent=2)

    print("Sequences (message order):")
    for s in seeds:
        order = " > ".join(st["method"] for st in s["steps"])
        extra = f"   skipped: {', '.join(s['skipped'])}" if s.get("skipped") else ""
        also = f"   (same as: {', '.join(s['also'])})" if s.get("also") else ""
        print(f"  {s['id']:<28} {s['source']:<13} {order}{extra}{also}")
    print(f"\nFormat variants from RFC 4475 ({len(variants)} of its {n_sections} test sections):")
    for v in variants:
        print(f"  {v['id']:<20} RFC 4475 {v['rfc_section']:<9} {v['title']}")
    print(f"\nWritten: {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
