"""Piece 3: the rule checker (the judge).

A crash-only fuzzer only asks "did the server crash?". This checker asks
"did the server break a security rule?" and returns PASS or VIOLATION.

The rules are NOT written in this file. They live in rules.json, so a new
rule is one new entry there and no new Python.

Each rule in rules.json has:
  id       short name, e.g. "R1"
  applies  the situation it is about (see SITUATIONS below); each sequence
           in fuzzer_client.py says which situation it creates
  method   the request it checks, e.g. "BYE"
  expect   which reply codes are correct:
             [200]      exactly these codes (a list: [401, 407] also works)
             "2xx"      any code in that class
             "!2xx"     any code that is NOT in that class
  text     the rule in plain words

The checked reply is the final one, after any password challenge the test
answered. A missing reply (timeout) is always a VIOLATION.

Run:  python rule_checker.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(HERE, "rules.json")
MODE_FILE = os.path.join(HERE, "server_mode.txt")

# Words used in the result line for each situation.
SITUATIONS = {
    "no_call": "with no call",
    "call_up": "for a real call",
    "no_credentials": "without credentials",
    "wrong_password": "with a wrong password",
    "other_user": "for another user's address",
}


def load_rules(path=RULES_FILE):
    """Read rules.json and stop early with a clear message if a rule is wrong."""
    with open(path) as f:
        rules = json.load(f)
    for rule in rules:
        missing = [k for k in ("id", "applies", "method", "expect", "text") if k not in rule]
        if missing:
            raise ValueError(f"Rule {rule.get('id', '?')} is missing: {', '.join(missing)}")
        if rule["applies"] not in SITUATIONS:
            raise ValueError(f"Rule {rule['id']}: unknown situation '{rule['applies']}'")
    return rules


RULES = load_rules()


def code_matches(code, expect):
    """Is this reply code one of the expected ones?"""
    if code is None:
        return False  # no reply at all is never acceptable
    if isinstance(expect, list):
        return code in expect
    negate = expect.startswith("!")
    wanted = int(expect.lstrip("!")[0])  # "2xx" -> 2
    return (code // 100 == wanted) != negate


def situation_of(trace):
    """The situation the sequence created (older traces: guess from the steps)."""
    if trace.get("situation"):
        return trace["situation"]
    sent = [step["sent"] for step in trace["steps"]]
    return "call_up" if "INVITE" in sent and "ACK" in sent else "no_call"


def check(trace):
    """Return a list of findings, one per rule that applies to this trace."""
    situation = situation_of(trace)
    findings = []
    for step in trace["steps"]:
        final = step["codes"][-1] if step["codes"] else None
        for rule in RULES:
            if rule["method"] != step["sent"] or rule["applies"] != situation:
                continue
            ok = code_matches(final, rule["expect"])
            findings.append({
                "rule": rule["id"],
                "result": "PASS" if ok else "VIOLATION",
                "detail": f"{step['sent']} {SITUATIONS[situation]} got {final or 'no reply'}",
                "text": rule["text"],
            })
    return findings


def current_mode():
    try:
        with open(MODE_FILE) as f:
            return f.read().strip() or "normal"
    except FileNotFoundError:
        return "normal"


if __name__ == "__main__":
    from fuzzer_client import SEQUENCES, run_sequence, target_is_up
    from sip_messages import TARGET_HOST, TARGET_PORT

    print(f"Target: Kamailio at {TARGET_HOST}:{TARGET_PORT}  (mode: {current_mode()})\n")
    if not target_is_up():
        print("No reply. Is Kamailio running?  ->  docker compose up -d")
        raise SystemExit(1)

    counts = {"PASS": 0, "VIOLATION": 0}
    for seq in SEQUENCES:
        trace = run_sequence(seq)
        if trace["error"]:
            print(f"{seq:<25} --  ERROR      {trace['error']}")
        for f in check(trace):
            counts[f["result"]] += 1
            print(f"{seq:<25} {f['rule']}  {f['result']:<9}  {f['detail']}")
            if f["result"] == "VIOLATION":
                print(f"{'':<25}     broken rule: {f['text']}")
    print(f"\n{counts['PASS']} PASS, {counts['VIOLATION']} VIOLATION")
