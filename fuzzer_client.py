"""Piece 2: the fuzzer client (the sender), acting as the user "alice".

It sends a *sequence* of SIP messages to Kamailio and records every reply.
When Kamailio asks for a password (401 / 407 challenge) the client answers
the challenge the way each test says: correctly, with a wrong password,
with alice's password while claiming to be bob, or not at all.

Sequences:
  normal_call              INVITE -> ACK -> BYE, a real call to bob
  bye_without_call         BYE for a call that was never started (made-up To tag)
  register_no_credentials  REGISTER, and do not answer the challenge
  register_wrong_password  REGISTER, answer the challenge with a wrong password
  register_as_other_user   REGISTER bob's address using alice's own password

Run:  python fuzzer_client.py
"""

import socket

from sip_messages import (DOMAIN, TARGET_HOST, TARGET_PORT, USERS, build_request,
                          digest_credentials, header, new_branch, new_id, parse,
                          reason_of, tag_of, uri_in, values)

ME = "alice"
REPLY_TIMEOUT = 3.0  # seconds to wait for a final reply

# auth: how to answer a password challenge
#   "valid"  - correctly            "none"  - do not answer it
#   "wrong"  - with a wrong password
#   "own"    - with alice's own (valid) password, for someone else's address
SEQUENCES = {
    "normal_call": {
        "situation": "call_up", "to": "bob",
        "steps": [{"method": "INVITE", "auth": "valid"}, {"method": "ACK"},
                  {"method": "BYE"}],
    },
    # "forge": the BYE carries a To tag (call identity) that no server ever
    # issued, like a hang-up for a call that never started. A BYE inside a
    # call is never challenged for a password, so no "auth" is needed.
    "bye_without_call": {
        "situation": "no_call", "to": "bob",
        "steps": [{"method": "BYE", "forge": True}],
    },
    "register_no_credentials": {
        "situation": "no_credentials", "to": ME,
        "steps": [{"method": "REGISTER", "auth": "none"}],
    },
    "register_wrong_password": {
        "situation": "wrong_password", "to": ME,
        "steps": [{"method": "REGISTER", "auth": "wrong"}],
    },
    "register_as_other_user": {
        "situation": "other_user", "to": "bob",
        "steps": [{"method": "REGISTER", "auth": "own"}],
    },
}


class Session:
    """One test run: one socket, one Call-ID, and the dialog it builds."""

    def __init__(self, to_user, me=ME, password=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))  # any free door for the client
        self.sock.settimeout(REPLY_TIMEOUT)
        self.port = self.sock.getsockname()[1]
        self.to_user = to_user
        self.me = me                              # who the client claims to be
        self.password = password or USERS.get(me)
        self.expires = 10                         # REGISTER lifetime in seconds
        self.call_id = f"{new_id()}@statefuzz"  # a fresh call every run
        self.from_tag = new_id()
        self.cseq = 0
        # Dialog state, filled in by the 200 OK to INVITE.
        self.to_tag = None
        self.remote_target = None   # bob's Contact URI
        self.route_set = []         # Kamailio's Record-Route, as Route headers
        self.last_invite_cseq = None

    # ---- sending ----

    def request(self, method, auth_header=None, branch=None, cseq=None):
        if method == "REGISTER":
            uri = f"sip:{DOMAIN}"
        elif self.remote_target and method in ("ACK", "BYE"):
            uri = self.remote_target
        else:
            uri = f"sip:{self.to_user}@{DOMAIN}"
        in_dialog = method in ("ACK", "BYE") and self.to_tag is not None
        extra = [auth_header] if auth_header else []
        if method == "REGISTER":
            extra.append(f"Expires: {self.expires}")
        text = build_request(
            method, uri, call_id=self.call_id, cseq=cseq or self.cseq,
            from_user=self.me if method != "REGISTER" else self.to_user,
            from_tag=self.from_tag, to_user=self.to_user, local_port=self.port,
            to_tag=self.to_tag if in_dialog else None, branch=branch,
            routes=self.route_set if in_dialog else (), extra_headers=extra)
        return uri, text

    def send(self, text):
        self.sock.sendto(text.encode(), (TARGET_HOST, TARGET_PORT))

    def receive_replies(self):
        """Collect replies until a final one (code >= 200) or a timeout."""
        replies = []
        while True:
            try:
                data, _ = self.sock.recvfrom(65535)
            except (socket.timeout, ConnectionResetError):
                return replies
            reply = parse(data.decode(errors="replace"))
            if reply["code"] is None or header(reply, "Call-ID") != self.call_id:
                continue  # not a reply to us
            replies.append(reply)
            if reply["code"] >= 200:
                return replies

    def ack_failed_invite(self, branch, cseq, reply):
        """SIP requires an ACK for a failed INVITE (same branch, To tag)."""
        to_tag = tag_of(header(reply, "To"))
        uri = f"sip:{self.to_user}@{DOMAIN}"
        text = build_request("ACK", uri, call_id=self.call_id, cseq=cseq,
                             from_user=self.me, from_tag=self.from_tag,
                             to_user=self.to_user, to_tag=to_tag,
                             local_port=self.port, branch=branch)
        self.send(text)

    # ---- one step of a sequence ----

    def run_step(self, step):
        method = step["method"]
        auth = step.get("auth", "none")
        shown = []  # what to print for this step

        if method == "ACK":
            # ACK for the 2xx: same CSeq number as the INVITE, no reply.
            _, text = self.request("ACK", cseq=self.last_invite_cseq)
            self.send(text)
            return {"sent": "ACK", "replies": [], "codes": []}

        if step.get("forge") and self.to_tag is None:
            self.to_tag = new_id()  # a call identity nobody ever created

        self.cseq += 1
        branch = new_branch()
        uri, text = self.request(method, branch=branch)
        self.send(text)
        replies = self.receive_replies()
        final = replies[-1] if replies else None

        if final and final["code"] in (401, 407) and auth != "none":
            shown.append(f"{reason_of(final)} (challenge)")
            if method == "INVITE":
                self.ack_failed_invite(branch, self.cseq, final)
            challenge = header(final, "WWW-Authenticate" if final["code"] == 401
                               else "Proxy-Authenticate")
            password = "not-the-password" if auth == "wrong" else self.password
            credentials = digest_credentials(challenge, method, uri, self.me, password)
            auth_name = "Authorization" if final["code"] == 401 else "Proxy-Authorization"
            self.cseq += 1
            branch = new_branch()
            _, text = self.request(method, f"{auth_name}: {credentials}", branch=branch)
            self.send(text)
            replies = self.receive_replies()
            final = replies[-1] if replies else None

        if method == "INVITE":
            self.last_invite_cseq = self.cseq
            if final and 200 <= final["code"] < 300:
                self.to_tag = tag_of(header(final, "To"))
                self.remote_target = uri_in(header(final, "Contact"))
                self.route_set = list(reversed(values(final, "Record-Route")))
            elif final:
                self.ack_failed_invite(branch, self.cseq, final)

        shown += [reason_of(r) for r in replies]
        return {"sent": method, "replies": shown, "codes": [r["code"] for r in replies]}


def run_sequence(name):
    """Send one sequence and return a trace: what was sent and what came back."""
    spec = SEQUENCES[name]
    session = Session(spec["to"])
    trace = {"sequence": name, "situation": spec["situation"],
             "call_id": session.call_id, "steps": [], "error": None}
    try:
        for step in spec["steps"]:
            if step["method"] in ("ACK", "BYE") and spec["situation"] == "call_up" \
                    and session.to_tag is None:
                trace["error"] = "the call could not be set up, so ACK/BYE were not sent"
                break
            trace["steps"].append(session.run_step(step))
        # A test that only checks the INVITE still hangs up a call it set up.
        if session.to_tag and "BYE" not in [s["sent"] for s in trace["steps"]]:
            session.run_step({"method": "ACK"})
            session.run_step({"method": "BYE"})
        # An accepted REGISTER (e.g. a hijack in buggy mode) is removed again
        # (Expires: 0). Left in place, Kamailio would also send the next run's
        # requests for that user to this test's closed port and answer late.
        for step, spec_step in zip(trace["steps"], spec["steps"]):
            if step["sent"] == "REGISTER" and step["codes"] and 200 <= step["codes"][-1] < 300:
                session.expires = 0
                session.run_step(spec_step)
    finally:
        session.sock.close()
    return trace


def target_is_up():
    """Send one OPTIONS and see whether anything answers."""
    session = Session("bob")
    session.sock.settimeout(2.0)
    try:
        session.cseq = 1
        _, text = session.request("OPTIONS")
        session.send(text)
        return bool(session.receive_replies())
    finally:
        session.sock.close()


if __name__ == "__main__":
    if not target_is_up():
        print(f"No reply from {TARGET_HOST}:{TARGET_PORT}. Is Kamailio running? "
              "(docker compose up -d)")
        raise SystemExit(1)
    for seq in SEQUENCES:
        result = run_sequence(seq)
        print(f"\n== {seq} ==")
        for step in result["steps"]:
            print(f"  sent {step['sent']:<9} got: {', '.join(step['replies']) or '(no reply)'}")
        if result["error"]:
            print(f"  !! {result['error']}")
