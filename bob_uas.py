"""The test phone "bob" (runs in its own Docker container next to Kamailio).

bob is NOT the target. He exists so that a call INVITE -> ACK -> BYE really
travels through Kamailio, the way it would between two phones:

    fuzzer (alice) --> Kamailio --> bob
                   <--          <--

What bob does:
  * registers with Kamailio every few seconds (with his password), so
    Kamailio knows where to send calls for bob@statefuzz.local
  * answers INVITE with 100 Trying, 180 Ringing, 200 OK
  * answers BYE with 200 OK for a call he knows, 481 for one he does not

Started by docker compose; you do not run this file yourself.
"""

import socket
import threading
import time

from sip_messages import (DOMAIN, LOCAL_HOST, TARGET_HOST, TARGET_PORT, USERS,
                          build_request, build_response, digest_credentials,
                          header, new_id, parse)

ME = "bob"
CALL_PORT = 5070       # where calls arrive
REGISTER_PORT = 5071   # where bob's own REGISTER replies arrive
REGISTER_EVERY = 5     # seconds (Kamailio forgets bob when it restarts)


def register_forever():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", REGISTER_PORT))
    sock.settimeout(2.0)
    call_id, from_tag, cseq = f"{new_id()}@bob", new_id(), 0
    registered = None

    def send(auth=None):
        nonlocal cseq
        cseq += 1
        text = build_request(
            "REGISTER", f"sip:{DOMAIN}", call_id=call_id, cseq=cseq,
            from_user=ME, from_tag=from_tag, to_user=ME, local_port=REGISTER_PORT,
            contact=f"<sip:{ME}@{LOCAL_HOST}:{CALL_PORT}>",
            extra_headers=(["Expires: 60"] + ([auth] if auth else [])))
        sock.sendto(text.encode(), (TARGET_HOST, TARGET_PORT))
        while True:
            try:
                reply = parse(sock.recvfrom(65535)[0].decode(errors="replace"))
            except OSError:
                return None
            if reply["code"] and reply["code"] >= 200:
                return reply

    while True:
        reply = send()
        if reply and reply["code"] == 401:
            credentials = digest_credentials(header(reply, "WWW-Authenticate"),
                                             "REGISTER", f"sip:{DOMAIN}", ME, USERS[ME])
            reply = send(f"Authorization: {credentials}")
        ok = bool(reply and reply["code"] == 200)
        if ok != registered:
            state = "registered with" if ok else "could NOT register with"
            print(f"bob {state} Kamailio at {TARGET_HOST}:{TARGET_PORT}"
                  + ("" if ok else f" ({reply['first_line'] if reply else 'no reply'})"))
            registered = ok
        time.sleep(REGISTER_EVERY)


def answer_calls():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", CALL_PORT))
    calls = {}  # Call-ID -> bob's To tag
    contact = f"Contact: <sip:{ME}@{LOCAL_HOST}:{CALL_PORT}>"
    print(f"bob is answering calls on {LOCAL_HOST}:{CALL_PORT}")
    while True:
        data, sender = sock.recvfrom(65535)
        request = parse(data.decode(errors="replace"))
        method = request["method"]
        if method is None:
            continue
        call_id = header(request, "Call-ID")
        replies = []
        if method == "INVITE":
            tag = calls.setdefault(call_id, new_id())
            replies = [build_response(request, 100, "Trying"),
                       build_response(request, 180, "Ringing", tag, [contact]),
                       build_response(request, 200, "OK", tag, [contact])]
        elif method == "ACK":
            pass  # SIP never replies to ACK
        elif method == "BYE":
            if calls.pop(call_id, None):
                replies = [build_response(request, 200, "OK")]
            else:
                replies = [build_response(request, 481, "Call/Transaction Does Not Exist")]
        elif method in ("OPTIONS", "CANCEL"):
            replies = [build_response(request, 200, "OK")]
        else:
            replies = [build_response(request, 405, "Method Not Allowed")]
        for reply in replies:
            sock.sendto(reply.encode(), sender)
        print(f"bob got {method:<8} -> "
              f"{', '.join(r.split(chr(13))[0][8:] for r in replies) or '(no reply)'}")


if __name__ == "__main__":
    threading.Thread(target=register_forever, daemon=True).start()
    answer_calls()
