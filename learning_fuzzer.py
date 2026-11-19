"""Piece 7: the learning fuzzer, the StateFuzz loop in a small form.

rule_checker.py runs 5 fixed tests. This file shows the CORE IDEA of StateFuzz:
broken security rules are used as feedback to learn what to test next.

Each round:
  1. the LEARNER picks a kind of change (a "mutation")
  2. the MUTATOR applies it to a normal sequence, making a new one; the normal
     sequences come from public datasets (datasets/seeds.json: ProFuzzBench,
     SIPp, RFC 4475) plus our 2 built-in ones
  3. the sequence is sent to Kamailio (fuzzer_client.Session)
  4. every reply is judged with the same rules as rule_checker.py (rules.json)
  5. a NEW broken rule is replayed twice; it is "confirmed" if it repeats
  6. the learner is rewarded: 1 for a new violation, a little for a known one
  7. the round is saved to datasets/execution_runs.csv (the execution dataset)

The learner uses Thompson sampling: every mutation keeps a count of wins and
misses, and the one with the highest random draw from Beta(wins+1, misses+1)
is played. Mutations that broke rules are drawn high more often, the others
still get a chance.

Strategies (for comparison):
  random    pick mutations blindly (no feedback)
  thompson  Thompson sampling picks the mutation
  ranker    Thompson picks the mutation, the generator makes several candidate
            sequences, and a classifier trained on execution_runs.csv
            (ranker_model.py) picks the one most likely to break a rule

Everything is black-box: the facts used to judge (is there a call? which
password was sent? whose address?) come from what the fuzzer itself did and
the replies it got. Nothing is read from Kamailio's code, config or logs.

Run:  python learning_fuzzer.py                      30 rounds, StateFuzz (ranker)
      python learning_fuzzer.py --strategy random    no feedback
      python learning_fuzzer.py --rounds 300 --quiet collect data
      python learning_fuzzer.py --compare            StateFuzz vs random, 3 runs each
      python dashboard.py                            the same loop in a web page
"""

import argparse
import copy
import csv
import json
import os
import random
import re
import time

from fuzzer_client import ME, Session, target_is_up
from rule_checker import RULES, code_matches, current_mode
from sip_messages import new_id

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS_FILE = os.path.join(HERE, "datasets", "seeds.json")
RUNS_FILE = os.path.join(HERE, "datasets", "execution_runs.csv")
STRATEGIES = ("random", "thompson", "ranker")

BUILTIN = [
    {"id": "builtin_call", "source": "builtin", "steps": [
        {"method": "INVITE", "auth": "valid", "to": "bob"},
        {"method": "ACK", "to": "bob"}, {"method": "BYE", "to": "bob"}]},
    {"id": "builtin_register", "source": "builtin", "steps": [
        {"method": "REGISTER", "auth": "valid", "to": ME}]},
]


def load_seeds():
    """The normal sequences and RFC 4475 variants (built-in only if not imported)."""
    try:
        with open(SEEDS_FILE) as f:
            data = json.load(f)
        return data["seeds"], [v["id"] for v in data["variants"]]
    except (FileNotFoundError, KeyError, ValueError):
        return BUILTIN, []


SEED_POOL, VARIANTS = load_seeds()


def pick_seed(rng, need=None, min_steps=1):
    """A random normal sequence that contains the method `need`."""
    pool = [s for s in SEED_POOL if len(s["steps"]) >= min_steps
            and (need is None or any(st["method"] == need for st in s["steps"]))]
    seed = rng.choice(pool)
    return {"seed": seed["id"], "source": seed["source"], "variant": None,
            "steps": copy.deepcopy(seed["steps"])}


def first(spec, method):
    return next(i for i, st in enumerate(spec["steps"]) if st["method"] == method)


# ---------- 1-2. the mutations (one change each) ----------

def delete_step(rng):
    spec = pick_seed(rng, min_steps=2)
    del spec["steps"][rng.randrange(len(spec["steps"]))]
    return spec


def swap_steps(rng):
    spec = pick_seed(rng, min_steps=2)
    i = rng.randrange(len(spec["steps"]) - 1)
    spec["steps"][i], spec["steps"][i + 1] = spec["steps"][i + 1], spec["steps"][i]
    return spec


def duplicate_step(rng):
    """Repeat the ACK or the BYE."""
    spec = pick_seed(rng, need="BYE")
    i = rng.choice([i for i, st in enumerate(spec["steps"]) if st["method"] in ("ACK", "BYE")])
    spec["steps"].insert(i + 1, copy.deepcopy(spec["steps"][i]))
    return spec


def forge_bye(rng):
    """Hang up with a call identity the server never issued."""
    spec = pick_seed(rng, need="BYE")
    if rng.random() < 0.5:
        spec["steps"] = [{"method": "BYE", "forge": True, "to": "bob"}]
    else:
        last_bye = max(i for i, st in enumerate(spec["steps"]) if st["method"] == "BYE")
        spec["steps"][last_bye]["forge"] = True
    return spec


def change_password(rng):
    spec = pick_seed(rng, need="REGISTER")
    spec["steps"][first(spec, "REGISTER")]["auth"] = rng.choice(["wrong", "none"])
    return spec


def other_user(rng):
    """Register bob's address with alice's own password."""
    spec = pick_seed(rng, need="REGISTER")
    spec["steps"][first(spec, "REGISTER")]["to"] = "bob"
    return spec


def rfc_variant(rng):
    """Send a normal sequence in an unusual but valid RFC 4475 message style."""
    spec = pick_seed(rng)
    spec["variant"] = rng.choice(VARIANTS) if VARIANTS else None
    return spec


MUTATIONS = {f.__name__: f for f in (delete_step, swap_steps, duplicate_step, forge_bye,
                                     change_password, other_user, rfc_variant)}
if not VARIANTS:
    del MUTATIONS["rfc_variant"]


def describe(spec):
    """INVITE > ACK > BYE(forged), REGISTER(wrong pw) for bob, ..."""
    parts = []
    for step in spec["steps"]:
        tag = {"wrong": "(wrong pw)", "none": "(no pw)"}.get(step.get("auth"), "")
        text = step["method"] + ("(forged)" if step.get("forge") else tag)
        if step["method"] == "REGISTER" and step["to"] != ME:
            text += f" for {step['to']}"
        parts.append(text)
    return " > ".join(parts) + (f"  [{spec['variant']}]" if spec.get("variant") else "")


# ---------- RFC 4475 message styles ----------

COMPACT_FORMS = {"Via": "v", "From": "f", "To": "t", "Call-ID": "i", "Contact": "m",
                 "Content-Length": "l"}


def apply_variant(text, variant):
    if variant == "compact_headers":
        for name, short in COMPACT_FORMS.items():
            text = re.sub(rf"^{name}: ", f"{short}: ", text, flags=re.M)
    elif variant == "unknown_header":
        text = text.replace("Max-Forwards: 70\r\n", "Max-Forwards: 70\r\n"
                            "NewFangledHeader:   newfangled value\r\n continued newfangled value\r\n", 1)
    elif variant == "no_lws_display_name":
        text = re.sub(r"^From: <", 'From: "Alice"<', text, flags=re.M)
    elif variant == "long_values":
        text = text.replace("Max-Forwards: 70\r\n", "Max-Forwards: 70\r\nX-Long-Value: "
                            + "very" * 200 + "long\r\n", 1)
    elif variant == "trailing_octets":
        text += "0000000000000000"
    return text


class VariantSession(Session):
    def __init__(self, to_user, variant=None):
        super().__init__(to_user)
        self.variant = variant

    def send(self, text):
        super().send(apply_variant(text, self.variant))


# ---------- 3. send one sequence to Kamailio ----------

def situation(step, call):
    """Which rules.json situation this step is in (None: no rule applies)."""
    if step["method"] == "BYE":
        if step.get("forge") or call == "none":
            return "no_call"
        return "call_up" if call == "up" else None   # a BYE after the call ended
    if step["method"] == "REGISTER":
        if step.get("auth") == "none":
            return "no_credentials"
        if step.get("auth") == "wrong":
            return "wrong_password"
        return "other_user" if step["to"] != ME else None
    return None


def run(spec):
    """Send the sequence; return one result per step (sent, final code, situation, state)."""
    session = VariantSession(spec["steps"][0]["to"], spec.get("variant"))
    call, results = "none", []   # the call as the fuzzer sees it: none -> up -> ended
    try:
        for step in spec["steps"]:
            session.to_user = step["to"]
            where = situation(step, call)
            if step.get("forge"):
                # A made-up call identity, with no route into the real call.
                saved = (session.to_tag, session.remote_target, session.route_set)
                session.to_tag, session.remote_target, session.route_set = new_id(), None, []
                out = session.run_step({"method": "BYE"})
                session.to_tag, session.remote_target, session.route_set = saved
            else:
                out = session.run_step(step)
            final = out["codes"][-1] if out["codes"] else None
            if step["method"] == "INVITE" and session.to_tag:
                call = "up"
            if where == "call_up" and final == 200:
                call = "ended"
            results.append({"sent": step["method"], "final": final, "situation": where,
                            "state": call})
        # Leave Kamailio clean for the next round: hang up, and remove any
        # registration this round created (Expires: 0).
        if call == "up":
            session.to_user = "bob"
            session.run_step({"method": "ACK"})
            session.run_step({"method": "BYE"})
        for step, res in zip(spec["steps"], results):
            if res["sent"] == "REGISTER" and res["final"] and 200 <= res["final"] < 300:
                session.to_user = step["to"]
                session.expires = 0
                session.run_step(step)
    finally:
        session.sock.close()
    return results


# ---------- 4. judge with rules.json ----------

def judge(results):
    """The rules broken in this run: {rule id: (rule, code got)}."""
    broken = {}
    for res in results:
        for rule in RULES:
            if rule["method"] == res["sent"] and rule["applies"] == res["situation"] \
                    and not code_matches(res["final"], rule["expect"]):
                broken[rule["id"]] = (rule, res["final"])
    return broken


# ---------- 7. the execution dataset ----------

FIELDS = ["time", "mode", "strategy", "round", "seed", "source", "mutation", "variant",
          "sequence", "spec", "replies", "states", "verdict", "rules"]


def log_round(row):
    new_file = not os.path.exists(RUNS_FILE)
    with open(RUNS_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


# ---------- the learner ----------

class Learner:
    """Thompson sampling over the mutations (random=True: no feedback)."""

    def __init__(self, rng, random_choice=False):
        self.rng, self.random_choice = rng, random_choice
        self.wins = {m: 0.0 for m in MUTATIONS}
        self.misses = {m: 0.0 for m in MUTATIONS}
        self.picks = {m: 0 for m in MUTATIONS}

    def choose(self):
        if self.random_choice:
            return self.rng.choice(list(MUTATIONS))
        draws = {m: self.rng.betavariate(self.wins[m] + 1, self.misses[m] + 1) for m in MUTATIONS}
        return max(draws, key=draws.get)

    def reward(self, mutation, value):
        self.picks[mutation] += 1
        self.wins[mutation] += value
        self.misses[mutation] += 1 - value

    def score(self, mutation):
        """The learner's estimate (0..1) that this mutation breaks a rule."""
        return (self.wins[mutation] + 1) / (self.wins[mutation] + self.misses[mutation] + 2)


# ---------- 5-6. the loop ----------

class Fuzzer:
    def __init__(self, strategy="thompson", seed=None, log=True, random_choice=None):
        if random_choice is not None:   # older callers: Fuzzer(random_choice=True)
            strategy = "random" if random_choice else "thompson"
        self.strategy, self.log = strategy, log
        self.mode = current_mode()
        self.rng = random.Random(seed)
        self.learner = Learner(self.rng, strategy == "random")
        self.found = {}      # rule id -> finding
        self.rounds = []
        self.violation_rounds = 0
        self.ranker = None
        if strategy == "ranker":
            from ranker_model import Ranker
            self.ranker = Ranker(self.mode)

    CANDIDATES = 5     # sequences the generator makes for the ranker
    EXPLORE = 0.1      # how often the ranker sends a random candidate instead

    def generate(self, mutation):
        if not (self.ranker and self.ranker.ready()):
            return MUTATIONS[mutation](self.rng)
        candidates = [MUTATIONS[mutation](self.rng) for _ in range(self.CANDIDATES)]
        if self.rng.random() < self.EXPLORE:
            return self.rng.choice(candidates)
        scores = self.ranker.score(candidates, mutation)
        return candidates[max(range(len(candidates)), key=scores.__getitem__)]

    def round(self):
        mutation = self.learner.choose()
        spec = self.generate(mutation)
        results = run(spec)
        broken = judge(results)
        new = [rid for rid in broken if rid not in self.found]
        self.learner.reward(mutation, 1.0 if new else (0.15 if broken else 0.0))
        self.violation_rounds += bool(broken)
        if self.ranker:
            self.ranker.learn(spec, mutation, bool(broken), logged=self.log)
        for rid in new:
            rule, got = broken[rid]
            replays = [rid in judge(run(spec)) for _ in range(2)]
            self.found[rid] = {"rule": rid, "text": rule["text"], "got": got,
                               "sequence": describe(spec), "round": len(self.rounds) + 1,
                               "confirmed": all(replays)}
        record = {"n": len(self.rounds) + 1, "mutation": mutation, "sequence": describe(spec),
                  "verdict": "VIOLATION" if broken else "PASS",
                  "rules": sorted(broken), "new": new, "spec": spec}
        self.rounds.append(record)
        if self.log:
            log_round({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"), "mode": self.mode,
                "strategy": self.strategy, "round": record["n"], "seed": spec["seed"],
                "source": spec["source"], "mutation": mutation, "variant": spec["variant"] or "",
                "sequence": record["sequence"], "spec": json.dumps(spec),
                "replies": " ".join(f"{r['sent']}:{r['final'] or '-'}" for r in results),
                "states": ">".join(["none"] + [r["state"] for r in results]),
                "verdict": record["verdict"], "rules": " ".join(record["rules"])})
        return record


def bar(value, width=20):
    return "#" * round(value * width) + "." * (width - round(value * width))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--strategy", choices=STRATEGIES, default="ranker")
    parser.add_argument("--random", action="store_true", help="same as --strategy random")
    parser.add_argument("--compare", action="store_true", help="StateFuzz vs random, 3 runs each")
    parser.add_argument("--delay", type=float, default=0.2, help="pause between rounds (s)")
    parser.add_argument("--quiet", action="store_true", help="only print a summary")
    parser.add_argument("--no-log", action="store_true", help="do not save to execution_runs.csv")
    args = parser.parse_args()
    strategy = "random" if args.random else args.strategy

    sources = sorted({s["source"] for s in SEED_POOL})
    print(f"Target: Kamailio (mode: {current_mode()})   seeds: {len(SEED_POOL)} "
          f"from {', '.join(sources)}   RFC 4475 variants: {len(VARIANTS)}\n")
    if not target_is_up():
        raise SystemExit("No reply. Is Kamailio running?  ->  docker compose up -d")

    if args.compare:
        print(f"{'':<10}{'rounds with a violation':>25}{'rules broken':>15}{'1st violation at':>19}")
        for name in ("random", "ranker"):
            for rep in range(3):
                fz = Fuzzer(strategy=name, seed=rep, log=not args.no_log)
                for _ in range(args.rounds):
                    fz.round()
                first_v = min((f["round"] for f in fz.found.values()), default="-")
                print(f"{name:<10}{fz.violation_rounds:>18} of {args.rounds:<4}"
                      f"{len(fz.found):>15}{str(first_v):>19}")
        return

    fz = Fuzzer(strategy=strategy, log=not args.no_log)
    if not args.quiet:
        print(f"{'#':>3}  {'mutation':<16}{'sequence sent':<44}verdict")
    for i in range(args.rounds):
        r = fz.round()
        if args.quiet:
            if (i + 1) % 25 == 0:
                print(f"  {i + 1} rounds, {fz.violation_rounds} broke a rule")
        else:
            verdict = r["verdict"] + (" " + ", ".join(r["rules"]) if r["rules"] else "")
            if r["new"]:
                verdict += "   NEW"
            print(f"{r['n']:>3}  {r['mutation']:<16}{r['sequence']:<44}{verdict}")
            time.sleep(args.delay)

    print(f"\n{fz.violation_rounds} of {args.rounds} rounds broke a rule.\n")
    print("What the learner learned (chance this mutation breaks a rule):")
    for m in sorted(MUTATIONS, key=fz.learner.score, reverse=True):
        print(f"  {m:<16} {bar(fz.learner.score(m))} {fz.learner.score(m):.2f}"
              f"   picked {fz.learner.picks[m]}x")
    print("\nViolations found:")
    for f in fz.found.values():
        state = "CONFIRMED (2/2 replays)" if f["confirmed"] else "not confirmed"
        print(f"  {f['rule']}  got {f['got']}  round {f['round']}  {f['sequence']}  -> {state}")
        print(f"      broken rule: {f['text']}")
    if not fz.found:
        print("  none")
    if not args.no_log:
        print(f"\nRounds saved to {os.path.relpath(RUNS_FILE)}")


if __name__ == "__main__":
    main()
