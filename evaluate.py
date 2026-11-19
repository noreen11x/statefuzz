"""Piece 9: compare the 3 strategies on the same Kamailio.

    python evaluate.py                    5 runs x 40 rounds per strategy
    python evaluate.py --runs 10 --rounds 60
    python evaluate.py --with-thompson    also Thompson alone (what the classifier adds)

Strategies (learning_fuzzer.py):
  random     no feedback
  ranker     StateFuzz: Thompson sampling picks the mutation (feedback) and the
             classifier (ranker_model.py) picks the sequence

Measured per run, in the current server mode:
  tests to 1st violation   sequences sent until a rule was first broken
  tests to all rules       sequences sent until every rule broken in this
                           evaluation (by any run) was found by this run
  rounds with a violation

Buggy mode: results/evaluation_buggy.csv, .md and a chart (.png).
Normal mode: the false-alarm check (every strategy should break 0 rules).
Evaluation rounds are not added to execution_runs.csv.
"""

import argparse
import csv
import os
import statistics

from fuzzer_client import target_is_up
from learning_fuzzer import Fuzzer
from rule_checker import current_mode

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results")
NAMES = {"random": "Random (no feedback)", "thompson": "Thompson only",
         "ranker": "StateFuzz (feedback + classifier)"}


def one_run(strategy, seed, rounds):
    fz = Fuzzer(strategy=strategy, seed=seed, log=False)
    first, found_at = None, {}
    for _ in range(rounds):
        r = fz.round()
        if r["rules"] and first is None:
            first = r["n"]
        for rid in r["rules"]:
            found_at.setdefault(rid, r["n"])
    return {"strategy": strategy, "seed": seed, "first": first, "found_at": found_at,
            "violation_rounds": fz.violation_rounds}


def fmt(values, rounds):
    """Mean of the runs; a run that never got there counts as `rounds` (shown with >)."""
    if not values:
        return "-"
    done = [v for v in values if v is not None]
    mean = statistics.mean(v if v is not None else rounds for v in values)
    return f"{mean:.1f}" if len(done) == len(values) else f">{mean:.1f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=40)
    parser.add_argument("--with-thompson", action="store_true", help="also Thompson alone")
    args = parser.parse_args()
    STRATEGIES = ("random", "thompson", "ranker") if args.with_thompson else ("random", "ranker")
    mode = current_mode()
    print(f"Target: Kamailio (mode: {mode})   {args.runs} runs x {args.rounds} rounds per strategy\n")
    if not target_is_up():
        raise SystemExit("No reply. Is Kamailio running?  ->  docker compose up -d")

    runs = []
    for strategy in STRATEGIES:
        for rep in range(args.runs):
            res = one_run(strategy, 100 + rep, args.rounds)
            runs.append(res)
            print(f"  {NAMES[strategy]:<34} run {rep + 1}: first violation at "
                  f"{res['first'] or '-'}, rules {sorted(res['found_at']) or 'none'}")

    all_rules = sorted({rid for r in runs for rid in r["found_at"]})
    for r in runs:
        r["all"] = max(r["found_at"].values()) if all_rules and \
            set(r["found_at"]) == set(all_rules) else None
    os.makedirs(OUT, exist_ok=True)

    if not all_rules:
        print(f"\nFalse-alarm check ({mode} mode): no strategy broke any rule in "
              f"{len(runs) * args.rounds} rounds.")
        with open(os.path.join(OUT, f"evaluation_{mode}.md"), "w") as f:
            f.write(f"False-alarm check, {mode} mode: 0 violations in "
                    f"{len(runs) * args.rounds} rounds ({args.runs} runs x {args.rounds} "
                    f"rounds x {len(STRATEGIES)} strategies).\n")
        return

    header = (f"| Strategy | Tests to 1st violation | Tests to all rules ({', '.join(all_rules)}) "
              f"| Rounds with a violation |")
    lines = [header, "|---|---|---|---|"]
    for s in STRATEGIES:
        rs = [r for r in runs if r["strategy"] == s]
        vr = statistics.mean(r["violation_rounds"] for r in rs)
        lines.append(f"| {NAMES[s]} | {fmt([r['first'] for r in rs], args.rounds)} | "
                     f"{fmt([r['all'] for r in rs], args.rounds)} | "
                     f"{vr:.1f} of {args.rounds} ({100 * vr / args.rounds:.0f}%) |")
    table = "\n".join(lines)
    note = (f"\nMean of {args.runs} runs x {args.rounds} rounds, {mode} mode. "
            f"'>' means at least one run did not get there (counted as {args.rounds}).")
    print("\n" + table + note)

    with open(os.path.join(OUT, f"evaluation_{mode}.md"), "w") as f:
        f.write(table + "\n" + note + "\n")
    with open(os.path.join(OUT, f"evaluation_{mode}.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["strategy", "run_seed", "tests_to_first_violation", "tests_to_all_rules",
                    "violation_rounds", "rules_found"])
        for r in runs:
            w.writerow([r["strategy"], r["seed"], r["first"] or "", r["all"] or "",
                        r["violation_rounds"], " ".join(sorted(r["found_at"]))])

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4.5))
    width, colors = 0.38, ["#9aa5b8", "#2f4b8a"]
    for k, (key, label) in enumerate((("first", "Tests to 1st violation"),
                                      ("all", "Tests to find all rules"))):
        for i, s in enumerate(STRATEGIES):
            vals = [r[key] if r[key] is not None else args.rounds
                    for r in runs if r["strategy"] == s]
            x = i + (k - 0.5) * width
            ax.bar(x, statistics.mean(vals), width, color=colors[k],
                   label=label if i == 0 else None)
            ax.scatter([x] * len(vals), vals, color="black", s=12, zorder=3)
    ax.set_xticks(range(len(STRATEGIES)), [NAMES[s] for s in STRATEGIES])
    ax.set_ylabel("sequences sent (lower is better)")
    ax.set_title(f"Kamailio, {mode} mode: {args.runs} runs x {args.rounds} rounds (dots = runs)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False)
    fig.tight_layout()
    path = os.path.join(OUT, f"evaluation_{mode}.png")
    fig.savefig(path, dpi=160)
    print(f"\nSaved: results/evaluation_{mode}.md, .csv and .png")


if __name__ == "__main__":
    main()
