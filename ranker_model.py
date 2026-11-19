"""Piece 8: the classifier that ranks candidate sequences (scikit-learn).

    python ranker_model.py                 train on the current server mode
    python ranker_model.py --mode buggy    train on rounds recorded in buggy mode

It learns from datasets/execution_runs.csv (written by learning_fuzzer.py):
every row is a sequence that was sent, labelled by the rule checker
(VIOLATION = 1, PASS = 0). Given a new sequence it predicts the chance that
it breaks a security rule, so the fuzzer can send the most promising one.

Features: only what is known BEFORE sending (the model must rank candidates
that have not been sent yet):
  messages and their order (pairs such as BYE>ACK), the expected call state
  at each step (e.g. a BYE while no call is up), the password case, a forged
  call identity, another user's address, the RFC 4475 variant, the source
  dataset and the mutation.

Two models are trained (logistic regression, gradient boosting) and tested on
SEQUENCES THEY NEVER SAW (the split is by sequence, so the same sequence is
never in both train and test). The better one is saved to
datasets/ranker_<mode>.pkl. One model per mode: the same sequence is fine on
a correct server and a violation on a misconfigured one.
"""

import argparse
import csv
import json
import os
import pickle
import warnings

from rule_checker import current_mode

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS_FILE = os.path.join(HERE, "datasets", "execution_runs.csv")


def model_file(mode):
    return os.path.join(HERE, "datasets", f"ranker_{mode}.pkl")


def features(spec, mutation):
    """One sequence -> a dict of named features."""
    steps = spec["steps"]
    methods = [s["method"] for s in steps]
    f = {"steps": len(steps), f"mutation={mutation}": 1,
         f"source={spec['source']}": 1, f"first={methods[0]}": 1}
    if spec.get("variant"):
        f[f"variant={spec['variant']}"] = 1
    for m in methods:
        f[f"count_{m}"] = f.get(f"count_{m}", 0) + 1
    for a, b in zip(methods, methods[1:]):
        f[f"order {a}>{b}"] = 1
    call = "none"   # the call state the fuzzer expects at each step
    for s in steps:
        m = s["method"]
        if s.get("forge"):
            f["forged BYE"] = 1
        f[f"{m} while call={'none' if s.get('forge') else call}"] = 1
        if m == "REGISTER":
            f[f"REGISTER password={s.get('auth', 'valid')}"] = 1
            if s["to"] != "alice":
                f["REGISTER for another user"] = 1
        if m == "INVITE":
            call = "up"
        elif m == "BYE" and call == "up" and not s.get("forge"):
            call = "ended"
    return f


def load_rows(mode):
    if not os.path.exists(RUNS_FILE):
        return []
    with open(RUNS_FILE, newline="") as f:
        return [r for r in csv.DictReader(f) if r["mode"] == mode]


def make_models():
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    return {"logistic regression": LogisticRegression(max_iter=2000, class_weight="balanced"),
            "gradient boosting": GradientBoostingClassifier(random_state=0)}


def to_xy(rows):
    X = [features(json.loads(r["spec"]), r["mutation"]) for r in rows]
    y = [1 if r["verdict"] == "VIOLATION" else 0 for r in rows]
    return X, y


def fit(name, X, y):
    """Train one model on all rows: (vectorizer, model)."""
    from sklearn.feature_extraction import DictVectorizer
    vec = DictVectorizer()
    model = make_models()[name]
    model.fit(vec.fit_transform(X), y)
    return vec, model


def evaluate(rows):
    """Train both models on some sequences, test on the unseen ones."""
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    from sklearn.model_selection import GroupShuffleSplit

    X, y = to_xy(rows)
    groups = [r["sequence"] for r in rows]
    for state in range(50):  # a split whose train and test both hold each class
        tr, te = next(GroupShuffleSplit(test_size=0.3, random_state=state).split(X, y, groups))
        if len({y[i] for i in tr}) == 2 and len({y[i] for i in te}) == 2:
            break
    else:
        return None, None
    vec = DictVectorizer()
    Xtr = vec.fit_transform([X[i] for i in tr])
    Xte = vec.transform([X[i] for i in te])
    ytr, yte = [y[i] for i in tr], [y[i] for i in te]
    results = {}
    for name, model in make_models().items():
        model.fit(Xtr, ytr)
        pred = model.predict(Xte)
        results[name] = {
            "accuracy": accuracy_score(yte, pred),
            "precision": precision_score(yte, pred, zero_division=0),
            "recall": recall_score(yte, pred, zero_division=0),
            "f1": f1_score(yte, pred, zero_division=0)}
    split = {"train_rows": len(tr), "test_rows": len(te),
             "train_sequences": len({groups[i] for i in tr}),
             "test_sequences": len({groups[i] for i in te})}
    return results, split


def top_features(vec, model, n=8):
    names = vec.get_feature_names_out()
    if hasattr(model, "coef_"):
        weights = model.coef_[0]          # + pushes towards VIOLATION
    else:
        weights = model.feature_importances_
    order = sorted(range(len(names)), key=lambda i: weights[i], reverse=True)[:n]
    return [(names[i], float(weights[i])) for i in order]


class Ranker:
    """Used by learning_fuzzer.py: scores candidate sequences."""

    RETRAIN_EVERY = 20

    def __init__(self, mode):
        self.mode, self.vec, self.model, self.name = mode, None, None, "logistic regression"
        if os.path.exists(model_file(mode)):
            with open(model_file(mode), "rb") as f:
                saved = pickle.load(f)
            self.vec, self.model, self.name = saved["vectorizer"], saved["model"], saved["name"]
        self.extra = []       # rounds of this run (if they are not logged)
        self.since = 0

    def ready(self):
        return self.model is not None

    def score(self, specs, mutation):
        X = self.vec.transform([features(s, mutation) for s in specs])
        return list(self.model.predict_proba(X)[:, 1])

    def learn(self, spec, mutation, violation, logged):
        """Called after every round; retrains every RETRAIN_EVERY rounds."""
        if not logged:
            self.extra.append({"spec": json.dumps(spec), "mutation": mutation,
                               "verdict": "VIOLATION" if violation else "PASS"})
        self.since += 1
        if self.since >= self.RETRAIN_EVERY:
            self.since = 0
            X, y = to_xy(load_rows(self.mode) + self.extra)
            if len(set(y)) == 2:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self.vec, self.model = fit(self.name, X, y)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default=current_mode(), choices=["normal", "buggy"])
    args = parser.parse_args()
    rows = load_rows(args.mode)
    X, y = to_xy(rows)
    print(f"Execution dataset: {len(rows)} rounds in {args.mode} mode, "
          f"{sum(y)} VIOLATION, {len(y) - sum(y)} PASS, "
          f"{len({r['sequence'] for r in rows})} different sequences")
    sources = {}
    for r in rows:
        sources[r["source"]] = sources.get(r["source"], 0) + 1
    print("  by source: " + ", ".join(f"{k} {v}" for k, v in sorted(sources.items())))
    if len(rows) < 30:
        raise SystemExit("Too few rounds. Collect more:  python learning_fuzzer.py --rounds 300 --quiet")
    if len(set(y)) < 2:
        print(f"\nEvery round is {'a VIOLATION' if y[0] else 'PASS'} in {args.mode} mode, "
              "so there is nothing to tell apart: no model is trained.")
        if args.mode == "normal":
            print("That is the false-alarm check: the correct server broke no rule.")
        return

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        results, split = evaluate(rows)
    if results is None:
        raise SystemExit("Not enough different sequences of each class to test. Collect more rounds.")
    print(f"\nTest on unseen sequences: trained on {split['train_sequences']} sequences "
          f"({split['train_rows']} rounds), tested on {split['test_sequences']} others "
          f"({split['test_rows']} rounds)\n")
    print(f"  {'model':<22}{'accuracy':>9}{'precision':>11}{'recall':>8}{'F1':>7}")
    for name, m in results.items():
        print(f"  {name:<22}{m['accuracy']:>9.2f}{m['precision']:>11.2f}{m['recall']:>8.2f}{m['f1']:>7.2f}")
    best = max(results, key=lambda n: (round(results[n]["f1"], 3), n == "logistic regression"))
    print(f"\nKept: {best} (higher F1; logistic regression on a tie, as it is simpler)")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        vec, model = fit(best, X, y)   # final model: all rows
    label = "weight" if hasattr(model, "coef_") else "importance"
    print(f"\nFeatures that lead to violations ({label}):")
    for name, w in top_features(vec, model):
        print(f"  {w:>7.2f}  {name}")
    with open(model_file(args.mode), "wb") as f:
        pickle.dump({"mode": args.mode, "name": best, "vectorizer": vec, "model": model,
                     "metrics": results[best], "split": split, "rows": len(rows)}, f)
    print(f"\nSaved: {os.path.relpath(model_file(args.mode))}")


if __name__ == "__main__":
    main()
