"""Score a scanner's output against the corpus ground truth.

The corpus half of an evaluation is already machine-readable — every
entry's `expected.yaml` says what a correct scanner should conclude. This
module is the other half: given a scanner's verdicts in a normalised
shape, it works out what that scanner caught, what it missed, and what it
wrongly flagged, so the numbers in `evaluations/<scanner>/report.md` stop
being counted by hand.

A scanner's native output is turned into that normalised shape by an
adapter in `lib/adapters.py`. The shape is one `ScanResult` per skill:

    ScanResult(verdict="malicious" | "benign", categories=[...])

`categories` is best-effort — many scanners don't emit anything that maps
onto `taxonomy.yaml`, so category scoring is reported separately and only
over the entries where the scanner said something.
"""

from dataclasses import dataclass, field

from lib.corpus import load_entries, tier_of

VALID_VERDICTS = {"benign", "malicious"}

# "malicious" is the positive class: a scanner flagging a skill is a
# positive, so a true positive is a malicious skill correctly flagged.
POSITIVE = "malicious"


@dataclass
class ScanResult:
    """One scanner's conclusion about one skill, adapter-normalised."""

    verdict: str
    categories: list = field(default_factory=list)

    def __post_init__(self):
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(
                f"verdict must be one of {sorted(VALID_VERDICTS)}, got {self.verdict!r}"
            )
        self.categories = list(self.categories or [])


@dataclass
class Scorecard:
    scanner: str = ""

    # Binary confusion matrix on the verdict.
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    # Entries in the corpus the scanner report didn't cover, and entries
    # in the report that don't correspond to any corpus entry.
    missing: list = field(default_factory=list)   # ids
    unknown: list = field(default_factory=list)   # ids

    # Detail lists, each item: {"id", "category", "tier"}.
    misses: list = field(default_factory=list)            # malicious called benign
    false_positives: list = field(default_factory=list)   # benign called malicious

    # {tier_number: [detected, total]} over malicious entries only.
    by_tier: dict = field(default_factory=dict)
    # {category: [detected, total]} over malicious entries only.
    by_category: dict = field(default_factory=dict)

    # Category-label agreement, over true positives where the scanner
    # actually emitted at least one category.
    cat_labeled: int = 0   # true positives with a non-empty category list
    cat_hits: int = 0      # ...of those, ones that overlap the expected set

    @property
    def scored(self):
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self):
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self):
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def f1(self):
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return 2 * p * r / (p + r)

    @property
    def accuracy(self):
        return (self.tp + self.tn) / self.scored if self.scored else None

    def as_dict(self):
        return {
            "scanner": self.scanner,
            "counts": {
                "scored": self.scored,
                "malicious": self.tp + self.fn,
                "benign": self.tn + self.fp,
                "missing_from_report": len(self.missing),
                "unknown_in_report": len(self.unknown),
            },
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "metrics": {
                "precision": self.precision,
                "recall": self.recall,
                "f1": self.f1,
                "accuracy": self.accuracy,
            },
            "by_tier": {
                str(t): {"detected": d, "total": n}
                for t, (d, n) in sorted(self.by_tier.items())
            },
            "by_category": {
                cat: {"detected": d, "total": n}
                for cat, (d, n) in sorted(self.by_category.items())
            },
            "category_labels": {
                "labeled_true_positives": self.cat_labeled,
                "overlapping_expected": self.cat_hits,
            },
            "misses": self.misses,
            "false_positives": self.false_positives,
            "missing_from_report": sorted(self.missing),
            "unknown_in_report": sorted(self.unknown),
        }


def score(results, scanner="", entries=None):
    """Compare a dict of {entry_id: ScanResult} against the corpus.

    Entries the report doesn't cover are recorded in `Scorecard.missing`
    and left out of every metric — a partial report is scored on what it
    contains, not penalised for what it omits. Use `goat.py score
    --strict` to treat an uncovered entry as a wrong answer instead.
    """
    entries = entries if entries is not None else load_entries()
    card = Scorecard(scanner=scanner)

    seen = set()
    for entry in entries:
        expected_verdict = entry.expected["verdict"]
        expected_cats = set(entry.expected.get("categories") or [])
        tier_number = int(tier_of(entry.id)[0])
        is_malicious = expected_verdict == POSITIVE

        if is_malicious:
            card.by_tier.setdefault(tier_number, [0, 0])[1] += 1
            card.by_category.setdefault(entry.category, [0, 0])[1] += 1

        result = results.get(entry.id)
        if result is None:
            card.missing.append(entry.id)
            continue
        seen.add(entry.id)

        detail = {"id": entry.id, "category": entry.category, "tier": tier_number}
        got_positive = result.verdict == POSITIVE

        if is_malicious and got_positive:
            card.tp += 1
            card.by_tier[tier_number][0] += 1
            card.by_category[entry.category][0] += 1
            if result.categories:
                card.cat_labeled += 1
                if expected_cats & set(result.categories):
                    card.cat_hits += 1
        elif is_malicious and not got_positive:
            card.fn += 1
            card.misses.append(detail)
        elif not is_malicious and got_positive:
            card.fp += 1
            card.false_positives.append(detail)
        else:
            card.tn += 1

    card.unknown = [rid for rid in results if rid not in seen]
    return card


def score_strict(results, scanner="", entries=None):
    """Like `score`, but an entry missing from the report counts as the
    scanner having called it benign (the safe-looking default a silent
    scanner effectively asserts)."""
    entries = entries if entries is not None else load_entries()
    filled = dict(results)
    for entry in entries:
        filled.setdefault(entry.id, ScanResult(verdict="benign"))
    card = score(filled, scanner=scanner, entries=entries)
    # `missing` is meaningful to report even though it was scored.
    card.missing = [e.id for e in entries if e.id not in results]
    card.unknown = [rid for rid in results
                    if rid not in {e.id for e in entries}]
    return card
