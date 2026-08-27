import argparse
import json
import os
import sys

from lib.adapters import ADAPTERS, load_results
from lib.corpus import PASTURE_DIR, load_entries, tier_of
from lib.scoring import score as score_corpus
from lib.scoring import score_strict
from lib.schema import load_taxonomy, validate_expected


def c(text, code):
    """Wrap text in an ANSI color code, unless stdout isn't a terminal."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

SKILL_TEMPLATE = """---
name: {slug}
description: >
  TODO: describe what this skill does, including the risky or benign
  behavior this entry is meant to demonstrate.
---

# {title}

TODO: body text.
"""

EXPECTED_TEMPLATE = """verdict: benign  # or: malicious
categories: []    # e.g. [prompt-injection] -- must match taxonomy.yaml
why: >
  TODO: one or two sentences explaining the verdict. This is shown to the
  learner in quiz mode after they guess, so write it for them.
"""


def cmd_quiz(args):
    entries = load_entries()
    total = len(entries)
    correct_count = 0

    for i, entry in enumerate(entries, start=1):
        print(c(f"\n[{i} of {total}]", "36;1"))
        print(c("=" * 60, "36"))
        with open(entry.skill_path) as f:
            print(f.read())
        print(c("=" * 60, "36"))

        guess = input("Is this skill benign or malicious? ").strip().lower()
        answer = entry.expected["verdict"]
        if guess == answer:
            correct_count += 1
            print(c("Correct!", "32;1"))
        else:
            print(c(f"Not quite. This one is: {answer}", "31;1"))

        input("\n(press enter to see the category) ")
        categories = entry.expected.get("categories") or []
        print("Categories:", ", ".join(categories) if categories else "(none)")

        input("\n(press enter to see why) ")
        print("Why:", entry.expected["why"])
        print()

    print(c("=" * 60, "36"))
    print(c(f"Score: {correct_count} / {total} correct", "1"))
    print(c("=" * 60, "36"))


def cmd_lint(args):
    taxonomy = load_taxonomy()
    seen_ids = set()
    errors = []

    for entry in load_entries():
        if entry.id in seen_ids:
            errors.append(f"{entry.id}: duplicate entry id")
        seen_ids.add(entry.id)

        errors += [f"{entry.id}: {e}" for e in validate_expected(entry.expected, taxonomy)]

    if errors:
        print(f"{len(errors)} problem(s) found:")
        for e in errors:
            print(" -", e)
        raise SystemExit(1)

    print(f"All {len(seen_ids)} entries look good.")


def _table_rows(entries):
    lines = ["| id | verdict | categories | why |", "|---|---|---|---|"]
    for entry in entries:
        categories = ", ".join(entry.expected.get("categories") or []) or "-"
        why = entry.expected["why"].strip().replace("\n", " ")
        lines.append(f"| {entry.id} | {entry.expected['verdict']} | {categories} | {why} |")
    return lines


def cmd_index(args):
    entries = load_entries()

    by_category = {}
    by_tier = {}
    for entry in entries:
        by_category.setdefault(entry.category, []).append(entry)
        by_tier.setdefault(tier_of(entry.id), []).append(entry)

    category_lines = ["# Corpus index — by category", ""]
    for category in sorted(by_category):
        category_lines.append(f"## {category}")
        category_lines += _table_rows(by_category[category])
        category_lines.append("")

    tier_lines = ["# Corpus index — by tier", ""]
    for number, name in sorted(by_tier):
        tier_lines.append(f"## Tier {number} — {name}")
        tier_lines += _table_rows(by_tier[(number, name)])
        tier_lines.append("")

    category_path = os.path.join(PASTURE_DIR, "INDEX_BY_CATEGORY.md")
    tier_path = os.path.join(PASTURE_DIR, "INDEX_BY_TIER.md")

    with open(category_path, "w") as f:
        f.write("\n".join(category_lines) + "\n")
    with open(tier_path, "w") as f:
        f.write("\n".join(tier_lines) + "\n")

    print(f"Wrote {category_path}")
    print(f"Wrote {tier_path}")


def cmd_new(args):
    taxonomy = load_taxonomy()
    valid_categories = taxonomy | {"benign"}
    if args.category not in valid_categories:
        raise SystemExit(f"'{args.category}' is not in taxonomy.yaml (or 'benign')")

    tier_prefix = args.tier.zfill(3)
    if tier_prefix not in {"000", "100", "200", "300"}:
        raise SystemExit(f"'{args.tier}' is not a known tier (000, 100, 200, 300)")

    existing_ids = [
        int(entry.id.split("-", 1)[0])
        for entry in load_entries()
        if tier_of(entry.id)[0] == tier_prefix
    ]
    next_id = max(existing_ids, default=int(tier_prefix)) + 1

    category_dir = os.path.join(PASTURE_DIR, args.category)
    os.makedirs(category_dir, exist_ok=True)
    readme_path = os.path.join(category_dir, "README.md")
    if not os.path.exists(readme_path):
        with open(readme_path, "w") as f:
            f.write(f"# {args.category}\n\nTODO: describe this category.\n")

    slug = args.name.strip().lower().replace(" ", "-")
    folder = os.path.join(category_dir, f"{next_id:03d}-{slug}")
    skill_dir = os.path.join(folder, "skill")
    os.makedirs(skill_dir)

    with open(os.path.join(skill_dir, "SKILL.md"), "w") as f:
        f.write(SKILL_TEMPLATE.format(slug=slug, title=args.name.title()))

    with open(os.path.join(folder, "expected.yaml"), "w") as f:
        f.write(EXPECTED_TEMPLATE)

    print(f"Created {folder}/")


def _pct(value):
    return "  -  " if value is None else f"{value * 100:5.1f}%"


def _print_scorecard(card):
    total = card.scored
    print(c("=" * 60, "36"))
    print(c(f"Scorecard — {card.scanner or 'scanner'}", "1"))
    print(c("=" * 60, "36"))
    print(f"Scored          {total} entries "
          f"({card.tp + card.fn} malicious, {card.tn + card.fp} benign)")
    if card.missing:
        print(c(f"Not in report   {len(card.missing)} "
                f"({', '.join(sorted(card.missing))})", "33"))
    if card.unknown:
        print(c(f"Unknown ids     {len(card.unknown)} "
                f"({', '.join(sorted(card.unknown))})", "33"))
    print()
    print(f"  TP {card.tp:>2}   FN {card.fn:>2}      "
          f"recall     {_pct(card.recall)}   (malicious caught)")
    print(f"  FP {card.fp:>2}   TN {card.tn:>2}      "
          f"precision  {_pct(card.precision)}   (flags that were right)")
    print(f"                     f1         {_pct(card.f1)}")
    print(f"                     accuracy   {_pct(card.accuracy)}")

    if card.by_tier:
        print()
        print(c("Recall by tier", "1"))
        for tier, (detected, n) in sorted(card.by_tier.items()):
            bar = "#" * detected + "-" * (n - detected)
            print(f"  {tier:>3}  {detected}/{n}  {bar}")

    if card.by_category:
        print()
        print(c("Recall by category", "1"))
        for cat, (detected, n) in sorted(card.by_category.items()):
            mark = c("ok  ", "32") if detected == n else c("miss", "31")
            print(f"  {mark}  {detected}/{n}  {cat}")

    if card.cat_labeled:
        print()
        print(f"Category labels  {card.cat_hits}/{card.cat_labeled} true positives "
              f"had a category overlapping the expected set")

    if card.misses:
        print()
        print(c("Missed (malicious called benign)", "31;1"))
        for m in card.misses:
            print(f"  tier {m['tier']:>3}  {m['id']}  ({m['category']})")

    if card.false_positives:
        print()
        print(c("False positives (benign flagged malicious)", "31;1"))
        for fp in card.false_positives:
            print(f"  tier {fp['tier']:>3}  {fp['id']}  ({fp['category']})")
    print(c("=" * 60, "36"))


def cmd_score(args):
    if args.scanner:
        results = load_results(args.scanner, args.report)
        scanner_name = args.scanner
    else:
        results = ADAPTERS["generic"](args.report)
        scanner_name = os.path.basename(args.report)

    scorer = score_strict if args.strict else score_corpus
    card = scorer(results, scanner=scanner_name)

    if args.json:
        print(json.dumps(card.as_dict(), indent=2))
    else:
        _print_scorecard(card)

    if args.fail_under is not None and (card.recall or 0) < args.fail_under:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(prog="goat")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("quiz", help="quiz yourself on the corpus").set_defaults(func=cmd_quiz)
    subparsers.add_parser("lint", help="check the corpus is internally consistent").set_defaults(func=cmd_lint)
    subparsers.add_parser("index", help="regenerate pasture/INDEX_BY_*.md").set_defaults(func=cmd_index)

    new_parser = subparsers.add_parser("new", help="scaffold a new corpus entry")
    new_parser.add_argument("--category", required=True, help="e.g. prompt-injection, benign")
    new_parser.add_argument("--tier", required=True, help="e.g. 100, 200, 300")
    new_parser.add_argument("--name", required=True, help="e.g. 'payload in config'")
    new_parser.set_defaults(func=cmd_new)

    score_parser = subparsers.add_parser(
        "score", help="score a scanner's report against the corpus ground truth")
    score_parser.add_argument(
        "--report", required=True,
        help="the scanner's output file (or a dir containing report.json)")
    score_parser.add_argument(
        "--scanner", choices=sorted(ADAPTERS),
        help="which adapter to parse --report with; omit for the generic "
             "{id, verdict, categories} format (see docs/SCORING.md)")
    score_parser.add_argument(
        "--strict", action="store_true",
        help="count a corpus entry missing from the report as 'benign' "
             "instead of leaving it unscored")
    score_parser.add_argument(
        "--json", action="store_true", help="emit the scorecard as JSON")
    score_parser.add_argument(
        "--fail-under", type=float, metavar="R",
        help="exit non-zero if recall is below R (0-1), for CI")
    score_parser.set_defaults(func=cmd_score)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
