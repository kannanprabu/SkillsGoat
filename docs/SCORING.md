# Scoring a scanner

`python3 goat.py score` compares a scanner's verdicts against the
corpus's ground truth and prints what it caught, what it missed, and what
it wrongly flagged. It turns the by-hand counting behind
`evaluations/<scanner>/report.md` into a repeatable command.

## Quick start

Against a scanner SkillsGoat already has an adapter for:

    python3 goat.py score --scanner skill-scanner --report evaluations/skill-scanner/report.json
    python3 goat.py score --scanner skillspector  --report evaluations/skillspector/report.json

Against any other scanner, normalise its output to the generic format
below and drop `--scanner`:

    python3 goat.py score --report my-run.json

Add `--json` for a machine-readable scorecard, or `--fail-under 0.8` to
exit non-zero when recall drops below a threshold (for CI).

## What it measures

`malicious` is the positive class — a scanner flagging a skill is a
positive.

| Metric | Meaning |
|---|---|
| **recall** | fraction of the 12 malicious skills the scanner flagged |
| **precision** | fraction of the scanner's flags that were correct |
| **f1** | harmonic mean of the two |
| **accuracy** | fraction of all 15 verdicts that were correct |
| **recall by tier** | recall split across evasion tiers 100/200/300 (see `docs/TIERS.md`) |
| **recall by category** | recall split across the `taxonomy.yaml` categories |
| **category labels** | of the true positives where the scanner emitted its own category, how many overlap the expected `taxonomy.yaml` category. Reported separately and never folded into the score — most scanners don't emit anything that maps onto the taxonomy. |

A partial report is scored only on the entries it covers; the rest are
listed under "Not in report". `--strict` instead counts an uncovered
entry as the scanner having called it benign.

## Generic report format

A JSON list — or an object with a `results` list — of one row per skill:

```json
[
  { "id": "101-instruction-in-description", "verdict": "malicious",
    "categories": ["prompt-injection-metadata"] },
  { "id": "001-shell-wrapper-tool", "verdict": "benign" }
]
```

- `id` — the `<id>-<name>` corpus folder (e.g. `302-ci-log-shipper`). A
  full path ending in `<id>-<name>` or `<id>-<name>/skill` also works, so
  you can feed back whatever path your scanner recorded.
- `verdict` — `malicious` or `benign`. Map your scanner's top-line
  recommendation onto this: its "do not install" / "unsafe" state is
  `malicious`, everything advisory or lower is `benign`.
- `categories` — optional, `taxonomy.yaml` labels.

## Adding a scanner adapter

Adapters live in `lib/adapters.py`. One is a single function:

```python
def load_myscanner(path):
    data = _load_json(path)
    results = {}
    for row in data["..."]:
        entry_id = _entry_id_from_path(row["..."])   # -> "302-ci-log-shipper"
        verdict = "malicious" if row["..."] else "benign"
        results[entry_id] = ScanResult(verdict=verdict, categories=[...])
    return results
```

Register it in the `ADAPTERS` dict at the bottom of the file and it
becomes a `--scanner` choice. Decide `verdict` from the scanner's own
headline recommendation, not by re-deriving one from raw findings — the
point of the evaluation is to score the verdict a user would actually
see. The two bundled adapters (`skillspector`, `skill-scanner`) reproduce
the headline numbers in their respective `evaluations/` write-ups;
`tests/test_scoring.py` pins those numbers so an adapter change can't
silently drift.
