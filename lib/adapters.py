"""Turn a scanner's native report into `{entry_id: ScanResult}`.

Each scanner speaks its own dialect — a 0-100 risk score, a SAFE/NOT SAFE
boolean, a list of findings with severities. An adapter's whole job is to
collapse that into the one thing scoring needs: did this scanner, in
effect, tell a user *not* to install this skill?

Adding a scanner is one function, `load(path) -> {entry_id: ScanResult}`,
registered in `ADAPTERS` at the bottom. `path` is whatever the scanner
wrote — usually a JSON file, sometimes a directory. Map its per-skill
output back to a corpus id (the `<id>-<name>` folder name, e.g.
`302-ci-log-shipper`) and decide malicious vs benign by the scanner's
*own* top-line recommendation, not by re-deriving one from raw findings.

See docs/SCORING.md for the format the `generic` adapter expects, which
is also the format a new scanner integration should aim to emit directly.
"""

import json
import os

from lib.scoring import ScanResult

# Every corpus entry lives at pasture/<category>/<id>-<name>/skill/. Both
# of the paths scanners record — a repo-relative "source" and an absolute
# "skill_path" — contain ".../<id>-<name>/skill" somewhere, so the id is
# always the basename of the directory that contains "skill".


def _entry_id_from_path(path):
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if parts and parts[-1] == "skill":
        parts = parts[:-1]
    if not parts:
        raise ValueError(f"can't derive an entry id from {path!r}")
    return parts[-1]


def _load_json(path):
    if os.path.isdir(path):
        path = os.path.join(path, "report.json")
    with open(path) as f:
        return json.load(f)


# --------------------------------------------------------------------------
# generic — the format documented in docs/SCORING.md
# --------------------------------------------------------------------------

def load_generic(path):
    """A JSON list of {id, verdict, categories?}, or an object with a
    "results" list of the same. `id` may be the bare `<id>-<name>` folder
    name or any path that ends in `<id>-<name>[/skill]`."""
    data = _load_json(path)
    rows = data["results"] if isinstance(data, dict) else data

    results = {}
    for row in rows:
        raw_id = row.get("id") or row.get("skill") or row.get("source") or ""
        entry_id = raw_id if "/" not in raw_id else _entry_id_from_path(raw_id)
        verdict = row["verdict"].strip().lower()
        results[entry_id] = ScanResult(verdict=verdict,
                                       categories=row.get("categories") or [])
    return results


# --------------------------------------------------------------------------
# skillspector — NVIDIA SkillSpector
# --------------------------------------------------------------------------

# SkillSpector emits SAFE / CAUTION / DO NOT INSTALL. Only DO NOT INSTALL
# is a "don't run this" verdict — CAUTION is advisory and, in the
# published evaluations, is counted as not-flagged. Keep that mapping so
# the scorer reproduces evaluations/skillspector/report.md.
SKILLSPECTOR_BLOCK = {"DO NOT INSTALL"}


def load_skillspector(path):
    data = _load_json(path)
    results = {}
    for skill in data.get("skills", []):
        entry_id = _entry_id_from_path(skill["skill"]["source"])
        recommendation = skill["risk_assessment"]["recommendation"].upper()
        verdict = "malicious" if recommendation in SKILLSPECTOR_BLOCK else "benign"

        cats = []
        for issue in skill.get("issues", []) or []:
            cat = issue.get("category")
            if cat:
                cats.append(cat)
        results[entry_id] = ScanResult(verdict=verdict, categories=cats)
    return results


# --------------------------------------------------------------------------
# skill-scanner — Cisco skill-scanner
# --------------------------------------------------------------------------

def load_skill_scanner(path):
    data = _load_json(path)
    results = {}
    for row in data.get("results", []):
        entry_id = _entry_id_from_path(row["skill_path"])
        # `is_safe` is the scanner's own top-line boolean; a corpus-wide
        # MANIFEST_MISSING_LICENSE notice fires on every entry and does
        # not move it, which is exactly why we read the boolean and not
        # the finding count.
        verdict = "benign" if row.get("is_safe", True) else "malicious"

        cats = []
        for finding in row.get("findings", []) or []:
            cat = finding.get("category")
            if cat and cat != "policy_violation":
                cats.append(cat)
        results[entry_id] = ScanResult(verdict=verdict, categories=cats)
    return results


ADAPTERS = {
    "generic": load_generic,
    "skillspector": load_skillspector,
    "skill-scanner": load_skill_scanner,
}


def load_results(scanner, path):
    try:
        adapter = ADAPTERS[scanner]
    except KeyError:
        known = ", ".join(sorted(ADAPTERS))
        raise SystemExit(f"unknown scanner {scanner!r} — known adapters: {known}")
    return adapter(path)
