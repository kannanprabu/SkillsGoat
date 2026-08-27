"""Tests for lib/scoring.py, lib/adapters.py and `goat.py score`.

Stdlib unittest only, so `python3 -m unittest` works with nothing
installed but the corpus's own `pyyaml`. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.adapters import load_generic, load_skill_scanner, load_skillspector
from lib.corpus import load_entries
from lib.scoring import ScanResult, score, score_strict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL = os.path.join(REPO, "evaluations")


def _perfect_results():
    """A scanner that gets every corpus entry exactly right."""
    return {
        e.id: ScanResult(verdict=e.expected["verdict"],
                         categories=e.expected.get("categories") or [])
        for e in load_entries()
    }


class ScanResultTest(unittest.TestCase):
    def test_rejects_unknown_verdict(self):
        with self.assertRaises(ValueError):
            ScanResult(verdict="sketchy")

    def test_categories_defaults_to_list(self):
        self.assertEqual(ScanResult(verdict="benign").categories, [])


class ScoreTest(unittest.TestCase):
    def test_perfect_scanner(self):
        card = score(_perfect_results(), scanner="perfect")
        self.assertEqual(card.fp, 0)
        self.assertEqual(card.fn, 0)
        self.assertEqual(card.recall, 1.0)
        self.assertEqual(card.precision, 1.0)
        self.assertEqual(card.accuracy, 1.0)
        self.assertEqual(card.misses, [])
        self.assertEqual(card.false_positives, [])
        # every malicious entry has an expected category, and the perfect
        # scanner echoes it, so every true positive is a category hit.
        self.assertEqual(card.cat_hits, card.cat_labeled)
        self.assertEqual(card.cat_labeled, card.tp)

    def test_silent_scanner_misses_everything(self):
        card = score({}, scanner="silent")
        self.assertEqual(card.scored, 0)
        self.assertEqual(len(card.missing), len(load_entries()))
        self.assertIsNone(card.recall)

    def test_flag_everything_scanner(self):
        results = {e.id: ScanResult(verdict="malicious") for e in load_entries()}
        card = score(results, scanner="paranoid")
        self.assertEqual(card.fn, 0)
        self.assertEqual(card.recall, 1.0)
        self.assertEqual(card.tn, 0)
        # the three benign decoys are all false positives
        self.assertEqual(card.fp, 3)
        self.assertEqual({fp["id"] for fp in card.false_positives},
                         {e.id for e in load_entries()
                          if e.expected["verdict"] == "benign"})

    def test_partial_report_is_scored_on_what_it_covers(self):
        entries = load_entries()
        one = entries[0]
        results = {one.id: ScanResult(verdict=one.expected["verdict"])}
        card = score(results)
        self.assertEqual(card.scored, 1)
        self.assertEqual(len(card.missing), len(entries) - 1)

    def test_strict_counts_missing_as_benign(self):
        entries = load_entries()
        malicious = next(e for e in entries if e.expected["verdict"] == "malicious")
        # report covers only that one malicious entry, and gets it right
        results = {malicious.id: ScanResult(verdict="malicious")}
        strict = score_strict(results)
        self.assertEqual(strict.scored, len(entries))
        # every other malicious entry is now a miss
        n_malicious = sum(1 for e in entries if e.expected["verdict"] == "malicious")
        self.assertEqual(strict.fn, n_malicious - 1)
        self.assertEqual(strict.tp, 1)

    def test_unknown_ids_are_reported_not_scored(self):
        results = dict(_perfect_results())
        results["999-not-a-real-entry"] = ScanResult(verdict="malicious")
        card = score(results)
        self.assertIn("999-not-a-real-entry", card.unknown)
        self.assertEqual(card.recall, 1.0)  # bogus id didn't distort metrics

    def test_as_dict_is_json_serialisable(self):
        card = score(_perfect_results(), scanner="perfect")
        json.dumps(card.as_dict())  # must not raise


class AdapterTest(unittest.TestCase):
    def test_generic_accepts_bare_ids_and_paths(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([
                {"id": "101-instruction-in-description", "verdict": "malicious",
                 "categories": ["prompt-injection-metadata"]},
                {"id": "benign/001-shell-wrapper-tool/skill", "verdict": "benign"},
            ], f)
            path = f.name
        try:
            results = load_generic(path)
        finally:
            os.unlink(path)
        self.assertEqual(results["101-instruction-in-description"].verdict, "malicious")
        self.assertIn("001-shell-wrapper-tool", results)

    def test_skillspector_adapter_matches_published_headline(self):
        # evaluations/skillspector/report.md: 1/12 malicious flagged
        # DO NOT INSTALL, 1/3 benign false-positive.
        results = load_skillspector(os.path.join(EVAL, "skillspector", "report.json"))
        card = score(results, scanner="skillspector")
        self.assertEqual(card.tp, 1)
        self.assertEqual(card.fn, 11)
        self.assertEqual(card.fp, 1)

    def test_skillspector_llm_adapter_matches_published_headline(self):
        results = load_skillspector(
            os.path.join(EVAL, "skillspector", "llm-enabled", "report.json"))
        card = score(results, scanner="skillspector-llm")
        self.assertEqual(card.tp, 7)
        self.assertEqual(card.fp, 1)  # 203-changelog-generator survives

    def test_skill_scanner_adapter_matches_published_headline(self):
        # evaluations/skill-scanner/report.md: 3/12 flagged NOT SAFE, 0/3 FP.
        results = load_skill_scanner(
            os.path.join(EVAL, "skill-scanner", "report.json"))
        card = score(results, scanner="skill-scanner")
        self.assertEqual(card.tp, 3)
        self.assertEqual(card.fp, 0)

    def test_skill_scanner_llm_adapter_matches_published_headline(self):
        # report.md: "recall jumps from 3/12 to 10/12 with no cost to
        # precision, though two entries remain unrecoverable".
        results = load_skill_scanner(
            os.path.join(EVAL, "skill-scanner", "llm-enabled", "report.json"))
        card = score(results, scanner="skill-scanner-llm")
        self.assertEqual(card.tp, 10)
        self.assertEqual(card.fn, 2)
        self.assertEqual(card.fp, 0)
        self.assertEqual({m["category"] for m in card.misses}, {"indirect-injection"})


class CliTest(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "goat.py", "score", *args],
            cwd=REPO, capture_output=True, text=True)

    def test_score_json_output(self):
        p = self._run("--scanner", "skill-scanner",
                      "--report", "evaluations/skill-scanner/report.json", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        payload = json.loads(p.stdout)
        self.assertEqual(payload["confusion"]["tp"], 3)

    def test_fail_under_gate(self):
        p = self._run("--scanner", "skill-scanner",
                      "--report", "evaluations/skill-scanner/report.json",
                      "--fail-under", "0.9", "--json")
        self.assertEqual(p.returncode, 1)

    def test_fail_under_pass(self):
        p = self._run("--scanner", "skill-scanner",
                      "--report", "evaluations/skill-scanner/llm-enabled/report.json",
                      "--fail-under", "0.8", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main()
