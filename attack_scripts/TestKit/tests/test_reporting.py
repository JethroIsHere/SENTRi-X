"""Regression checks for unscored hardware reports and single-flow narratives."""
import ast
import csv
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT))
import run_chapter4_matrix as matrix

spec = importlib.util.spec_from_file_location("sentrix_narrative", KIT.parents[1] / "backend/narrative.py")
narrative = importlib.util.module_from_spec(spec)
spec.loader.exec_module(narrative)


def row(trial="test", case="S1", engine="hybrid", count=7, status="completed", code=0, domain="omni"):
    return dict(trial_id=trial, case=case, engine=engine, exit_code=code,
                elapsed_seconds=30, status=status, alerts_count=count,
                detection_outcome="detected", detection_latency=0,
                error=None, dataset=domain)


class ReportingTests(unittest.TestCase):
    def test_counts_never_establish_scored_outcomes(self):
        for case in ("B0", "S1", "S2"):
            for count in (0, 12):
                with self.subTest(case=case, count=count):
                    r = matrix.normalize_observations([row(case=case, count=count)])[0]
                    self.assertEqual(r["detection_outcome"], "pending_review")
                    self.assertIsNone(r["detection_latency"])
                    self.assertTrue(r["review_required"])
                    self.assertEqual(r["legacy_detection_outcome"], "detected")
                    self.assertEqual(r["legacy_detection_latency"], 0)

    def test_failed_checks_and_preflight_are_inconclusive(self):
        for status, code in (("completed", 3), ("preflight_failed", 2), ("execution_failed", 2)):
            self.assertEqual(matrix.normalize_observations([row(status=status, code=code)])[0]["detection_outcome"], "inconclusive")

    def test_stricter_summary_invalidity_is_preserved(self):
        r = row()
        r["detection_outcome"] = "inconclusive"
        self.assertEqual(matrix.normalize_observations([r])[0]["detection_outcome"], "inconclusive")

    def test_report_uses_rows_and_keeps_repeats(self):
        rows = [row("first", count=7), row("repeat", count=9),
                row("snort", engine="snort", count=2, domain="snort"),
                row("failed", case="S2", status="preflight_failed", code=2)]
        with tempfile.TemporaryDirectory() as tmp:
            md, csv_path = Path(tmp) / "report.md", Path(tmp) / "report.csv"
            matrix.generate_markdown_report(rows, md, csv_path)
            text = md.read_text()
            comparison = text.split("## 2.")[1].split("## 3.")[0]
            for value in ("7 candidates", "9 candidates", "2 candidates", "`first`", "`repeat`"):
                self.assertIn(value, comparison)
            self.assertIn("No valid observation (preflight_failed", text)
            self.assertNotIn("51 alerts", text)
            self.assertNotIn("Primary Advantage", text)
            with csv_path.open() as f:
                saved = list(csv.DictReader(f))
            self.assertEqual(len(saved), 4)
            self.assertTrue(all(r["detection_latency"] == "" for r in saved))

    def test_summary_does_not_bypass_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            kit = Path(tmp)
            evidence = kit / "evidence" / "trial"
            evidence.mkdir(parents=True)
            for complete, issues, expected in ((True, [], "pending_review"), (False, [], "inconclusive"), (True, [{"kind": "poll_failed"}], "inconclusive")):
                summary = dict(status="completed", complete_scoring_window=complete,
                               alerts=dict(candidate_alerts_in_scoring_window=[{"alert_id": "a"}],
                                           detection_outcome="detected", detection_latency_seconds=0.1,
                                           observer_issues=issues))
                (evidence / "summary.json").write_text(json.dumps(summary))
                with patch.object(matrix.subprocess, "run") as run:
                    run.return_value.returncode = 0
                    result = matrix.run_single_trial(kit, kit / "config.json", "S1", "hybrid", "trial")
                self.assertEqual(result["detection_outcome"], expected)
                self.assertIsNone(result["detection_latency"])

    def test_report_only_never_contacts_hardware(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, md, dest = [Path(tmp) / p for p in ("old.csv", "report.md", "new.csv")]
            r = row()
            with source.open("w") as f:
                writer = csv.DictWriter(f, fieldnames=list(r))
                writer.writeheader()
                writer.writerow(r)
            args = ["matrix", "--report-only", str(source), "--output-report", str(md), "--output-csv", str(dest)]
            with patch.object(sys, "argv", args), patch.object(matrix, "http_json", side_effect=AssertionError("network")), patch.object(matrix, "run_single_trial", side_effect=AssertionError("trial")):
                matrix.main()
            self.assertTrue(md.exists())


class NarrativeTests(unittest.TestCase):
    def test_recorded_narrative_only_uses_verified_local_attack_shap(self):
        # Execute the actual alert-recording function without loading model artifacts.
        tree = ast.parse((KIT.parents[1] / "backend/main.py").read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "record_threat_alert")
        for method, target, eligible in (("tree_shap_per_flow", 1, True),
                                         ("global_rf_importance", 1, False),
                                         ("reference_sample_shap", 1, False),
                                         ("tree_shap_per_flow", 0, False)):
            values = [{"f": "src_pkts", "v": 0.2}]
            env = dict(ATTACK_CLASS_INDEX=1, engine=SimpleNamespace(current_model="omni", execution_mode="hybrid"),
                       compute_shap_explanation=lambda _: dict(values=values, method=method, target_class=target),
                       generate_attack_narrative=narrative.generate_attack_narrative,
                       classify_attack_type=narrative.classify_attack_type,
                       compute_lime_explanation_for_packet=lambda _: dict(values=[], target_class=None),
                       classify_threat_level=lambda _: "High", uuid4=lambda: "id", utc_now=lambda: "time",
                       insert_alert=lambda _: None)
            exec(compile(ast.Module(body=[function], type_ignores=[]), "backend/main.py", "exec"), env)
            alert = env["record_threat_alert"]({}, SimpleNamespace(columns=["src_pkts"]), 0.9, "live_hardware")
            self.assertEqual("separate RF feature explanation" in alert["explanation_meta"]["reason"], eligible)
            self.assertIn("hybrid (omni)", alert["explanation_meta"]["reason"])
            self.assertEqual(alert["attack_type_source"], "heuristic_behavioral")

    def test_single_failed_connection_is_not_scanning(self):
        label, reason = narrative.classify_attack_type(dict(conn_state_REJ=1, src_pkts=2, duration=0.5, dst_port=22))
        self.assertEqual(label, "unanswered or rejected connection (heuristic)")
        self.assertIn("correlated attempts", reason)

    def test_reset_service_connection_does_not_claim_repetition(self):
        label, reason = narrative.classify_attack_type(dict(conn_state_RSTO=1, src_pkts=8, duration=8, dst_port="22"))
        self.assertEqual(label, "reset or rejected service connection (heuristic)")
        self.assertNotIn("repeated connection attempts", reason)
        self.assertIn("require service logs", reason)

    def test_missing_sni_does_not_establish_suspicious_tls(self):
        label, reason = narrative.classify_attack_type(dict(proto="TCP", dst_port=443, conn_state_SF=1))
        self.assertEqual(label, "model-flagged flow anomaly")
        self.assertNotIn("command-and-control", reason)

    def test_high_rate_is_observation_not_verified_dos(self):
        label, reason = narrative.classify_attack_type(dict(duration=0.01, src_pkts=3))
        self.assertEqual(label, "high packet rate (heuristic)")
        self.assertIn("service impact is unverified", reason)

    def test_narrative_labels_rf_attributions_and_requires_evidence(self):
        text = narrative.generate_attack_narrative(dict(src_ip="a", dst_ip="b"),
                  shap_values=[dict(f="src_pkts", v=-0.2), dict(f="duration", v=0)],
                  confidence=0.9, model_type="hybrid (omni)")
        self.assertIn("opposes the RF attack-class output", text)
        self.assertIn("is neutral toward the RF attack-class output", text)
        self.assertIn("RF SHAP does not explain the CNN", text)
        self.assertIn("independent packet or service evidence", text)
        self.assertNotIn("this is classified as", text)


if __name__ == "__main__":
    unittest.main()
