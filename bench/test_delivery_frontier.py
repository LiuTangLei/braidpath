"""Offline ledger contracts. Synthetic fixtures are not performance evidence."""
import copy
import json
from pathlib import Path
import random
import tempfile
import unittest

from bench.delivery_frontier import (
    EvidenceError, audit_campaign, closed_endpoint, main, read_json,
    record_ledger, timeline_census,
)


def direction():
    r = {key: 0 for key in [
        "application_received", "application_flow_limit_dropped", "application_oversize_dropped",
        "application_unavailable_dropped", "ingress_queue_full_dropped", "ingress_queue_closed_dropped",
        "ingress_shutdown_dropped", "ingress_queue_enqueued", "sender_queue_enqueued",
        "sender_queue_full_dropped", "sender_queue_closed_dropped", "input_shutdown_dropped",
        "sender_input_consumed", "encoding_dropped", "original_packets_received",
        "original_records_delivered", "fec_records_recovered", "repair_symbols_received",
        "deduplicated", "receiver_queue_full_dropped", "invalid_symbols_dropped",
        "udp_target_delivered", "udp_target_send_dropped"]}
    r.update(application_received=1000, ingress_queue_full_dropped=100,
             ingress_queue_enqueued=900, sender_queue_full_dropped=200,
             sender_queue_enqueued=700, sender_input_consumed=690, input_shutdown_dropped=10)
    s = dict(originals_ingress_expired_dropped=20, originals_generated=670,
             originals_queue_full_dropped=150, originals_enqueued=520,
             originals_quinn_admitted=500, originals_expired_dropped=10,
             originals_shutdown_dropped=10, repairs_generated=80, repairs_enqueued=60,
             repairs_queue_full_dropped=20, repairs_quinn_admitted=50,
             repairs_budget_skipped=5, repairs_expired_dropped=3, repairs_shutdown_dropped=2)
    return {"records": r, "symbols": s}


def endpoint(role):
    d = direction()
    return {"role": role, "final": True, "error": None, "outcome": "stopped",
            "stats": {"shutdown_complete": True, "drain_incomplete": False,
                      "omitted_session_scopes": 0, "evicted_session_scopes": 0,
                      "omitted_path_scopes": 0, "paths": {},
                      "sessions": {"test-session": {"server_to_client": copy.deepcopy(d)}},
                      "directions": {"server_to_client": d}}}


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def campaign(root, complete=True):
    save(root / "registration.json", {"conditions": {"order": [
        {"window": "window_a", "variant": "baseline"},
        {"window": "window_b", "variant": "candidate"}]}})
    save(root / "wrapper-completion.json", {
        "status": "complete" if complete else "protection_failed",
        "continuous_protection_passed": complete})
    for label in ["window_a", "window_b"] if complete else ["window_a"]:
        w = root / label
        save(w / "metrics.json", {"bulk": {"population": 800}, "interactive": {"requested": 4}})
        save(w / "completion.json", {"error": None, "cleanup_errors": [], "cleanup_unconfirmed": []})
        save(w / "server/stats.json", endpoint("server"))
        save(w / "client/stats.json", endpoint("client"))


class LedgerTests(unittest.TestCase):
    def test_optional_prequeue_repair_pruning_never_changes_original_population(self):
        d = direction()
        before = record_ledger(d)
        d['symbols'].update(repairs_locally_unrecoverable=8,
            repairs_locally_unrecoverable_bytes=8000,
            repairs_locally_unrecoverable_skipped=8,
            repairs_locally_unrecoverable_skipped_bytes=8000)
        d['symbols']['repairs_generated'] += 8
        after = record_ledger(d)
        self.assertEqual(before['nodes_records'], after['nodes_records'])
        self.assertEqual(before['dispositions_records'], after['dispositions_records'])
        self.assertEqual(after['repair_symbols_separate']['repairs_locally_unrecoverable_skipped'], 8)

    def test_dispositions_close_without_mixing_repairs(self):
        result = record_ledger(direction())
        self.assertEqual(result["pre_encoding_disposed_records"], 330)
        self.assertEqual(result["encoded_original_disposed_records"], 170)
        self.assertEqual(result["all_local_first_pass_disposed_records"], 500)
        self.assertEqual(result["api_original_admission_fraction"], .5)
        self.assertTrue(all(row["residual"] == 0 for row in result["balances"]))
        self.assertFalse(result["interpretation"]["api_admission_is_wire_transmission"])
        self.assertFalse(result["interpretation"]["local_disposition_is_proof_of_cpu_bottleneck"])

    def test_repair_counts_do_not_change_original_population(self):
        d = direction()
        before = record_ledger(d)
        for key in d["symbols"]:
            if key.startswith("repairs_"):
                d["symbols"][key] *= 100
        after = record_ledger(d)
        for key in ["pre_encoding_disposed_records", "api_original_admission_fraction"]:
            self.assertEqual(before[key], after[key])

    def test_reconstruction_is_not_subtracted_from_local_disposals(self):
        d = direction()
        d["records"]["fec_records_recovered"] = 400
        self.assertEqual(record_ledger(d)["all_local_first_pass_disposed_records"], 500)

    def test_zero_population_is_unknown_fraction_not_zero_capacity(self):
        d = direction()
        for fields in d.values():
            for key in fields:
                fields[key] = 0
        result = record_ledger(d)
        self.assertIsNone(result["api_original_admission_fraction"])

    def test_missing_negative_boolean_and_fractional_counts_fail(self):
        for value in [None, -1, True, 1.5]:
            d = direction()
            d["records"]["application_received"] = value
            with self.assertRaises(EvidenceError):
                record_ledger(d)
        d = direction()
        del d["symbols"]["originals_generated"]
        with self.assertRaises(EvidenceError):
            record_ledger(d)

    def test_unattributed_encoding_errors_are_not_forced_to_close(self):
        d = direction()
        d["records"]["encoding_dropped"] = 1
        with self.assertRaisesRegex(EvidenceError, "not record-attributable"):
            record_ledger(d)

    def test_each_stage_must_close_not_just_total(self):
        d = direction()
        d["records"]["ingress_queue_enqueued"] += 1
        with self.assertRaisesRegex(EvidenceError, "does not close"):
            record_ledger(d)

    def test_exact_partition_with_100_deterministic_distributions(self):
        rng = random.Random(193)
        for _ in range(100):
            d = direction()
            r, s = d["records"], d["symbols"]
            values = [rng.randrange(100) for _ in range(7)]
            (r["ingress_queue_full_dropped"], r["sender_queue_full_dropped"],
             r["input_shutdown_dropped"], s["originals_ingress_expired_dropped"],
             s["originals_queue_full_dropped"], s["originals_expired_dropped"],
             s["originals_shutdown_dropped"]) = values
            r["application_received"] = sum(values) + 50
            r["ingress_queue_enqueued"] = r["application_received"] - values[0]
            r["sender_queue_enqueued"] = r["ingress_queue_enqueued"] - values[1]
            r["sender_input_consumed"] = r["sender_queue_enqueued"] - values[2]
            s["originals_generated"] = r["sender_input_consumed"] - values[3]
            s["originals_enqueued"] = s["originals_generated"] - values[4]
            s["originals_quinn_admitted"] = 50
            self.assertEqual(record_ledger(d)["all_local_first_pass_disposed_records"], sum(values))


class CampaignTests(unittest.TestCase):
    def test_partial_stays_partial_and_attempted_is_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign(root, False)
            save(root / "window_b/jobs.json", [])
            result = audit_campaign(root)
            self.assertEqual(result["completed_business_windows"], 1)
            self.assertEqual(result["wrapper_status"], "protection_failed")
            self.assertFalse(result["continuous_protection_passed"])
            self.assertTrue(result["windows"][1]["has_jobs"])
            self.assertIsNone(result["windows"][0]["network_loss_probability"])

    def test_aggregate_and_session_ledger_are_not_added(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign(root)
            result = audit_campaign(root)
            nodes = result["windows"][0]["sender"]["nodes_records"]
            self.assertEqual(nodes["application_received"], 1000)
            self.assertFalse(result["source_binary_and_collector_hash_chain_revalidated"])
            self.assertGreater(len(result["input_sha256"]), 5)

    def test_wrong_session_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign(root)
            client = endpoint("client")
            client["stats"]["sessions"]["other"] = client["stats"]["sessions"].pop("test-session")
            save(root / "window_a/client/stats.json", client)
            with self.assertRaisesRegex(EvidenceError, "sessions do not match"):
                audit_campaign(root)

    def test_missing_completion_is_not_a_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign(root)
            save(root / "window_a/completion.json", {})
            with self.assertRaisesRegex(EvidenceError, "missing window completion"):
                audit_campaign(root)

    def test_unclean_endpoint_or_incomplete_census_is_rejected(self):
        for field, value in [("drain_incomplete", True), ("shutdown_complete", False),
                             ("omitted_path_scopes", 1), ("evicted_session_scopes", 1)]:
            e = endpoint("server")
            e["stats"][field] = value
            with self.assertRaises(EvidenceError):
                closed_endpoint(e, "server")

    def test_duplicate_windows_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign(root)
            for labels in [["window_a", "window_a"], ["../outside"]]:
                save(root / "registration.json", {"conditions": {"order": [
                    {"window": label, "variant": "baseline"} for label in labels]}})
                with self.assertRaises(EvidenceError):
                    audit_campaign(root)

    def test_output_cannot_replace_existing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign(root)
            out = root / "report.json"
            out.write_text("keep me")
            with self.assertRaises(FileExistsError):
                main(["--campaign", str(root), "--output", str(out)])
            self.assertEqual(out.read_text(), "keep me")

    def test_duplicate_json_keys_and_nonfinite_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            for raw in ['{"x":1,"x":2}', '{"x":NaN}']:
                path.write_text(raw)
                with self.assertRaises(EvidenceError):
                    read_json(path, {})

    def test_timeline_deduplicates_control_samples_without_claiming_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stats.jsonl"
            control = {"at_us": 10, "generation": 1, "offered_backlog": True,
                       "transport_blocked": False, "queue_delay_ms": 2}
            row = {"stats": {"paths": {"s/0": {"connection_id": 3,
                                               "adaptive": {"last_control": control}}}}}
            first = json.dumps(row)
            control["at_us"] = 20
            path.write_text(first + "\n" + first + "\n" + json.dumps(row) + "\n")
            result = timeline_census(path)
            self.assertEqual(result["paths"]["s/0"]["distinct_control_snapshots"], 2)
            self.assertEqual(result["paths"]["s/0"]["backlog_with_api_buffer_not_full"], 2)
            self.assertFalse(result["limiter_owner_identified"])


if __name__ == "__main__":
    unittest.main()
