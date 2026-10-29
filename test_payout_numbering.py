"""Payout references remain sequential and independent of copied form metadata."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import app as backend
from payout_numbering import ensure_payout_numbering, payout_number, payout_number_repair_plan


def matches(row, query):
    for field, expected in query.items():
        if isinstance(expected, dict):
            if "$in" in expected and row.get(field) not in expected["$in"]:
                return False
        elif row.get(field) != expected:
            return False
    return True


class PayoutNumberingTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"id": value, "payout_number": "SP-202610-0013", "status": "Paid" if value == 13 else "Pending Approval",
                      "created_at": datetime(2026, 10, 8 if value == 13 else 29),
                      "amount": 8000 if value == 13 else 25000, "paid_amount": 8000 if value == 13 else 0,
                      "stakeholder_id": value, "payout_type": "Profit Distribution"} for value in [13, 14, 15, 16]]
        self.payables = [{"id": value, "source_module": "Stakeholder Payout", "source_id": value,
                          "source_reference": "SP-202610-0013", "paid_amount": 8000 if value == 13 else 0}
                         for value in [13, 14, 15, 16]]
        self.counter = 1
        self.lock = RLock()
        self.db = MagicMock()
        self.db.stakeholder_payout_receipts.find.side_effect = lambda *args: self.snapshot()
        self.db.stakeholder_payout_receipts.find_one.side_effect = lambda query, *args: next((deepcopy(row) for row in self.snapshot() if matches(row, query)), None)
        self.db.stakeholder_payout_receipts.update_one.side_effect = lambda query, update: self.update(self.rows, query, update)
        self.db.stakeholder_payout_receipts.insert_one.side_effect = self.insert
        self.db.payables.update_many.side_effect = lambda query, update: self.update(self.payables, query, update)
        self.db.counters.update_one.side_effect = self.floor_counter
        self.now = datetime(2026, 10, 29)

    def snapshot(self):
        with self.lock:
            return deepcopy(self.rows)

    def floor_counter(self, query, update, **kwargs):
        with self.lock:
            self.counter = max(self.counter, update["$max"]["sequence_value"])

    def next_id(self, name):
        with self.lock:
            self.counter += 1
            return self.counter

    def insert(self, doc):
        with self.lock:
            if any(row["id"] == doc["id"] or row["payout_number"] == doc["payout_number"] for row in self.rows):
                raise backend.pymongo.errors.DuplicateKeyError("duplicate receipt")
            self.rows.append(deepcopy(doc))

    def update(self, rows, query, update):
        with self.lock:
            modified = 0
            for row in rows:
                if not matches(row, query):
                    continue
                row.update(deepcopy(update.get("$set", {})))
                for field, value in update.get("$addToSet", {}).items():
                    values = row.setdefault(field, [])
                    if value not in values:
                        values.append(value)
                modified += 1
            return SimpleNamespace(modified_count=modified)

    def test_actual_duplicate_pattern_preserves_original_and_assigns_14_15_16(self):
        plan, floor = payout_number_repair_plan(self.rows, self.now)
        self.assertEqual([(change["id"], change["new_number"]) for change in plan], [
            (14, "SP-202610-0014"), (15, "SP-202610-0015"), (16, "SP-202610-0016")])
        self.assertEqual(floor, 16)
        before = deepcopy(self.rows)
        ensure_payout_numbering(self.db, self.now)
        for original, updated in zip(before, self.rows):
            for field, value in original.items():
                if field != "payout_number":
                    self.assertEqual(updated[field], value, field)
        self.assertEqual(self.rows[0], before[0])
        self.assertEqual([item["source_reference"] for item in self.payables], [f"SP-202610-{value:04d}" for value in [13, 14, 15, 16]])
        self.assertEqual(self.payables[0]["paid_amount"], 8000)
        self.assertEqual(self.counter, 16)
        self.db.stakeholder_payout_receipts.create_index.assert_any_call("payout_number", unique=True, name="unique_payout_receipt_number")

    def test_repair_is_idempotent_and_keeps_month_and_number_history(self):
        ensure_payout_numbering(self.db, self.now)
        self.assertEqual(ensure_payout_numbering(self.db, datetime(2026, 11, 1)), [])
        self.assertEqual(self.rows[1]["previous_payout_numbers"], ["SP-202610-0013"])
        self.assertEqual(self.rows[1]["payout_number"], "SP-202610-0014")

    def test_missing_numbers_and_collisions_are_assigned_unused_references(self):
        rows = [{"id": 2, "payout_number": "SP-202610-0014"},
                {"id": 13, "payout_number": "SP-202610-0013"},
                {"id": 14, "payout_number": "SP-202610-0013"},
                {"id": 15, "created_at": datetime(2026, 9, 1)}]
        plan, floor = payout_number_repair_plan(rows, self.now)
        self.assertEqual(len({item["new_number"] for item in plan}), len(plan))
        self.assertTrue(next(item for item in plan if item["id"] == 15)["new_number"].startswith("SP-202609-"))
        self.assertGreaterEqual(floor, 16)

    def test_ambiguous_duplicate_ids_are_not_repaired(self):
        with self.assertRaises(ValueError):
            payout_number_repair_plan([{**self.rows[0]}, {**self.rows[0]}], self.now)

    def test_server_ignores_copied_number_and_sequence_continues_from_existing(self):
        with patch.object(backend, "get_db", return_value=self.db), \
                patch.object(backend, "require_treasury_access", return_value={"id": 7}), \
                patch.object(backend, "payout_recipient_payload", return_value=({"stakeholder_id": 1, "recipient_name": "Test"}, None)), \
                patch.object(backend, "get_next_sequence_value", side_effect=self.next_id), \
                patch.object(backend, "log_treasury_action"), \
                patch.object(backend, "attach_pending_approval_display"):
            client = backend.app.test_client()
            for expected_id in [17, 18, 19]:
                response = client.post("/api/treasury/stakeholder-payouts", json={
                    "payout_number": "SP-202610-0013", "amount": 25000, "status": "Draft"})
                self.assertEqual(response.status_code, 200, response.json)
                self.assertEqual(response.json["payout"]["id"], expected_id)
                self.assertEqual(response.json["payout"]["payout_number"], payout_number(expected_id))
            self.assertEqual(len({row["payout_number"] for row in self.rows}), len(self.rows))

    def test_concurrent_creation_allocates_unique_sequential_numbers(self):
        ensure_payout_numbering(self.db, self.now)
        def create(_):
            ensure_payout_numbering(self.db, self.now)
            receipt_id = self.next_id("stakeholder_payout_receipts")
            self.insert({"id": receipt_id, "payout_number": payout_number(receipt_id, self.now)})
            return receipt_id
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(create, range(24)))
        self.assertEqual(sorted(ids), list(range(17, 41)))
        self.assertEqual(len({row["payout_number"] for row in self.rows}), len(self.rows))

    def test_manual_existing_reference_is_retained_and_counter_never_moves_backwards(self):
        self.rows.append({"id": 20, "payout_number": "SP-202610-0050"})
        self.counter = 90
        ensure_payout_numbering(self.db, self.now)
        self.assertEqual(self.counter, 90)
        self.assertEqual(self.rows[-1]["payout_number"], "SP-202610-0050")

    def test_existing_nonunique_indexes_are_preserved_and_unique_ones_are_reused(self):
        self.db.stakeholder_payout_receipts.index_information.return_value = {
            "id_1": {"key": [("id", 1)], "background": True},
            "payout_number_1": {"key": [("payout_number", 1)], "unique": True},
        }
        ensure_payout_numbering(self.db, self.now)
        self.db.stakeholder_payout_receipts.create_index.assert_called_once_with("id", unique=True, name="unique_payout_receipt_id")
        self.db.stakeholder_payout_receipts.drop_index.assert_not_called()


if __name__ == "__main__":
    unittest.main()
