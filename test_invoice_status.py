"""Invoice stage regressions using an in-memory database; no real payments are posted."""

from copy import deepcopy
import unittest
from unittest.mock import MagicMock, patch

import app as backend


class InvoiceStatusTests(unittest.TestCase):
    def setUp(self):
        self.invoice = {
            "id": 8, "invoice_number": "SC202610001", "status": "Approved",
            "customer_id": 3, "project_id": 4, "account_id": 5,
            "issue_date": "2026-10-25", "due_date": "2026-11-06",
            "currency": "INR", "subtotal": 100, "tax_rate": 18,
            "tax_amount": 18, "total_amount": 118, "amount_paid": 0,
            "items": [{"description": "Service", "qty": 1, "price": 100}],
            "notes": "Original terms", "payment_details_snapshot": {"bank_name": "Original Bank"},
        }
        self.transactions = []
        self.db = MagicMock()
        self.db.invoices.find_one.side_effect = lambda query: deepcopy(self.invoice) if query["id"] == 8 else None
        self.db.invoices.update_one.side_effect = lambda query, update: self.invoice.update(deepcopy(update["$set"]))
        self.db.invoices.insert_one.side_effect = lambda doc: self.invoice.update(deepcopy(doc))
        self.db.invoices.aggregate.side_effect = lambda pipeline: [deepcopy(self.invoice)]
        self.db.system_settings.find_one.return_value = None
        self.db.transactions.find.side_effect = lambda query: [deepcopy(tx) for tx in self.transactions
            if tx["invoice_id"] == query["invoice_id"] and tx.get("status") != "Reversed"]
        for name, value in [
            ("get_db", self.db), ("audit_actor", ({"id": 7}, 7, "Test User")),
            ("get_next_sequence_value", 8),
        ]:
            patcher = patch.object(backend, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ["require_finance_access", "log_activity_async"]:
            patcher = patch.object(backend, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        self.client = backend.app.test_client()

    def save(self, status, **fields):
        return self.client.put("/api/finance/invoices/8/status", json={"status": status, **fields})

    def test_paid_stage_survives_read_and_reconciliation_without_editing_invoice(self):
        before = deepcopy(self.invoice)
        response = self.save("Paid")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["invoice"]["status"], "Paid")
        self.assertEqual(response.json["invoice"]["amount_paid"], 118)
        self.assertEqual(self.invoice["manual_amount_paid"], 118)
        self.assertEqual(self.client.get("/api/finance/invoices/8").json["invoice"]["status"], "Paid")
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Paid")
        self.assertEqual(self.invoice["amount_paid"], 118)
        for key in before.keys() - {"status", "amount_paid"}:
            self.assertEqual(self.invoice[key], before[key], key)
        self.assertEqual(self.invoice["modified_by_id"], 7)
        self.log_activity_async.assert_called_once()
        self.db.transactions.insert_one.assert_not_called()

    def test_partial_payments_can_be_updated_then_completed(self):
        for amount in [30, 70.25]:
            response = self.save("Partially Paid", amount_paid=amount)
            self.assertEqual(response.status_code, 200)
            backend.sync_invoice_status_and_paid(self.db, 8)
            self.assertEqual(self.invoice["status"], "Partially Paid")
            self.assertEqual(self.invoice["amount_paid"], amount)
        self.assertEqual(self.save("Paid").status_code, 200)
        self.assertEqual(self.invoice["amount_paid"], 118)
        self.assertEqual(self.save("Approved").status_code, 200)
        self.assertEqual(self.invoice["amount_paid"], 0)

    def test_draft_sent_and_approval_transitions(self):
        self.invoice["status"] = "Draft"
        for status in ["Sent", "Draft", "Approved"]:
            self.assertEqual(self.save(status).status_code, 200)
            self.assertEqual(self.invoice["status"], status)
        for status in ["Draft", "Sent"]:
            self.assertEqual(self.save(status).status_code, 400)
            self.assertEqual(self.invoice["status"], "Approved")

    def test_invalid_payments_and_unknown_stages_do_not_write(self):
        for amount in [None, "", "bad", "NaN", "Infinity", True, -1, 0, 118, 119]:
            with self.subTest(amount=amount):
                self.assertEqual(self.save("Partially Paid", amount_paid=amount).status_code, 400)
        for status in [None, "Fully Paid", "Unknown", []]:
            with self.subTest(status=status):
                self.assertEqual(self.save(status).status_code, 400)
        self.db.invoices.update_one.assert_not_called()

    def test_stage_endpoint_rejects_invoice_edits(self):
        self.assertEqual(self.save("Paid", total_amount=1).status_code, 400)
        self.db.invoices.update_one.assert_not_called()

    def test_existing_ledger_receipts_are_not_counted_twice(self):
        self.transactions = [{"invoice_id": 8, "total_amount": 30},
                             {"invoice_id": 8, "amount": 40, "status": "Reversed"}]
        self.assertEqual(self.save("Partially Paid", amount_paid=50).status_code, 200)
        self.assertEqual(self.invoice["manual_amount_paid"], 20)
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["amount_paid"], 50)
        self.transactions.append({"invoice_id": 8, "amount": 68})
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Paid")
        self.assertEqual(self.invoice["amount_paid"], 118)
        self.transactions[-1]["status"] = "Reversed"
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Partially Paid")
        self.assertEqual(self.invoice["amount_paid"], 50)

    def test_stage_cannot_erase_linked_payments(self):
        self.transactions = [{"invoice_id": 8, "amount": 60}]
        for status, fields in [("Approved", {}), ("Partially Paid", {"amount_paid": 40})]:
            response = self.save(status, **fields)
            self.assertEqual(response.status_code, 400)
            self.assertIn("linked ledger payments", response.json["error"])
        self.db.invoices.update_one.assert_not_called()
        self.assertEqual(self.save("Paid").status_code, 200)
        self.assertEqual(self.invoice["manual_amount_paid"], 58)

    def test_void_is_preserved_during_reconciliation(self):
        self.transactions = [{"invoice_id": 8, "amount": 60}]
        self.assertEqual(self.save("Cancelled").status_code, 200)
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Cancelled")
        self.assertEqual(self.invoice["amount_paid"], 60)

    def test_legacy_invoices_still_follow_receipts_and_reversals(self):
        self.transactions = [{"invoice_id": 8, "total_amount": 118}]
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Paid")
        self.transactions[0]["status"] = "Reversed"
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Approved")
        self.assertEqual(self.invoice["amount_paid"], 0)

    def test_create_and_general_update_preserve_manual_payments(self):
        payload = {**self.invoice, "status": "Partially Paid", "amount_paid": 45}
        self.assertEqual(self.client.post("/api/finance/invoices", json=payload).status_code, 200)
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["amount_paid"], 45)
        payload = {**self.invoice, "status": "Paid"}
        self.assertEqual(self.client.put("/api/finance/invoices/8", json=payload).status_code, 200)
        backend.sync_invoice_status_and_paid(self.db, 8)
        self.assertEqual(self.invoice["status"], "Paid")
        self.assertEqual(self.invoice["amount_paid"], 118)

    def test_approved_invoice_core_edit_is_still_rejected(self):
        response = self.client.put("/api/finance/invoices/8", json={**self.invoice, "notes": "Changed"})
        self.assertEqual(response.status_code, 400)
        self.db.invoices.update_one.assert_not_called()

    def test_missing_invoice_and_finance_access(self):
        self.assertEqual(self.client.put("/api/finance/invoices/999/status", json={"status": "Paid"}).status_code, 404)
        self.require_finance_access.side_effect = lambda: backend.abort(403)
        self.assertEqual(self.save("Paid").status_code, 403)
        self.db.invoices.update_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
