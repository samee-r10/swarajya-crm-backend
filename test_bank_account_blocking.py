"""Bank blocks are checked before financial writes. All data stays in memory."""

from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import app as backend


def matches(row, query):
    for key, expected in query.items():
        value = row.get(key)
        if isinstance(expected, dict):
            if "$in" in expected and value not in expected["$in"]:
                return False
            if "$ne" in expected and value == expected["$ne"]:
                return False
        elif expected != value:
            return False
    return True


class Cursor(list):
    def sort(self, *args):
        return self

    def limit(self, count):
        return Cursor(self[:count])


class BankAccountBlockingTests(unittest.TestCase):
    def setUp(self):
        self.bank = {"id": 1, "status": "Active", "account_name": "Company Bank", "account_number": "123456",
                     "bank_name": "Bank", "currency": "INR", "opening_balance": 1000}
        self.banks = [self.bank, {**self.bank, "id": 2, "account_number": "987654", "account_name": "Second Bank"}]
        self.movements = []
        self.payments = []
        self.revenue = {"id": 8, "amount": 100, "is_settled": False}
        self.payable = {"id": 9, "status": "Pending", "outstanding_amount": 100, "original_amount": 100,
                        "source_module": "Expense Log", "payable_number": "PAY-9"}
        self.db = MagicMock()
        for name, rows in [("company_bank_accounts", self.banks), ("company_bank_transactions", self.movements),
                           ("payable_payments", self.payments)]:
            collection = getattr(self.db, name)
            collection.find.side_effect = lambda query, *args, rows=rows: Cursor(deepcopy([row for row in rows if matches(row, query)]))
            collection.find_one.side_effect = lambda query, *args, rows=rows, **kwargs: next((deepcopy(row) for row in rows if matches(row, query)), None)
            collection.update_one.side_effect = lambda query, update, rows=rows: self.update(rows, query, update)
            collection.insert_one.side_effect = lambda doc, rows=rows: rows.append(deepcopy(doc))
        self.db.company_bank_transactions.aggregate.side_effect = self.aggregate_movements
        self.db.payables.find.return_value = []
        self.db.payables.find_one.return_value = self.payable
        self.db.treasury_revenue.find_one.return_value = self.revenue
        self.db.loan_accounts.find_one.return_value = {"id": 5, "bank_account_id": 1, "total_loan_amount": 1000}
        self.db.transactions.find_one.return_value = None
        self.db.transactions.find.return_value = []
        for name, value in [("get_db", self.db), ("require_treasury_access", {"id": 7}),
                            ("get_next_sequence_value", 99), ("check_accounting_period_lock", (False, None, None)),
                            ("audit_actor", ({"id": 7}, 7, "Test User")),
                            ("loan_totals", {"total_disbursed_amount": 0})]:
            patcher = patch.object(backend, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        for name in ["log_treasury_action", "log_activity_async", "require_finance_access", "ensure_default_accounts"]:
            patcher = patch.object(backend, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        self.client = backend.app.test_client()

    @staticmethod
    def update(rows, query, update):
        for row in rows:
            if matches(row, query):
                row.update(deepcopy(update.get("$set", {})))
        return SimpleNamespace(matched_count=1)

    def aggregate_movements(self, pipeline):
        rows = self.movements
        for stage in pipeline:
            if "$match" in stage:
                rows = [row for row in rows if matches(row, stage["$match"])]
        group = next(stage["$group"] for stage in pipeline if "$group" in stage)
        ids = {row.get("bank_account_id") for row in rows} if group["_id"] else {None}
        return [{"_id": key,
                 "inflow": sum(row.get("inflow", 0) for row in rows if key is None or row.get("bank_account_id") == key),
                 "outflow": sum(row.get("outflow", 0) for row in rows if key is None or row.get("bank_account_id") == key)} for key in ids]

    def status(self, status):
        return self.client.put("/api/treasury/bank-accounts/1/status", json={"status": status})

    def test_block_and_unblock_are_persisted_and_audited(self):
        self.assertEqual(self.status("Blocked").status_code, 200)
        self.assertEqual(self.bank["status"], "Blocked")
        self.assertEqual(self.bank["modified_by_id"], 7)
        self.assertEqual(self.movements, [])
        self.assertEqual(self.status("Active").status_code, 200)
        self.assertEqual(self.bank["status"], "Active")
        self.assertEqual(self.log_treasury_action.call_count, 2)

    def test_statements_balances_and_management_list_remain_readable(self):
        self.bank["status"] = "Blocked"
        for suffix in ["", "/statement", "/balance"]:
            response = self.client.get("/api/treasury/bank-accounts/1" + suffix)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["bank_account"]["status"], "Blocked")
        listing = self.client.get("/api/treasury/bank-accounts").json
        self.assertEqual(len(listing["bank_accounts"]), 2)
        self.assertEqual(listing["stats"]["available_balance"], 1000)

    def test_invalid_status_and_permission_do_not_change_account(self):
        for status in ["Unknown", "Inactive", None, [], "active"]:
            self.assertEqual(self.status(status).status_code, 400)
        response = self.client.put("/api/treasury/bank-accounts/999/status", json={"status": "Blocked"})
        self.assertEqual(response.status_code, 404)
        self.require_treasury_access.side_effect = lambda: backend.abort(403)
        self.assertEqual(self.status("Blocked").status_code, 403)
        self.assertEqual(self.bank["status"], "Active")

    def test_stale_edit_cannot_silently_unblock_account(self):
        self.bank["status"] = "Blocked"
        response = self.client.put("/api/treasury/bank-accounts/1", json={**self.bank, "status": "Active"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Use Unblock", response.json["error"])
        self.assertEqual(self.bank["status"], "Blocked")
        self.assertEqual(self.client.put("/api/treasury/bank-accounts/1", json={"account_name": "Updated"}).status_code, 200)
        self.assertEqual(self.bank["status"], "Blocked")

    def test_blocked_and_inactive_banks_reject_inflows_and_outflows(self):
        for status in ["Blocked", "Inactive"]:
            self.bank["status"] = status
            for direction in ["inflow", "outflow"]:
                with self.assertRaisesRegex(ValueError, status.lower()):
                    backend.record_company_bank_movement(self.db, 1, "Payment", 10, direction=direction)
        self.assertEqual(self.movements, [])

    def test_unblocked_and_legacy_banks_can_record_movements(self):
        self.status("Blocked")
        self.status("Active")
        backend.record_company_bank_movement(self.db, 1, "Payment", 10, direction="outflow")
        self.assertEqual(self.movements[0]["outflow"], 10)
        self.bank.pop("status")
        backend.record_company_bank_movement(self.db, 1, "Receipt", 20, direction="inflow")
        self.assertEqual(self.movements[1]["inflow"], 20)

    def test_stale_payable_selection_is_rejected_before_payment_insert(self):
        self.bank["status"] = "Blocked"
        for source in ["Expense Log", "HR Salary", "Stakeholder Payout"]:
            self.payable["source_module"] = source
            response = self.client.post("/api/treasury/payables/9/payments", json={"bank_account_id": 1, "payment_amount": 100})
            self.assertEqual(response.status_code, 400)
            self.assertIn("blocked", response.json["error"])
        self.assertEqual(self.payments, [])
        self.db.payables.update_one.assert_not_called()
        self.assertEqual(self.movements, [])

    def test_stale_revenue_selection_does_not_mark_revenue_settled(self):
        self.bank["status"] = "Blocked"
        response = self.client.put("/api/treasury/revenue/8", json={"bank_account_id": 1})
        self.assertEqual(response.status_code, 400)
        self.assertIn("blocked", response.json["error"])
        self.db.treasury_revenue.update_one.assert_not_called()
        self.db.treasury_payouts.insert_one.assert_not_called()
        self.assertEqual(self.movements, [])

    def test_transfers_cannot_use_blocked_source_or_destination(self):
        self.bank["status"] = "Blocked"
        for source, destination in [(1, 2), (2, 1)]:
            response = self.client.post("/api/treasury/fund-transfers", json={
                "from_bank_account_id": source, "to_bank_account_id": destination, "transfer_amount": 100})
            self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/treasury/fund-transfers", json={"transfer_all": True, "to_bank_account_id": 1})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.movements, [])

    def test_transfer_all_skips_blocked_sources_and_selector_excludes_them(self):
        self.bank["status"] = "Blocked"
        self.assertEqual(len(self.client.get("/api/treasury/fund-transfers").json["bank_accounts"]), 1)
        response = self.client.post("/api/treasury/fund-transfers", json={"transfer_all": True, "to_bank_account_id": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["transfers"], [])
        self.assertEqual(self.movements, [])

    def test_available_company_fund_never_falls_back_to_blocked_banks(self):
        self.bank["status"] = "Blocked"
        self.banks[1]["status"] = "Inactive"
        self.assertEqual(backend.company_fund_available(self.db), 0)

    def test_loan_and_finance_posting_reject_blocked_bank_before_inserting(self):
        self.bank["status"] = "Blocked"
        with self.assertRaisesRegex(ValueError, "blocked"):
            backend.create_finance_transaction(self.db, {"bank_account_id": 1, "amount": 100})
        response = self.client.post("/api/treasury/loans/5/disbursements", json={"amount": 100})
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/finance/transactions", json={"bank_account_id": 1, "amount": 100})
        self.assertEqual(response.status_code, 400)
        self.db.transactions.insert_one.assert_not_called()
        self.db.loan_disbursements.insert_one.assert_not_called()

    def test_edit_delete_and_reverse_cannot_change_a_blocked_bank_transaction(self):
        self.bank["status"] = "Blocked"
        self.db.transactions.find_one.return_value = {"id": "TXN1", "bank_account_id": 1}
        for method, url in [("put", "/api/finance/transactions/TXN1"), ("delete", "/api/finance/transactions/TXN1"),
                            ("post", "/api/finance/transactions/TXN1/reverse")]:
            response = getattr(self.client, method)(url, json={"amount": 100})
            self.assertEqual(response.status_code, 400)
        self.db.transactions.update_one.assert_not_called()
        self.db.transactions.delete_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
