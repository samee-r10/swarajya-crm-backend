"""Paid sales invoice selection and posting; no external database or actual entries."""

from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import app as backend
from finance_sales import is_sales_revenue_account, invoice_posting_defaults


def matches(row, query):
    for field, expected in query.items():
        if field == "$or":
            if not any(matches(row, option) for option in expected):
                return False
            continue
        if isinstance(expected, dict):
            for op, value in expected.items():
                if op == "$ne" and row.get(field) == value:
                    return False
                if op == "$in" and row.get(field) not in value:
                    return False
                if op == "$exists" and (field in row) != value:
                    return False
        elif row.get(field) != expected:
            return False
    return True


class Cursor(list):
    def sort(self, spec):
        return self


class SalesInvoicePostingTests(unittest.TestCase):
    def setUp(self):
        self.accounts = [
            {"id": 1, "name": "Sale of Development", "gl_code": "4000", "type": "Revenue"},
            {"id": 2, "name": "Sale of Design", "gl_code": "4005", "type": "Revenue"},
            {"id": 3, "name": "Subscription Revenue", "gl_code": "4010", "type": "Revenue"},
        ]
        self.invoice = {"id": 8, "invoice_number": "SC202610001", "customer_id": 3,
                        "project_id": 4, "account_id": 1, "product_id": 10,
                        "status": "Paid", "currency": "INR", "subtotal": 100,
                        "cgst_percent": 9, "cgst_amount": 9, "sgst_percent": 9, "sgst_amount": 9,
                        "tax_amount": 18, "total_amount": 118, "amount_paid": 118, "manual_amount_paid": 118,
                        "items": [{"description": "Development", "qty": 1, "price": 100}]}
        self.invoices = [self.invoice]
        self.transactions = []
        self.db = MagicMock()
        for name, rows in [("accounts", self.accounts), ("invoices", self.invoices), ("transactions", self.transactions)]:
            collection = getattr(self.db, name)
            collection.find.side_effect = lambda query, *args, rows=rows: Cursor(deepcopy([row for row in rows if matches(row, query)]))
            collection.find_one.side_effect = lambda query, *args, rows=rows: next((deepcopy(row) for row in rows if matches(row, query)), None)
            collection.update_one.side_effect = lambda query, update, rows=rows: self.update(rows, query, update)
        self.db.transactions.insert_one.side_effect = lambda doc: self.transactions.append(deepcopy(doc))
        self.db.custom_objects.find_one.return_value = None
        self.db.treasury_revenue.find_one.return_value = None
        self.db.expense_log.find_one.return_value = None
        self.db.treasury_revenue.find.return_value = []
        self.db.transactions.delete_one.side_effect = lambda query: self.transactions.__setitem__(slice(None), [tx for tx in self.transactions if not matches(tx, query)])
        for name, value in [("get_db", self.db), ("audit_actor", ({"id": 7}, 7, "Test User")),
                            ("get_next_sequence_value", 99), ("check_accounting_period_lock", (False, None, None)),
                            ("get_current_user", {"id": 7})]:
            patcher = patch.object(backend, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ["require_finance_access", "ensure_default_accounts", "log_activity_async",
                     "sync_transaction_to_treasury_revenue", "sync_finance_transaction_bank_movement",
                     "log_treasury_action", "release_claim_posting_if_reversed"]:
            patcher = patch.object(backend, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        self.client = backend.app.test_client()

    @staticmethod
    def update(rows, query, update):
        for row in rows:
            if matches(row, query):
                row.update(deepcopy(update.get("$set", {})))
                for key in update.get("$unset", {}):
                    row.pop(key, None)
        return SimpleNamespace(matched_count=1)

    def payload(self, **changes):
        return {"type": "Income", "account_id": 1, "customer_id": 3, "project_id": 4,
                "product_id": 10, "invoice_id": 8, "amount": 100, "cgst_percent": 9,
                "sgst_percent": 9, "currency": "INR", "category": "Service", "payment_status": "Paid",
                "transaction_date": "2026-10-29", **changes}

    def options(self, **query):
        return self.client.get("/api/finance/invoices/paid-unposted", query_string={
            "customer_id": 3, "project_id": 4, "account_id": 1, **query})

    def post(self, **changes):
        return self.client.post("/api/finance/transactions", json=self.payload(**changes))

    def test_development_design_and_renamed_development_accounts(self):
        for account in self.accounts[:2] + [{"name": "Renamed Development", "gl_code": "4000"}, {"name": "Sales of Design"}]:
            self.assertTrue(is_sales_revenue_account(account))
        self.assertFalse(is_sales_revenue_account(self.accounts[2]))

    def test_selector_filters_customer_project_account_status_and_posted_entries(self):
        self.invoices += [
            {**self.invoice, "id": 9, "customer_id": 30},
            {**self.invoice, "id": 10, "project_id": 40},
            {**self.invoice, "id": 11, "account_id": 2},
            {**self.invoice, "id": 12, "status": "Partially Paid"},
            {**self.invoice, "id": 13, "status": "Cancelled"},
            {**self.invoice, "id": 14}, {**self.invoice, "id": 15},
        ]
        self.transactions += [{"id": "TXN1", "invoice_id": 14, "status": "Completed"},
                              {"id": "TXN2", "invoice_id": 15, "status": "Reversed"}]
        self.assertEqual([inv["id"] for inv in self.options().json["invoices"]], [8, 15])
        defaults = self.options().json["invoices"][0]["posting_defaults"]
        self.assertEqual((defaults["amount"], defaults["cgst_percent"], defaults["sgst_percent"]), (100, 9, 9))
        self.assertEqual(self.options(account_id=2).json["invoices"][0]["id"], 11)
        for fields in [{"project_id": ""}, {"customer_id": ""}, {"account_id": 3}]:
            self.assertEqual(self.options(**fields).json["invoices"], [])

    def test_post_records_balanced_gst_entry_without_counting_payment_twice(self):
        response = self.post(invoice_payment_recorded=False, invoice_allocated_amount=999, invoice_posting_key="bad")
        self.assertEqual(response.status_code, 200, response.json)
        tx = self.transactions[0]
        self.assertEqual((tx["amount"], tx["cgst_amount"], tx["sgst_amount"], tx["total_amount"]), (100, 9, 9, 118))
        self.assertTrue(tx["invoice_payment_recorded"])
        self.assertEqual(tx["invoice_posting_key"], "8")
        self.assertEqual(tx["invoice_allocated_amount"], 118)
        self.assertEqual((self.invoice["status"], self.invoice["amount_paid"], self.invoice["manual_amount_paid"]), ("Paid", 118, 118))
        self.assertEqual(self.options().json["invoices"], [])
        systems = {"bank": {"id": 1010}, "cgst_output": {"id": 2010}, "sgst_output": {"id": 2015}}
        legs = backend.expand_transaction_to_gl_legs(self.db, tx, systems)
        self.assertEqual(sum(leg.get("debit") or 0 for leg in legs), 118)
        self.assertEqual(sum(leg.get("credit") or 0 for leg in legs), 118)
        self.assertEqual(next(leg for leg in legs if leg["leg_id"].endswith("-sgst"))["credit"], 9)
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(len(self.transactions), 1)

    def test_design_and_unassigned_invoice_can_be_posted(self):
        for account in [2, None]:
            with self.subTest(account=account):
                self.transactions.clear()
                self.invoice["account_id"] = account
                self.assertEqual(self.post(account_id=2).status_code, 200)

    def test_deductions_allocate_full_invoice_not_just_net_cash(self):
        self.assertEqual(self.post(tds_percent=10, platform_fee_amount=3).status_code, 200)
        self.assertEqual(self.transactions[0]["total_amount"], 105)
        self.assertEqual(self.transactions[0]["invoice_allocated_amount"], 118)
        self.assertEqual(self.invoice["amount_paid"], 118)
        legs = backend.expand_transaction_to_gl_legs(self.db, self.transactions[0], {})
        self.assertEqual(sum(leg.get("debit") or 0 for leg in legs), sum(leg.get("credit") or 0 for leg in legs))

    def test_invalid_context_amount_currency_and_status_do_not_post(self):
        for fields in [
            {"project_id": ""}, {"project_id": 40}, {"customer_id": 30}, {"invoice_id": 999},
            {"account_id": 2}, {"amount": 99}, {"sgst_percent": 0}, {"currency": "USD"},
            {"payment_status": "Unpaid"}, {"additional_charges": 2}, {"status": "Reversed"},
            {"cgst_percent": "NaN"}, {"tds_percent": -1}, {"platform_fee_amount": 120},
        ]:
            with self.subTest(fields=fields):
                self.assertEqual(self.post(**fields).status_code, 400)
        for status in ["Draft", "Sent", "Approved", "Partially Paid", "Cancelled"]:
            self.invoice["status"] = status
            self.assertEqual(self.post().status_code, 400)
        self.assertEqual(self.transactions, [])

    def test_duplicate_race_is_rejected_by_unique_index(self):
        self.db.transactions.insert_one.side_effect = backend.pymongo.errors.DuplicateKeyError("duplicate invoice")
        self.assertEqual(self.post().status_code, 409)
        self.db.transactions.create_index.assert_called_once_with("invoice_posting_key", unique=True, sparse=True)

    def test_edit_preserves_allocation_and_current_invoice_is_selectable(self):
        self.post()
        self.assertEqual(self.options(transaction_id="TXN099").json["invoices"][0]["id"], 8)
        response = self.client.put("/api/finance/transactions/TXN099", json=self.payload(
            tds_percent=5, invoice_payment_recorded=False, invoice_allocated_amount=999, invoice_posting_key="bad"))
        self.assertEqual(response.status_code, 200, response.json)
        self.assertTrue(self.transactions[0]["invoice_payment_recorded"])
        self.assertEqual(self.transactions[0]["invoice_allocated_amount"], 118)
        self.assertEqual(self.invoice["amount_paid"], 118)
        self.assertEqual(self.invoice["manual_amount_paid"], 118)

    def test_reversal_reopens_posting_without_erasing_received_payment(self):
        self.post()
        self.assertEqual(self.client.post("/api/finance/transactions/TXN099/reverse").status_code, 200)
        self.assertNotIn("invoice_posting_key", self.transactions[0])
        self.assertEqual((self.invoice["status"], self.invoice["amount_paid"]), ("Paid", 118))
        self.assertEqual(len(self.options().json["invoices"]), 1)
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.invoice["amount_paid"], 118)

    def test_legacy_tax_total_is_not_assigned_an_invented_gst_split(self):
        invoice = {"subtotal": 100, "tax_amount": 18, "total_amount": 118}
        defaults = invoice_posting_defaults(invoice)
        self.assertTrue(defaults["tax_split_required"])
        self.assertEqual(defaults["cgst_amount"], 0)

    def test_delete_reopens_posting_and_keeps_the_invoice_paid(self):
        self.post()
        self.assertEqual(self.client.delete("/api/finance/transactions/TXN099").status_code, 200)
        self.assertEqual(self.transactions, [])
        self.assertEqual(self.invoice["amount_paid"], 118)
        self.assertEqual(len(self.options().json["invoices"]), 1)

    def test_posting_period_lock_is_enforced(self):
        with patch.object(backend, "check_accounting_period_lock", return_value=(True, None, "Period is locked")):
            response = self.post()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "Period is locked")
        self.assertEqual(self.transactions, [])

    def test_invoice_tax_split_is_saved_for_later_autofill(self):
        self.db.invoices.insert_one.side_effect = lambda doc: self.invoices.append(deepcopy(doc))
        self.db.company_bank_accounts.find_one.return_value = None
        response = self.client.post("/api/finance/invoices", json={**self.invoice, "id": 99,
                                    "invoice_number": "NEW-INV"})
        self.assertEqual(response.status_code, 200)
        created = self.invoices[-1]
        self.assertEqual((created["cgst_percent"], created["cgst_amount"], created["sgst_percent"], created["sgst_amount"]), (9, 9, 9, 9))

    def test_finance_access_is_required_for_selection_and_posting(self):
        self.require_finance_access.side_effect = lambda: backend.abort(403)
        self.assertEqual(self.options().status_code, 403)
        self.assertEqual(self.post().status_code, 403)


if __name__ == "__main__":
    unittest.main()
