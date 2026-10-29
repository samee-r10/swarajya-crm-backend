"""Salary ledger posting reuses HR payables; no live payroll or bank writes."""

from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import app as backend


def matches(row, query):
    for key, expected in query.items():
        if key == "$or":
            if not any(matches(row, option) for option in expected):
                return False
            continue
        value = row.get(key)
        if isinstance(expected, dict):
            for operation, operand in expected.items():
                if operation == "$in" and not (any(item in operand for item in value) if isinstance(value, list) else value in operand):
                    return False
                if operation == "$nin" and value in operand:
                    return False
                if operation == "$ne" and value == operand:
                    return False
                if operation == "$lt" and (value is None or value >= operand):
                    return False
                if operation == "$gte" and (value is None or value < operand):
                    return False
                if operation == "$lte" and (value is None or value > operand):
                    return False
        elif value != expected:
            return False
    return True


class Cursor(list):
    def sort(self, *args):
        return self


class SalaryPostingTests(unittest.TestCase):
    def setUp(self):
        self.records = [{"id": "payroll-1", "employee_id": "EMP1", "employee_name": "Test Employee",
                         "salary_month": "October", "salary_year": 2026, "net_payable_salary": 10000,
                         "status": "Finalized", "payment_status": "Pending"}]
        self.payables = []
        self.salary = []
        self.expense = {"id": 6, "name": "Salaries Expense", "gl_code": "6010", "type": "Expense", "show_in_expense": 1}
        self.bank = {"id": 2, "name": "Bank Account", "gl_code": "1010", "type": "Asset"}
        self.ap = {"id": 3, "name": "Accounts Payable", "gl_code": "2000", "type": "Liability"}
        self.accounts = [self.expense, self.bank, self.ap]
        self.db = MagicMock()
        for name, rows in [("hr_payroll", self.records), ("payables", self.payables),
                           ("hr_salary_transactions", self.salary), ("accounts", self.accounts)]:
            collection = getattr(self.db, name)
            collection.find.side_effect = lambda query, *args, rows=rows: Cursor(deepcopy([row for row in rows if matches(row, query)]))
            collection.find_one.side_effect = lambda query, *args, rows=rows, **kwargs: next((deepcopy(row) for row in rows if matches(row, query)), None)
            collection.insert_one.side_effect = lambda doc, rows=rows: rows.append(deepcopy(doc))
            collection.update_one.side_effect = lambda query, update, *args, rows=rows, **kwargs: self.update(rows, query, update)
            collection.update_many.side_effect = lambda query, update, rows=rows: self.update(rows, query, update)
        self.db.transactions.find.return_value = []
        self.db.transactions.find_one.return_value = None
        self.db.transactions.aggregate.return_value = []
        self.db.system_settings.find_one.return_value = None
        self.db.expense_log.find.return_value = []
        self.systems = {"bank": self.bank, "accounts_payable": self.ap}
        for name, value in [("get_db", self.db), ("require_finance_access", {"id": 7}),
                            ("require_hr_access", {"id": 7}), ("user_has_hr_permission", True),
                            ("get_next_sequence_value", 99), ("account_list", self.accounts),
                            ("get_system_gl_accounts", self.systems),
                            ("check_accounting_period_lock", (False, None, None))]:
            patcher = patch.object(backend, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        for name in ["ensure_default_accounts", "log_activity_async"]:
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

    def create_payable(self):
        response = self.client.post("/api/hr/salary-payments", json={
            "transaction": {"salary_month": "October", "salary_year": 2026}, "payroll_records": [{"id": "payroll-1"}]})
        self.assertEqual(response.status_code, 200, response.json)
        return self.payables[0]

    def post(self, **fields):
        return self.client.post("/api/finance/salary-postings", json={
            "payable_id": 99, "account_id": 6, "transaction_date": "2026-10-29", **fields})

    def test_hr_payable_appears_for_current_month_and_server_permission(self):
        self.create_payable()
        result = self.client.get("/api/finance/salary-posting-options")
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json["can_post_salary"])
        self.assertEqual(result.json["payables"][0]["salary_month"], "October")
        self.assertEqual(result.json["payables"][0]["salary_year"], 2026)
        self.assertEqual(result.json["payables"][0]["total_amount"], 10000)
        self.assertEqual([account["id"] for account in result.json["accounts"]], [6])
        self.account_list.assert_called_with(self.db, sort=[("gl_code", 1), ("name", 1)], include_balances=False)

    def test_post_links_same_payable_without_new_liability_or_bank_payment(self):
        payable = self.create_payable()
        original = deepcopy(payable)
        response = self.post(amount=1, total_amount=1, transaction_type="Salary Payment", bank_account_id=2)
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(len(self.payables), 1)
        self.assertEqual(len(self.salary), 1)
        self.assertEqual(self.salary[0]["amount"], 10000)
        self.assertEqual(self.salary[0]["account_id"], 6)
        self.assertEqual(self.salary[0]["salary_payable_id"], 99)
        self.assertEqual(self.salary[0]["source_module"], "HR Salary")
        self.assertEqual(self.salary[0]["outflow"], 0)
        self.assertNotIn("bank_account_id", self.salary[0])
        self.assertEqual(self.records[0]["ledger_transaction_id"], "TXN099")
        for key in ["source_id", "paid_amount", "outstanding_amount", "status", "original_amount", "source_reference"]:
            self.assertEqual(payable[key], original[key], key)
        self.db.company_bank_transactions.insert_one.assert_not_called()
        self.db.payable_payments.insert_one.assert_not_called()
        self.assertEqual(self.client.get("/api/finance/salary-posting-options").json["payables"], [])
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(len(self.salary), 1)

    def test_existing_partial_or_full_settlement_is_preserved(self):
        payable = self.create_payable()
        for status, paid, outstanding in [("Partially Paid", 4000, 6000), ("Paid", 10000, 0)]:
            self.salary.clear()
            payable.pop("ledger_transaction_id", None)
            self.records[0].pop("ledger_transaction_id", None)
            payable.update(status=status, paid_amount=paid, outstanding_amount=outstanding)
            self.records[0]["payment_status"] = status
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual((payable["status"], payable["paid_amount"], payable["outstanding_amount"]), (status, paid, outstanding))
            self.assertEqual(self.records[0]["payment_status"], status)

    def test_missing_draft_cancelled_and_mismatched_payroll_are_rejected(self):
        payable = self.create_payable()
        self.assertEqual(self.post(payable_id=123).status_code, 400)
        for change in [{"status": "Cancelled"}, {"original_amount": 1}, {"hr_payroll_record_ids": ["missing"]}]:
            original = deepcopy(payable)
            payable.update(change)
            self.assertEqual(self.post().status_code, 400)
            payable.clear()
            payable.update(original)
        self.records[0]["status"] = "Draft"
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(self.client.get("/api/finance/salary-posting-options").json["payables"], [])
        self.assertEqual(self.salary, [])

    def test_duplicate_transaction_and_unique_key_race_are_prevented(self):
        self.create_payable()
        self.salary.append({"id": "OLD", "hr_payroll_record_ids": ["payroll-1"], "status": "Posted"})
        self.assertEqual(self.post().status_code, 409)
        self.salary.clear()
        self.db.hr_salary_transactions.insert_one.side_effect = backend.pymongo.errors.DuplicateKeyError("duplicate payroll")
        self.assertEqual(self.post().status_code, 409)
        self.db.payables.update_one.assert_not_called()
        self.db.hr_salary_transactions.create_index.assert_any_call("salary_posting_record_keys", unique=True, sparse=True)

    def test_permission_and_accounting_lock_are_enforced(self):
        self.create_payable()
        self.user_has_hr_permission.return_value = False
        self.assertFalse(self.client.get("/api/finance/salary-posting-options").json["can_post_salary"])
        self.assertEqual(self.post().status_code, 403)
        self.user_has_hr_permission.return_value = True
        self.check_accounting_period_lock.return_value = (True, None, "Period closed")
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(self.salary, [])

    def test_legacy_posting_client_also_reuses_existing_payable(self):
        self.create_payable()
        response = self.client.post("/api/hr/salary-ledger-payments", json={
            "transaction": {"account_id": 6, "total_amount": 1, "transaction_date": "2026-10-29T08:00:00Z"},
            "payroll_records": [{"id": "payroll-1"}]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.payables), 1)
        self.assertEqual(self.salary[0]["transaction_date"], "2026-10-29")

    def test_salary_journal_credits_payable_and_uses_selected_expense_gl(self):
        self.create_payable()
        self.post()
        response = self.client.get("/api/finance/transactions/TXN099/gl-entries")
        self.assertEqual(response.status_code, 200, response.json)
        entries = response.json["entries"]
        self.assertEqual([(entry["gl_code"], entry.get("debit"), entry.get("credit")) for entry in entries],
                         [("6010", 10000, None), ("2000", None, 10000)])
        self.assertTrue(response.json["totals"]["is_balanced"])
        balances = backend.calculate_account_balance(self.db, self.ap, self.systems)
        self.assertEqual(balances["total_credits"], 10000)
        balances = backend.calculate_account_balance(self.db, self.bank, self.systems)
        self.assertEqual(balances["balance"], 0)

    def test_general_ledger_report_and_opening_balance_use_payable_account(self):
        self.create_payable()
        self.post()
        response = self.client.get("/api/finance/reports/general-ledger?account_id=3&start_date=2026-10-01&end_date=2026-10-31")
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(len(response.json["entries"]), 1)
        self.assertEqual(response.json["entries"][0]["gl_code"], "2000")
        response = self.client.get("/api/finance/reports/general-ledger?account_id=3&start_date=2026-11-01")
        self.assertEqual(response.status_code, 200, response.json)
        self.assertAlmostEqual(response.json["opening_balance"], 10000 / 95, places=2)

    def test_legacy_paid_salary_still_credits_bank(self):
        legacy = {"id": "LEGACY", "transaction_type": "Salary Payment", "status": "Paid",
                  "account_id": 6, "account_name": "Salaries Expense", "gl_code": "6010",
                  "total_amount": 10000, "currency": "INR", "transaction_date": "2026-09-30"}
        legs = backend.salary_transaction_gl_legs(self.db, legacy, self.systems)
        self.assertEqual([(leg["gl_code"], leg.get("credit")) for leg in legs], [("6010", None), ("1010", 10000)])
        self.assertEqual(backend.salary_transaction_gl_legs(self.db, {**legacy, "status": "Reversed"}, self.systems), [])

    def test_invalid_date_inactive_or_nonexpense_account_are_rejected(self):
        self.create_payable()
        self.assertEqual(self.post(transaction_date="invalid").status_code, 400)
        self.assertEqual(self.post(account_id=2).status_code, 400)
        self.expense["is_active"] = 0
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(self.salary, [])

    def test_salary_payable_cannot_mix_salary_months(self):
        payable = self.create_payable()
        self.records.append({**self.records[0], "id": "payroll-2", "salary_month": "September"})
        payable["hr_payroll_record_ids"].append("payroll-2")
        payable["original_amount"] = 20000
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(self.salary, [])


if __name__ == "__main__":
    unittest.main()
