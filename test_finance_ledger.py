"""Ledger read regressions; all database operations use in-memory fakes."""

from copy import deepcopy
import unittest
from unittest.mock import MagicMock, patch

import app as backend
from finance_ledger import load_ledger_transactions


class LedgerReadTests(unittest.TestCase):
    def make_db(self, rows, relations=None):
        db = MagicMock()
        calls = []
        collections = {"transactions": rows, **(relations or {})}

        def collection(name):
            def find(query, projection):
                calls.append((name, query, projection))
                records = collections.get(name, [])
                if "id" in query:
                    records = [row for row in records if row.get("id") in query["id"]["$in"]]
                return [{key: deepcopy(value) for key, value in row.items() if projection.get(key)}
                        for row in records]
            result = MagicMock()
            result.find.side_effect = find
            return result

        db.__getitem__.side_effect = collection
        db.transactions = collection("transactions")
        return db, calls

    def test_enrichment_keeps_ledger_and_export_fields_without_large_documents(self):
        db, calls = self.make_db([
            {"id": "TXN001", "date": "2026-10-28", "type": "Income", "amount": 100,
             "total_amount": 118, "cgst_amount": 18, "reference": "REF-1",
             "account_id": 1, "customer_id": 2, "vendor_id": 3, "project_id": 4,
             "invoice_id": 5, "invoice_number": "OLD", "attachments": ["large-document"],
             "custom_payload": "large-value"},
        ], {
            "accounts": [{"id": 1, "name": "Sales Revenue", "gl_code": "4000"}],
            "customers": [{"id": 2, "company_name": "Customer"}],
            "vendors": [{"id": 3, "name": "Vendor"}],
            "projects": [{"id": 4, "project_name": "Project"}],
            "invoices": [{"id": 5, "invoice_number": "INV-5"}],
        })
        row = load_ledger_transactions(db, {})[0]
        self.assertEqual(row["transaction_date"], "2026-10-28")
        self.assertEqual(row["account_name"], "Sales Revenue")
        self.assertEqual(row["gl_account_number"], "4000")
        self.assertEqual(row["customer_name"], "Customer")
        self.assertEqual(row["vendor_name"], "Vendor")
        self.assertEqual(row["project_name"], "Project")
        self.assertEqual(row["invoice_number"], "INV-5")
        self.assertEqual(row["total_amount"], 118)
        self.assertEqual(row["reference"], "REF-1")
        self.assertNotIn("attachments", row)
        self.assertNotIn("custom_payload", row)
        self.assertEqual(len(calls), 6)

    def test_database_reads_do_not_grow_with_transaction_count(self):
        rows = [{"id": f"TXN{i}", "account_id": 1, "customer_id": 2} for i in range(5000)]
        db, calls = self.make_db(rows)
        self.assertEqual(len(load_ledger_transactions(db, {"type": "Income"})), 5000)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][1], {"type": "Income"})
        self.assertEqual(calls[1][1], {"id": {"$in": [1]}})

    def test_missing_relations_keep_rows_reversals_and_invoice_fallback(self):
        db, calls = self.make_db([
            {"id": "TXN001", "status": "Reversed", "invoice_id": 7, "invoice_number": "INV-OLD"},
            {"id": "TXN002", "transaction_date": None, "date": "2026-10-27"},
        ])
        rows = load_ledger_transactions(db, {})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["status"], "Reversed")
        self.assertEqual(rows[0]["invoice_number"], "INV-OLD")
        self.assertEqual(rows[1]["transaction_date"], "2026-10-27")
        self.assertEqual(len(calls), 2)

    def test_empty_ledger_does_not_query_related_collections(self):
        db, calls = self.make_db([])
        self.assertEqual(load_ledger_transactions(db, {}), [])
        self.assertEqual(len(calls), 1)


class LedgerEndpointTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.db.custom_objects.find_one.return_value = {"id": 9}
        self.client = backend.app.test_client()

    def test_ledger_view_uses_small_read_and_does_not_load_custom_fields(self):
        with patch.object(backend, "require_finance_access"), \
                patch.object(backend, "get_db", return_value=self.db), \
                patch.object(backend, "ensure_default_accounts"), \
                patch.object(backend, "load_ledger_transactions", return_value=[{"id": "TXN1"}]) as load:
            response = self.client.get("/api/finance/transactions?view=ledger&type=Income")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["transactions"], [{"id": "TXN1"}])
        load.assert_called_once_with(self.db, {"type": "Income"})
        self.db.transactions.aggregate.assert_not_called()
        self.db.custom_objects.find_one.assert_not_called()

    def test_form_metadata_does_not_read_transaction_history(self):
        with patch.object(backend, "require_finance_access"), \
                patch.object(backend, "get_db", return_value=self.db), \
                patch.object(backend, "get_fields_for_user", return_value=[{"label": "Cost Centre"}]) as fields:
            response = self.client.get("/api/finance/transactions?metadata_only=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["fields"], [{"label": "Cost Centre"}])
        fields.assert_called_once_with(9)
        self.db.transactions.find.assert_not_called()
        self.db.transactions.aggregate.assert_not_called()

    def test_ledger_and_metadata_still_require_finance_access(self):
        with patch.object(backend, "require_finance_access", side_effect=lambda: backend.abort(403)), \
                patch.object(backend, "get_db") as get_db:
            for query in ["view=ledger", "metadata_only=1"]:
                self.assertEqual(self.client.get(f"/api/finance/transactions?{query}").status_code, 403)
        get_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
