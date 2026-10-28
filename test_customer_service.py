"""Isolated service tests; no real database or external notifications are used."""

from copy import deepcopy
import unittest
from unittest.mock import MagicMock, patch

import app as backend
from customer_service import normalize_service_terms


FREE = {
    "type": "Free", "name": "Implementation support",
    "start_date": "2026-10-28", "end_date": "2027-04-27",
    "notes": "Remote support during business hours",
}


class ServiceValidationTests(unittest.TestCase):
    def test_free_service_cannot_retain_a_paid_rate(self):
        terms = normalize_service_terms({**FREE, "hourly_rate": 1500})
        self.assertIsNone(terms["hourly_rate"])
        self.assertEqual(terms["currency"], "INR")

    def test_paid_service_accepts_an_open_ended_agreement(self):
        terms = normalize_service_terms({**FREE, "type": "Paid", "end_date": None,
                                         "hourly_rate": "1500.50", "currency": "inr"})
        self.assertEqual(terms["hourly_rate"], 1500.5)
        self.assertIsNone(terms["end_date"])
        self.assertEqual(terms["currency"], "INR")

    def test_invalid_terms_are_rejected(self):
        cases = [
            [], {**FREE, "type": "Unknown"}, {**FREE, "start_date": ""},
            {**FREE, "end_date": None}, {**FREE, "end_date": "2026-02-30"},
            {**FREE, "end_date": "2026-10-27"}, {**FREE, "currency": "123"},
            {**FREE, "notes": "x" * 5001},
        ]
        cases += [{**FREE, "type": "Paid", "hourly_rate": rate}
                  for rate in [None, "", True, 0, -1, "NaN", "Infinity", "1.001", "1000000000"]]
        for terms in cases:
            with self.subTest(terms=repr(terms)[:180]), self.assertRaises(ValueError):
                normalize_service_terms(terms)


class CustomerServiceApiTests(unittest.TestCase):
    def setUp(self):
        self.records = {1: {"id": 1, "company_name": "Test Customer", "contact_name": "Contact",
                            "status": "Active", "billing_address": "Mumbai"}}
        self.db = MagicMock()
        self.db.app_users.find_one.return_value = {"id": 7, "full_name": "Test User"}
        self.db.custom_objects.find_one.return_value = None
        self.db.opportunities.find.return_value = []
        self.db.projects.find.return_value = []
        self.db.customers.find_one.side_effect = lambda query, *args: deepcopy(self.records.get(query["id"]))
        self.db.customers.find.return_value.sort.side_effect = lambda *args: deepcopy(list(self.records.values()))
        self.db.customers.update_one.side_effect = lambda query, update: self.records[query["id"]].update(deepcopy(update["$set"]))
        self.db.customers.insert_one.side_effect = lambda value: self.records.update({value["id"]: deepcopy(value)})
        db_patch = patch.object(backend, "get_db", return_value=self.db)
        audit_patch = patch.object(backend, "log_activity_async")
        db_patch.start()
        self.audit = audit_patch.start()
        self.addCleanup(db_patch.stop)
        self.addCleanup(audit_patch.stop)
        self.client = backend.app.test_client()
        with self.client.session_transaction() as sess:
            sess["user_id"] = 7

    def save_service(self, terms):
        return self.client.put("/api/customers/1/service", json={"service_terms": terms})

    def test_save_and_read_terms_in_detail_and_list(self):
        response = self.save_service(FREE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["customer"]["billing_address"], "Mumbai")
        for url, key in [("/api/customers/1", "customer"), ("/api/customers", "customers")]:
            data = self.client.get(url).json[key]
            record = data[0] if isinstance(data, list) else data
            self.assertEqual(record["service_terms"]["end_date"], "2027-04-27")
            self.assertEqual(record["service_terms"]["notes"], FREE["notes"])
        self.assertEqual(self.records[1]["modified_by_id"], 7)
        self.audit.assert_called_once()

    def test_switch_to_paid_then_remove_service(self):
        self.save_service(FREE)
        response = self.save_service({**FREE, "type": "Paid", "hourly_rate": 1250.5})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["customer"]["service_terms"]["hourly_rate"], 1250.5)
        self.assertEqual(self.save_service(None).status_code, 200)
        self.assertIsNone(self.records[1]["service_terms"])

    def test_invalid_update_does_not_change_saved_service(self):
        self.save_service(FREE)
        before = deepcopy(self.records[1])
        response = self.save_service({**FREE, "type": "Paid", "hourly_rate": -5})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.records[1], before)
        self.assertEqual(self.client.put("/api/customers/1/service", json={}).status_code, 400)

    def test_profile_edit_preserves_service_and_validates_explicit_service_changes(self):
        self.save_service(FREE)
        response = self.client.put("/api/customers/1", json={"company_name": "Updated Customer"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.records[1]["service_terms"]["type"], "Free")
        response = self.client.put("/api/customers/1", json={"service_terms": {**FREE, "end_date": "invalid"}})
        self.assertEqual(response.status_code, 400)

    def test_customer_creation_normalizes_service_terms(self):
        with patch.object(backend, "get_next_sequence_value", return_value=2), patch.object(backend, "invalidate_options_cache"):
            response = self.client.post("/api/customers", json={"company_name": "New", "service_terms": FREE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["customer"]["service_terms"]["currency"], "INR")
        response = self.client.post("/api/customers", json={"service_terms": {**FREE, "type": "Paid"}})
        self.assertEqual(response.status_code, 400)

    def test_missing_customer_and_unauthenticated_writes(self):
        response = self.client.put("/api/customers/999/service", json={"service_terms": FREE})
        self.assertEqual(response.status_code, 404)
        with self.client.session_transaction() as sess:
            sess.clear()
        self.assertEqual(self.save_service(FREE).status_code, 401)
        self.db.customers.update_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
