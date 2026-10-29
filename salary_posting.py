"""Validate the payroll behind an existing salary payable before ledger posting."""

from math import isfinite

MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August",
          "September", "October", "November", "December")


def salary_payable_details(payable, records):
    if payable.get("source_module") != "HR Salary" or payable.get("status") in {"Cancelled", "Reversed"}:
        raise ValueError("Select an existing salary payable that has not been cancelled or reversed.")
    expected_ids = {str(value) for value in payable.get("hr_payroll_record_ids") or []}
    if not records or expected_ids and {str(record["id"]) for record in records} != expected_ids:
        raise ValueError("The payroll records linked to this salary payable could not all be found.")
    periods = {(record.get("salary_month"), int(record.get("salary_year") or 0)) for record in records}
    if len(periods) != 1:
        raise ValueError("A salary posting must contain records for one salary month and year.")
    month, year = next(iter(periods))
    if month not in MONTHS or year < 2000:
        raise ValueError("The salary payable has an invalid salary period.")
    if any(record.get("status") != "Finalized" for record in records):
        raise ValueError("Finalize all payroll records for this salary payable before posting.")
    if payable.get("ledger_transaction_id") or any(record.get("ledger_transaction_id") for record in records):
        raise ValueError("This salary payable has already been posted to the transaction ledger.")
    if any(record.get("salary_payable_id") and str(record["salary_payable_id"]) != str(payable["id"]) for record in records):
        raise ValueError("Some payroll records belong to a different salary payable.")
    amount = round(sum(float(record.get("net_payable_salary") or 0) for record in records), 2)
    original = round(float(payable.get("original_amount") or 0), 2)
    if not isfinite(amount) or amount <= 0 or not isfinite(original) or abs(amount - original) > .01:
        raise ValueError("Payroll totals must match the original salary payable amount before posting.")
    return {"id": payable["id"], "payable_number": payable.get("payable_number"),
            "salary_month": month, "salary_year": year, "record_count": len(records),
            "total_amount": amount, "currency": payable.get("currency") or "INR",
            "status": payable.get("status"), "source_reference": payable.get("source_reference"),
            "paid_amount": payable.get("paid_amount", 0),
            "outstanding_amount": payable.get("outstanding_amount", amount),
            "record_ids": [record["id"] for record in records]}
