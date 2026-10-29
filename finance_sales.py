"""Invoice selection and validation for posting previously received sales payments."""

from math import isfinite


def is_sales_revenue_account(account):
    if not account:
        return False
    name = " ".join(str(account.get("name") or "").lower().split())
    return str(account.get("gl_code") or "").strip() == "4000" or name in {
        "sales revenue", "sale of development", "sales of development",
        "sale of design", "sales of design",
    }


def invoice_posting_defaults(invoice):
    tax = round(float(invoice.get("tax_amount") or 0), 2)
    total = round(float(invoice.get("total_amount") or 0), 2)
    base = round(float(invoice.get("subtotal") or total - tax), 2)
    values = {"amount": base, "currency": invoice.get("currency") or "INR"}
    for kind in ("cgst", "sgst", "igst"):
        percent = float(invoice.get(f"{kind}_percent") or 0)
        amount = round(float(invoice.get(f"{kind}_amount") or base * percent / 100), 2)
        values[f"{kind}_amount"] = amount
        values[f"{kind}_percent"] = percent or (round(amount * 100 / base, 6) if base else 0)
    values["tax_split_required"] = tax > 0 and not any(values[f"{kind}_amount"] for kind in ("cgst", "sgst", "igst"))
    return values


def validate_invoice_posting(invoice, data, existing_transaction=None):
    if invoice.get("status") != "Paid":
        raise ValueError("Select a fully paid, unposted invoice.")
    defaults = invoice_posting_defaults(invoice)
    base = round(float(data.get("amount") or 0), 2)
    taxes = {kind: round(base * float(data.get(f"{kind}_percent") or 0) / 100, 2)
             for kind in ("cgst", "sgst", "igst")}
    if not all(isfinite(value) and value >= 0 for value in [base, *taxes.values()]):
        raise ValueError("Enter valid, non-negative amounts and GST rates.")
    gross = round(base + sum(taxes.values()), 2)
    total = round(float(invoice.get("total_amount") or 0), 2)
    if base <= 0 or abs(base - defaults["amount"]) > .01 or abs(gross - total) > .01:
        raise ValueError("Base amount and GST must match the selected invoice total.")
    if not defaults["tax_split_required"] and any(abs(taxes[kind] - defaults[f"{kind}_amount"]) > .01 for kind in taxes):
        raise ValueError("GST amounts must match the selected invoice.")
    if data.get("currency") != defaults["currency"]:
        raise ValueError("Currency must match the selected invoice.")
    if float(data.get("additional_charges") or data.get("additional_charges_amount") or 0) or float(data.get("additional_charges_percent") or 0):
        raise ValueError("Additional charges must be included in the invoice before posting.")
    for name in ("tds_percent", "platform_fee_percent", "platform_fee_amount", "platform_charges"):
        value = float(data.get(name) or 0)
        if not isfinite(value) or value < 0:
            raise ValueError("Enter valid, non-negative deductions.")
    tds = round(base * float(data.get("tds_percent") or 0) / 100, 2)
    fee = float(data.get("platform_fee_amount") or data.get("platform_charges") or 0)
    fee = fee or round(base * float(data.get("platform_fee_percent") or 0) / 100, 2)
    if gross - tds - fee <= 0:
        raise ValueError("Deductions must be less than the invoice total.")
    if data.get("payment_status", "Paid") != "Paid" or data.get("status", "Completed") not in {"Completed", "Posted"}:
        raise ValueError("A paid invoice must be posted as a completed, paid transaction.")
    recorded = not existing_transaction or existing_transaction.get("invoice_payment_recorded", False)
    if existing_transaction and existing_transaction.get("invoice_id") != invoice["id"]:
        recorded = True
    return {"invoice_id": invoice["id"], "invoice_number": invoice.get("invoice_number"),
            "customer_id": invoice.get("customer_id"), "project_id": invoice.get("project_id"),
            "product_id": invoice.get("product_id"),
            "invoice_payment_recorded": bool(recorded), "invoice_allocated_amount": total,
            "invoice_posting_key": str(invoice["id"])}
