"""Validation for the current service agreement stored on a customer."""

import re
from datetime import date
from decimal import Decimal, InvalidOperation


def normalize_service_terms(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("Service details must be an object.")
    service_type = value.get("type")
    if service_type not in ("Free", "Paid"):
        raise ValueError("Choose Free or Paid service.")

    def text(key, limit):
        result = value.get(key) or ""
        if not isinstance(result, str) or len(result.strip()) > limit:
            raise ValueError(f"Service {key.replace('_', ' ')} must be text up to {limit} characters.")
        return result.strip()

    def service_date(key, required=False):
        raw = value.get(key)
        if not raw and not required:
            return None
        if not isinstance(raw, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            raise ValueError(f"Service {key.replace('_', ' ')} must be a valid date (YYYY-MM-DD).")
        try:
            return date.fromisoformat(raw).isoformat()
        except ValueError:
            raise ValueError(f"Service {key.replace('_', ' ')} must be a valid date.") from None

    start = service_date("start_date", required=True)
    end = service_date("end_date", required=service_type == "Free")
    if end and end < start:
        raise ValueError("Service end date cannot be before the start date.")
    currency = text("currency", 3).upper() or "INR"
    if not re.fullmatch(r"[A-Z]{3}", currency):
        raise ValueError("Service currency must be a three-letter code, such as INR.")
    rate = None
    if service_type == "Paid":
        raw_rate = value.get("hourly_rate")
        try:
            rate = Decimal(str(raw_rate))
        except (InvalidOperation, ValueError):
            raise ValueError("Enter a positive hourly rate for paid service.") from None
        if not rate.is_finite() or rate <= 0 or rate > Decimal("999999999.99"):
            raise ValueError("Hourly rate must be greater than zero and at most 999999999.99.")
        if rate != rate.quantize(Decimal("0.01")):
            raise ValueError("Hourly rate can have at most two decimal places.")
    return {
        "type": service_type,
        "name": text("name", 160),
        "start_date": start,
        "end_date": end,
        "hourly_rate": float(rate) if rate is not None else None,
        "currency": currency,
        "notes": text("notes", 5000),
    }
