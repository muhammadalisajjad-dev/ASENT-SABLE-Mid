"""
Invoice schema validator.
"""
import re

def validate_invoice_text(text: str) -> dict:
    # Check for basic invoice markers
    has_invoice = bool(re.search(r"(?i)invoice", text))
    total_match = re.search(r"\$([0-9]+(?:\.[0-9]{2})?)", text)
    total = float(total_match.group(1)) if total_match else 0.0
    return {
        "valid": has_invoice,
        "total": total,
        "characters_parsed": len(text)
    }
