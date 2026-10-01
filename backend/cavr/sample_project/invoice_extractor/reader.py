"""
Sample Project: Invoice PDF Extractor.
Extracts invoice totals, line items, and invoice dates from PDF invoices.
"""
import os
from pypdf import PdfReader

class InvoiceReader:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def extract_text(self) -> str:
        # Call site: reader.py:14 (PdfReader)
        reader = PdfReader(self.filepath)
        text_parts = []
        for page_idx, page in enumerate(reader.pages):
            # Call site: reader.py:18 (page.extract_text)
            extracted = page.extract_text()
            if extracted:
                text_parts.append(extracted)
        return "\n".join(text_parts)

    def parse_metadata(self) -> dict:
        reader = PdfReader(self.filepath)
        # Call site: reader.py:26 (metadata access)
        return dict(reader.metadata or {})
