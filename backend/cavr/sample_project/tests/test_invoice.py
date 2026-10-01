import unittest
from invoice_extractor.validator import validate_invoice_text

class TestInvoiceValidation(unittest.TestCase):
    def test_sample_invoice_text(self):
        sample = "INVOICE #99812 - Total Amount: $450.00 - Due Date: 2026-10-15"
        res = validate_invoice_text(sample)
        self.assertTrue(res["valid"])
        self.assertEqual(res["total"], 450.0)

    def test_non_invoice_text(self):
        sample = "Hello World, standard document"
        res = validate_invoice_text(sample)
        self.assertFalse(res["valid"])

if __name__ == "__main__":
    unittest.main()
