"""Simple tests. Run with:  python -m unittest test_detector.py -v"""
import os
import unittest

import phishing_detector as pd


class DetectorTests(unittest.TestCase):
    def test_phishing_sample_is_flagged(self):
        result = pd.analyse("samples/phishing_example.eml", use_ai=False)
        self.assertEqual(result["final_verdict"], "likely malicious")
        self.assertGreaterEqual(result["rule_score"], 8)

    def test_legitimate_sample_is_not_flagged(self):
        result = pd.analyse("samples/legitimate_example.eml", use_ai=False)
        self.assertEqual(result["final_verdict"], "likely not malicious")
        self.assertEqual(result["rule_score"], 0)

    def test_registered_domain(self):
        self.assertEqual(pd.registered_domain("login.commbank.com.au"), "commbank.com.au")
        self.assertEqual(pd.registered_domain("mail.example.com"), "example.com")

    def test_lookalike_normalisation(self):
        self.assertEqual(pd.normalise_label("paypa1-secure"), "paypalsecure")

    def test_ai_json_parsing(self):
        reply = 'Sure! {"verdict": "Suspicious", "confidence": 0.7, "red_flags": [], "explanation": "x"}'
        self.assertEqual(pd.parse_ai_json(reply)["verdict"], "suspicious")
        with self.assertRaises(ValueError):
            pd.parse_ai_json("no json here")
        with self.assertRaises(ValueError):
            pd.parse_ai_json('{"verdict": "maybe"}')

    def test_runs_without_api_key(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result = pd.analyse("samples/phishing_example.eml", use_ai=True)
        self.assertIsNone(result["ai"])
        self.assertIn("ANTHROPIC_API_KEY", result["ai_note"])


if __name__ == "__main__":
    unittest.main()
