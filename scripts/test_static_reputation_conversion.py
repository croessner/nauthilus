"""Golden offline-conversion tests for operator intent, independent of runtime implementation."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("static_conversion", Path(__file__).with_name("convert-static-reputation.py"))
CONVERTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONVERTER)


class StaticConversionTest(unittest.TestCase):
    """Exercise explicit bands, absence, exact network scope and expiry conversion."""

    def test_all_bands_and_absence(self):
        """Each explicit source entry remains an exact same-band override and absence stays absent."""
        for band in ("trusted", "neutral", "blocked"):
            with self.subTest(band=band):
                result = CONVERTER.convert({"domains": [{"domain": "relay.example", "reputation": band}], "client_networks": [{"cidr": "192.0.2.16/28", "reputation": band}]}, "operator", "audit")
                self.assertEqual([entry["band"] for entry in result["overrides"]], [band, band])
                self.assertEqual(result["ip_override_networks"], ["192.0.2.16/28"])
                self.assertTrue(all(entry["origin"] == "cutover.static_reputation_v4" for entry in result["overrides"]))
        self.assertEqual(CONVERTER.convert({}, "operator", "audit")["overrides"], [])

    def test_no_widening_or_unknown_classification(self):
        """Conversion rejects malformed input instead of rounding a prefix or inventing neutrality."""
        for raw in ({"domains": [{"domain": "relay.example", "reputation": "unknown"}]}, {"client_networks": [{"cidr": "192.0.2.17/28", "reputation": "trusted"}]}, {"unexpected": True}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                CONVERTER.convert(raw, "operator", "audit")

    def test_expiry_is_preserved_deterministically(self):
        """Absolute expiry is kept per override and repeated conversion is byte-stable."""
        raw = {"domains": [{"domain": "relay.example", "reputation": "neutral"}], "client_networks": [{"cidr": "192.0.2.0/24", "reputation": "blocked"}]}
        result = CONVERTER.convert(raw, "operator", "audit", 2_000_000_000)
        self.assertEqual([entry["expires_at"] for entry in result["overrides"]], [2_000_000_000, 2_000_000_000])
        self.assertEqual(result, CONVERTER.convert(raw, "operator", "audit", 2_000_000_000))
        self.assertEqual(set(result), {"schema", "overrides", "ip_override_networks"})

    def test_policy_contract_input_is_rejected(self):
        """Signer contracts belong to external plugins and are rejected instead of silently dropped."""
        raw = {"contracts": [{"signer_domain": "relay.example", "allowed_client_cidrs": ["192.0.2.16/28"], "permitted_change_classes": []}]}
        with self.assertRaises(ValueError):
            CONVERTER.convert(raw, "operator", "audit")

    def test_duplicate_json_keys_cannot_drop_input(self):
        """The offline decoder must reject ambiguous source snapshots before producing an artifact."""
        with self.assertRaises(ValueError):
            CONVERTER.unique_object([("domains", []), ("domains", [])])


if __name__ == "__main__":
    unittest.main()
