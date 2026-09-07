"""Golden offline-conversion tests for operator intent, independent of runtime implementation."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("static_conversion", Path(__file__).with_name("convert-static-reputation.py"))
CONVERTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONVERTER)


class StaticConversionTest(unittest.TestCase):
    """Exercise explicit bands, absence, exact network scope and correlated Recipe conversion."""

    def test_all_bands_and_absence(self):
        """Each explicit source entry remains an exact same-band override and absence stays absent."""
        for band in ("trusted", "neutral", "blocked"):
            with self.subTest(band=band):
                result = CONVERTER.convert({"domains": [{"domain": "relay.example", "reputation": band}], "client_networks": [{"cidr": "192.0.2.16/28", "reputation": band}]}, "operator", "audit")
                self.assertEqual([entry["band"] for entry in result["overrides"]], [band, band])
                self.assertEqual(result["ip_override_networks"], ["192.0.2.16/28"])
                self.assertTrue(all(entry["origin"] == "cutover.static_dkim2_v4" for entry in result["overrides"]))
        self.assertEqual(CONVERTER.convert({}, "operator", "audit")["overrides"], [])

    def test_contract_and_recipe_authority_are_separate(self):
        """Network identity does not grant Recipe permissions and header-only authorization denies body-only edits."""
        raw = {"contracts": [{"signer_domain": "relay.example", "allowed_client_cidrs": ["192.0.2.16/28"], "permitted_change_classes": ["header.rewrite"]}]}
        result = CONVERTER.convert(raw, "operator", "audit")
        self.assertEqual(result["identity_contracts"][0]["current_peer_cidrs"], ["192.0.2.16/28"])
        where = result["policy_rules"][1]["if"]["records"]["where"]["all"]
        self.assertEqual(where, [{"field": "signer_domain", "eq": "relay.example"}, {"field": "change_classes", "contains_any": ["body.rewrite"]}])
        self.assertTrue(all(rule["then"]["decision"] == "deny" for rule in result["policy_rules"]))
        self.assertEqual(result["overrides"], [])

    def test_no_widening_or_unknown_classification(self):
        """Conversion rejects malformed input instead of rounding a prefix or inventing neutrality."""
        for raw in ({"domains": [{"domain": "relay.example", "reputation": "unknown"}]}, {"client_networks": [{"cidr": "192.0.2.17/28", "reputation": "trusted"}]}, {"unexpected": True}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                CONVERTER.convert(raw, "operator", "audit")

    def test_every_recipe_permission_subset_and_expiry(self):
        """Every former change-class permission is preserved as the exact complementary deny set."""
        for changes in ([], ["body.rewrite"], ["header.rewrite"], ["body.rewrite", "header.rewrite"]):
            raw = {"domains": [{"domain": "relay.example", "reputation": "neutral"}], "contracts": [{"signer_domain": "relay.example", "allowed_client_cidrs": ["192.0.2.0/24"], "permitted_change_classes": changes}]}
            result = CONVERTER.convert(raw, "operator", "audit", 2_000_000_000)
            self.assertEqual(result["overrides"][0]["expires_at"], 2_000_000_000)
            self.assertEqual(result, CONVERTER.convert(raw, "operator", "audit", 2_000_000_000))
            forbidden = sorted({"body.rewrite", "header.rewrite"} - set(changes))
            self.assertEqual(len(result["policy_rules"]), 1 + bool(forbidden))
            if forbidden:
                self.assertEqual(result["policy_rules"][1]["if"]["records"]["where"]["all"][1]["contains_any"], forbidden)

    def test_duplicate_json_keys_cannot_drop_input(self):
        """The offline decoder must reject ambiguous source snapshots before producing an artifact."""
        with self.assertRaises(ValueError):
            CONVERTER.unique_object([("domains", []), ("domains", [])])


if __name__ == "__main__":
    unittest.main()
