import unittest
import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE_DIR = Path(__file__).parent.parent
DASHBOARD_FILE = BASE_DIR / "views" / "dashboard.py"

from core.case_store import (
    close_all_open_cases,
    clear_threat_activity,
    save_case,
    get_soc_threat_activity,
    get_soc_investigation_queue
)


class TestSocLiveTelemetryAndBulkControls(unittest.TestCase):
    def setUp(self):
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            self.code = f.read()
        self.tree = ast.parse(self.code)

    def test_imports_close_all_and_clear_activity(self):
        """Ensure close_all_open_cases and clear_threat_activity are imported from core.case_store."""
        found_close_all = False
        found_clear_activity = False
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and node.module == "core.case_store":
                names = [alias.name for alias in node.names]
                if "close_all_open_cases" in names:
                    found_close_all = True
                if "clear_threat_activity" in names:
                    found_clear_activity = True

        self.assertTrue(found_close_all, "close_all_open_cases must be imported from core.case_store")
        self.assertTrue(found_clear_activity, "clear_threat_activity must be imported from core.case_store")

    def test_fragment_decorator_and_telemetry_function(self):
        """Ensure render_soc_live_telemetry has @st.fragment(run_every=2)."""
        found_func = False
        has_fragment_decorator = False
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == "render_soc_live_telemetry":
                found_func = True
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call):
                        # check st.fragment(run_every=2)
                        func_name = ""
                        if isinstance(dec.func, ast.Attribute):
                            func_name = f"{dec.func.value.id}.{dec.func.attr}"
                        if func_name == "st.fragment":
                            for kw in dec.keywords:
                                if kw.arg == "run_every" and getattr(kw.value, "value", None) == 2:
                                    has_fragment_decorator = True

        self.assertTrue(found_func, "render_soc_live_telemetry function not found")
        self.assertTrue(has_fragment_decorator, "@st.fragment(run_every=2) decorator not found on render_soc_live_telemetry")

    def test_clear_threat_activity_button_and_dialog(self):
        """Verify Recent Threat Activity header has clear activity button and confirmation dialog."""
        self.assertIn("btn_clear_threat_act", self.code)
        self.assertIn("btn_confirm_clear_act", self.code)
        self.assertIn("btn_cancel_clear_act", self.code)
        self.assertIn("clear_threat_activity(", self.code)
        self.assertIn('st.rerun(scope="fragment")', self.code)

    def test_close_all_cases_button_and_dialog(self):
        """Verify Active Incident Triage Queue has close all button and confirmation dialog."""
        self.assertIn("btn_soc_dash_close_all", self.code)
        self.assertIn("btn_confirm_close_all", self.code)
        self.assertIn("btn_cancel_close_all", self.code)
        self.assertIn("close_all_open_cases(", self.code)

    def test_case_store_functions_authorization(self):
        """Test close_all_open_cases and clear_threat_activity deny unauthenticated calls."""
        res1 = close_all_open_cases(user_id=None, client=None)
        self.assertFalse(res1.get("success"))
        self.assertIn("denied", res1.get("error", "").lower())

        res2 = clear_threat_activity(user_id=None, client=None)
        self.assertFalse(res2.get("success"))
        self.assertIn("denied", res2.get("error", "").lower())


if __name__ == "__main__":
    unittest.main()
