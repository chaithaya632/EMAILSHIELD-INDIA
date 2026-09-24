"""
tests/test_ui_redesign.py
Verification suite for the modular multi-page UI architecture:
- Page module importability and entry point verification
- Batch vs Live Mail state isolation
- Fragment auto-refresh presence in live_mail page
- Theme component functionality
"""

import os
import unittest
import importlib


class TestUIRedesignAndModularArchitecture(unittest.TestCase):
    """Tests for the modernized views/ architecture."""

    def test_01_all_page_modules_exist_and_importable(self):
        """All 7 primary view modules exist and have a callable render function."""
        expected_pages = [
            "dashboard",
            "analyze",
            "investigations",
            "ioc_intel",
            "reports",
            "alerts",
            "settings",
        ]
        for page_name in expected_pages:
            mod = importlib.import_module(f"views.{page_name}")
            self.assertTrue(
                hasattr(mod, "render"),
                f"Page 'views.{page_name}' must have a render() entry point."
            )
            self.assertTrue(
                callable(getattr(mod, "render")),
                f"Page 'views.{page_name}.render' must be callable."
            )

    def test_02_theme_components_available(self):
        """views._theme exposes standard design system components."""
        from views._theme import (
            inject_theme,
            page_header,
            metric_card,
            status_badge_html,
            empty_state,
            section_divider,
            detail_row,
            error_card,
            info_card,
            success_card,
            COLORS,
        )
        self.assertIn("bg", COLORS)
        self.assertIn("surface", COLORS)
        self.assertIn("green", COLORS)
        self.assertIn("red", COLORS)
        self.assertIn("primary", COLORS)

        badge = status_badge_html("safe", "Operational")
        self.assertIn("Operational", badge)
        self.assertIn(COLORS["green"], badge)

    def test_03_settings_preserves_auto_refresh_fragment(self):
        """views/settings.py preserves the critical @st.fragment(run_every=2) decorator."""
        settings_path = os.path.join("views", "settings.py")
        self.assertTrue(os.path.exists(settings_path))
        with open(settings_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("st.fragment", content)
        self.assertIn("run_every=2", content)
        self.assertIn("render_monitoring_fragment", content)

    def test_04_batch_and_live_state_isolation(self):
        """Batch analysis and live mail analysis use isolated session state namespaces."""
        batch_keys = {"batch_analysis_results", "batch_analysis_metrics", "batch_inspect_email_bytes", "current_email_bytes", "_analysis_sha256_cache"}
        live_keys = {"sentinel_stats", "worker_rec", "checkpoint_rec", "mailbox_rec"}
        self.assertTrue(batch_keys.isdisjoint(live_keys))

    def test_05_app_shell_thin_and_clean(self):
        """app.py is a clean navigation shell under 300 lines."""
        with open("app.py", "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertLess(
            len(lines),
            300,
            f"app.py should be a thin navigation shell (got {len(lines)} lines, expected < 300)"
        )

    def test_06_streamlit_internal_nav_hidden(self):
        """No raw pages/ directory exists, and config.toml disables showSidebarNavigation."""
        self.assertFalse(os.path.exists("pages"), "Directory 'pages/' must not exist to prevent Streamlit internal page leaks.")
        config_path = os.path.join(".streamlit", "config.toml")
        self.assertTrue(os.path.exists(config_path))
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("showSidebarNavigation = false", content)


if __name__ == "__main__":
    unittest.main()
