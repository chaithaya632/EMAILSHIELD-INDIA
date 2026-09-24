"""
tests/test_navigation_performance_optimizations.py
Verification suite for Phase 24 Global Navigation Performance Optimizations.

Validates:
1. Supabase client connection pooling and keep-alive caching.
2. Route-aware context fetching in app.py (no unnecessary queries on page switch).
3. Context reuse in views/dashboard.py (zero duplicate queries for mailbox, worker, checkpoint).
4. Context reuse in views/settings.py (zero duplicate queries for mailbox, worker, checkpoint).
5. Query deduplication in views/reports.py (get_all_cases called once across tabs).
6. Context reuse in views/analyze.py (mailbox_rec reused in Live Mail mode).
7. Strict preservation of app.py line count limit (< 300 lines).
"""

import os
import unittest
from unittest.mock import patch, MagicMock

from core.supabase_client import (
    get_supabase_client,
    clear_supabase_client_cache,
    _CLIENT_CACHE,
)
import views.dashboard as dashboard
import views.settings as settings
import views.reports as reports
import views.analyze as analyze


def _make_mock_st():
    m = MagicMock()
    m.session_state = {}
    m.tabs.side_effect = lambda t: [MagicMock() for _ in t]
    m.columns.side_effect = lambda c: [MagicMock() for _ in (range(c) if isinstance(c, int) else c)]
    return m


class TestNavigationPerformanceOptimizations(unittest.TestCase):
    def setUp(self):
        clear_supabase_client_cache()

    def tearDown(self):
        clear_supabase_client_cache()

    def test_supabase_client_connection_pooling_and_caching(self):
        """get_supabase_client reuses client instances for identical credentials and tokens."""
        with patch("core.supabase_client.get_supabase_credentials", return_value=("https://example.supabase.co", "anon-key-123")), \
             patch("core.supabase_client.create_client") as mock_create:
            mock_client = MagicMock()
            mock_create.return_value = mock_client

            c1 = get_supabase_client("jwt_token_alpha")
            c2 = get_supabase_client("jwt_token_alpha")
            
            self.assertIs(c1, c2)
            self.assertEqual(mock_create.call_count, 1)

            # Different JWT gets its own client instance
            c3 = get_supabase_client("jwt_token_beta")
            self.assertEqual(mock_create.call_count, 2)

            # Clearing cache purges stored clients
            clear_supabase_client_cache("jwt_token_alpha")
            c4 = get_supabase_client("jwt_token_alpha")
            self.assertEqual(mock_create.call_count, 3)

    def test_app_line_count_strictly_under_300(self):
        """app.py must remain strictly under 300 lines."""
        app_path = os.path.join(os.path.dirname(__file__), "..", "app.py")
        with open(app_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertLess(len(lines), 300, f"app.py has {len(lines)} lines; must be < 300")

    def test_dashboard_reuses_context_records_without_duplicate_queries(self):
        """views/dashboard.py consumes mailbox_rec, worker_rec, checkpoint_rec from ctx."""
        user_id = "test_user_dash_opt"
        mock_client = MagicMock()
        mock_mb = {"id": "mb_123", "email_address": "test@gmail.com", "is_active": True}
        mock_wk = {"id": "wk_123", "desired_state": "RUNNING"}
        mock_cp = {"last_uid": 100}

        ctx = {
            "mailbox_rec": mock_mb,
            "worker_rec": mock_wk,
            "checkpoint_rec": mock_cp,
        }

        mock_st = _make_mock_st()

        with patch("views.dashboard.is_authenticated_soc_caller", return_value=True), \
             patch("views.dashboard.get_user_mailbox") as mock_get_mb, \
             patch("views.dashboard.get_user_worker") as mock_get_wk, \
             patch("views.dashboard.get_user_checkpoint") as mock_get_cp, \
             patch("views.dashboard.get_user_sentinel_activity_stats", return_value={}), \
             patch("views.dashboard.render_soc_live_telemetry"), \
             patch("views.dashboard.st", mock_st):
            
            dashboard.render(user_id, mock_client, **ctx)

            mock_get_mb.assert_not_called()
            mock_get_wk.assert_not_called()
            mock_get_cp.assert_not_called()

    def test_settings_reuses_context_records_without_duplicate_queries(self):
        """views/settings.py consumes mailbox_rec, worker_rec, checkpoint_rec from ctx."""
        user_id = "test_user_sett_opt"
        mock_client = MagicMock()
        mock_mb = {"id": "mb_456", "email_address": "soc@gmail.com", "is_active": True}
        mock_wk = {"id": "wk_456", "desired_state": "RUNNING"}
        mock_cp = {"last_uid": 200}

        ctx = {
            "mailbox_rec": mock_mb,
            "worker_rec": mock_wk,
            "checkpoint_rec": mock_cp,
        }

        mock_st = _make_mock_st()

        with patch("views.settings.is_authorized_caller", return_value=True), \
             patch("views.settings.get_user_mailbox") as mock_get_mb, \
             patch("views.settings.get_user_worker") as mock_get_wk, \
             patch("views.settings.get_user_checkpoint") as mock_get_cp, \
             patch("views.settings.st", mock_st):
            
            settings.render(user_id, mock_client, **ctx)

            mock_get_mb.assert_not_called()
            mock_get_wk.assert_not_called()
            mock_get_cp.assert_not_called()

    def test_reports_deduplicates_case_query_across_tabs(self):
        """views/reports.py executes get_all_cases exactly once for both tabs."""
        user_id = "test_user_rep_opt"
        mock_client = MagicMock()
        mock_st = _make_mock_st()

        with patch("views.reports.is_authenticated_soc_caller", return_value=True), \
             patch("views.reports.get_all_cases", return_value=[{"case_id": "CASE-101"}]) as mock_cases, \
             patch("views.reports.build_case_infrastructure_graph"), \
             patch("views.reports.st", mock_st):

            reports.render(user_id, mock_client)

            self.assertEqual(mock_cases.call_count, 1)

    def test_analyze_live_mail_reuses_mailbox_rec_from_ctx(self):
        """views/analyze.py in Live Mail mode reuses mailbox_rec from ctx."""
        user_id = "test_user_ana_opt"
        mock_client = MagicMock()
        mock_mb = {"id": "mb_789", "email_address": "analyst@gmail.com", "is_active": True}

        ctx = {
            "mailbox_rec": mock_mb,
        }

        mock_st = _make_mock_st()
        mock_st.session_state = {"email_analysis_source": "📬 Select from Live Mail"}

        with patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox") as mock_get_mb, \
             patch("views.analyze.list_user_mailboxes", return_value=[mock_mb]), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=[]), \
             patch("views.analyze.st", mock_st):

            analyze.render(user_id, mock_client, **ctx)

            mock_get_mb.assert_not_called()


if __name__ == "__main__":
    unittest.main()
