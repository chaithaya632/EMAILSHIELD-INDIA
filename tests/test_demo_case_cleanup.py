"""
tests/test_demo_case_cleanup.py
Comprehensive regression tests for Demo Case Cleanup and Non-UUID Case ID Resolution in EMAILSHIELD INDIA:
1. _is_uuid correctly distinguishes UUIDs from case numbers like CASE-6EB1E0DA.
2. get_case_record and update_case_metadata query case_number.eq when given string case IDs.
3. close_case() succeeds on non-UUID case numbers.
4. cleanup_demo_cases identifies and deletes only confirmed demo/test cases.
5. Real user cases and cases with preserve_evidence == True are protected.
6. Cross-tenant deletion is rejected under RLS.
"""

import unittest
import uuid
from unittest.mock import patch, MagicMock, call

from core.case_store import (
    _is_uuid,
    get_case_record,
    update_case_metadata,
    close_case,
    cleanup_demo_cases,
    _delete_single_case,
)


class TestDemoCaseCleanupAndCaseIdResolution(unittest.TestCase):
    """Test suite covering case ID resolution, demo cleanup, forensic preservation, and tenant isolation."""

    def setUp(self):
        self.user_a = str(uuid.uuid4())
        self.user_b = str(uuid.uuid4())
        self.valid_uuid = str(uuid.uuid4())
        self.non_uuid_case = "CASE-6EB1E0DA"
        self.demo_case_id = "CASE-DEMO-999"

        self.mock_client_a = MagicMock()
        self.mock_client_a.auth.uid.return_value = self.user_a
        self.mock_client_a.user_id = self.user_a

        self.mock_client_b = MagicMock()
        self.mock_client_b.auth.uid.return_value = self.user_b
        self.mock_client_b.user_id = self.user_b

    # -------------------------------------------------------------------------
    # 1. _is_uuid correctly distinguishes UUIDs from case numbers
    # -------------------------------------------------------------------------
    def test_01_is_uuid_distinguishes_uuids_from_case_numbers(self):
        """
        Verifies _is_uuid returns True for standard UUIDs and False for case numbers
        like CASE-6EB1E0DA, CASE-1234, CASE-DEMO-001, etc.
        """
        # True UUIDs
        self.assertTrue(_is_uuid(self.valid_uuid))
        self.assertTrue(_is_uuid("123e4567-e89b-12d3-a456-426614174000"))
        self.assertTrue(_is_uuid(str(uuid.uuid4())))
        self.assertTrue(_is_uuid(str(uuid.uuid4()).upper()))

        # Non-UUID Case Numbers
        self.assertFalse(_is_uuid("CASE-6EB1E0DA"))
        self.assertFalse(_is_uuid("CASE-1234"))
        self.assertFalse(_is_uuid("CASE-DEMO-001"))
        self.assertFalse(_is_uuid("DEMO-777"))
        self.assertFalse(_is_uuid("CASE-TEST-ABC"))
        self.assertFalse(_is_uuid("6EB1E0DA"))
        self.assertFalse(_is_uuid("MSG-INBOX-001"))

        # Edge cases
        self.assertFalse(_is_uuid(""))
        self.assertFalse(_is_uuid(None))
        self.assertFalse(_is_uuid(12345))
        self.assertFalse(_is_uuid("not-a-uuid-at-all"))
        self.assertFalse(_is_uuid("123e4567-e89b-12d3-a456"))  # truncated

    # -------------------------------------------------------------------------
    # 2. get_case_record and update_case_metadata query case_number.eq when given string case IDs
    # -------------------------------------------------------------------------
    def test_02_get_case_record_queries_case_number_eq_on_string_ids(self):
        """
        Verifies get_case_record queries .eq('case_number', case_id) when given
        non-UUID string case ID, and .eq('id', case_id) when given a UUID.
        """
        # Scenario A: Non-UUID case ID -> case_number.eq
        table_mock = MagicMock()
        select_mock = MagicMock()
        eq_mock = MagicMock()
        exec_mock = MagicMock()

        self.mock_client_a.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.eq.return_value = eq_mock
        eq_mock.execute.return_value = MagicMock(data=[{
            "id": self.valid_uuid,
            "case_number": self.non_uuid_case,
            "status": "Open",
            "assigned_investigator": "Analyst 1",
            "analyst_notes": "Forensic triage",
            "case_severity": "HIGH",
            "raw_json": {"subject": "Suspicious Email", "user_id": self.user_a}
        }])

        rec = get_case_record(self.non_uuid_case, client=self.mock_client_a)

        self.mock_client_a.table.assert_called_with("cases")
        table_mock.select.assert_called_with("*")
        select_mock.eq.assert_called_with("case_number", self.non_uuid_case)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["case_id"], self.non_uuid_case)

        # Scenario B: UUID case ID -> id.eq
        select_mock.reset_mock()
        rec_uuid = get_case_record(self.valid_uuid, client=self.mock_client_a)
        select_mock.eq.assert_called_with("id", self.valid_uuid)

    def test_02b_update_case_metadata_queries_case_number_eq_on_string_ids(self):
        """
        Verifies update_case_metadata queries .eq('case_number', case_id) when given
        non-UUID string case ID, and .eq('id', case_id) when given a UUID.
        """
        table_mock = MagicMock()
        update_mock = MagicMock()
        eq_mock = MagicMock()

        self.mock_client_a.table.return_value = table_mock
        table_mock.update.return_value = update_mock
        update_mock.eq.return_value = eq_mock
        eq_mock.execute.return_value = MagicMock(data=[{"case_number": self.non_uuid_case}])

        # Non-UUID string case ID
        ok = update_case_metadata(
            case_id=self.non_uuid_case,
            status="Closed",
            investigator="Lead Analyst",
            client=self.mock_client_a
        )
        self.assertTrue(ok)
        self.mock_client_a.table.assert_called_with("cases")
        update_mock.eq.assert_called_with("case_number", self.non_uuid_case)

        # UUID case ID
        update_mock.reset_mock()
        ok_uuid = update_case_metadata(
            case_id=self.valid_uuid,
            status="Closed",
            client=self.mock_client_a
        )
        self.assertTrue(ok_uuid)
        update_mock.eq.assert_called_with("id", self.valid_uuid)

    # -------------------------------------------------------------------------
    # 3. close_case() succeeds on non-UUID case numbers
    # -------------------------------------------------------------------------
    def test_03_close_case_succeeds_on_non_uuid_case_number(self):
        """
        Verifies close_case() succeeds on non-UUID case numbers like CASE-6EB1E0DA.
        """
        mock_record = {
            "case_id": self.non_uuid_case,
            "status": "Open",
            "user_id": self.user_a,
            "subject": "Phishing Attempt"
        }

        with patch("core.case_store.is_authorized_caller", return_value=True), \
             patch("core.case_store.get_case_record", return_value=mock_record) as mock_get, \
             patch("core.case_store.update_case_metadata", return_value=True) as mock_update:

            success, err = close_case(
                case_id=self.non_uuid_case,
                user_id=self.user_a,
                client=self.mock_client_a
            )

            self.assertTrue(success)
            self.assertEqual(err, "")
            mock_get.assert_called_once_with(self.non_uuid_case, client=self.mock_client_a)
            mock_update.assert_called_once_with(
                case_id=self.non_uuid_case,
                status="Closed",
                client=self.mock_client_a
            )

    # -------------------------------------------------------------------------
    # 4. cleanup_demo_cases identifies and deletes only confirmed demo/test cases
    # -------------------------------------------------------------------------
    def test_04_cleanup_demo_cases_identifies_and_deletes_only_demo_cases(self):
        """
        Verifies cleanup_demo_cases:
        - Identifies cases with demo prefixes (CASE-DEMO-, DEMO-, CASE-TEST-) or flags.
        - Deletes only confirmed demo cases.
        - Preserves real user cases.
        """
        cases_dataset = [
            {
                "case_id": "CASE-DEMO-001",
                "case_number": "CASE-DEMO-001",
                "user_id": self.user_a,
                "subject": "Demo BEC Attack",
                "is_demo": True
            },
            {
                "case_id": "DEMO-002",
                "case_number": "DEMO-002",
                "user_id": self.user_a,
                "subject": "Synthetic credential harvesting",
                "tags": ["demo", "training"]
            },
            {
                "case_id": "CASE-TEST-003",
                "case_number": "CASE-TEST-003",
                "user_id": self.user_a,
                "subject": "[TEST] EICAR payload",
                "is_test": True
            },
            {
                "case_id": "CASE-REAL-001",
                "case_number": "CASE-REAL-001",
                "user_id": self.user_a,
                "subject": "Production executive invoice inquiry",
                "is_demo": False,
                "is_test": False
            }
        ]

        with patch("core.case_store.is_authorized_caller", return_value=True), \
             patch("core.case_store.get_all_cases", return_value=cases_dataset), \
             patch("core.case_store._delete_single_case", return_value=True) as mock_del:

            res = cleanup_demo_cases(
                user_id=self.user_a,
                client=self.mock_client_a,
                dry_run=False
            )

            self.assertEqual(res["status"], "success")
            self.assertEqual(res["deleted_count"], 3)
            self.assertEqual(res["preserved_count"], 1)
            self.assertIn("CASE-DEMO-001", res["deleted_case_ids"])
            self.assertIn("DEMO-002", res["deleted_case_ids"])
            self.assertIn("CASE-TEST-003", res["deleted_case_ids"])
            self.assertIn("CASE-REAL-001", res["protected_case_ids"])

            # Verify delete was called exactly 3 times for demo cases
            self.assertEqual(mock_del.call_count, 3)
            del_calls = [c[0][0] for c in mock_del.call_args_list]
            self.assertNotIn("CASE-REAL-001", del_calls)

    # -------------------------------------------------------------------------
    # 5. Real user cases and cases with preserve_evidence == True are protected
    # -------------------------------------------------------------------------
    def test_05_preserve_evidence_cases_are_strictly_protected(self):
        """
        BSA 2023 Compliance Invariant:
        Any case with preserve_evidence == True MUST NEVER be deleted,
        even if it has a demo prefix like CASE-DEMO-PRESERVED or is_demo=True.
        """
        cases_with_evidence = [
            {
                "case_id": "CASE-DEMO-PRESERVED",
                "case_number": "CASE-DEMO-PRESERVED",
                "user_id": self.user_a,
                "subject": "Synthetic case with locked forensic evidence",
                "preserve_evidence": True,
                "is_demo": True
            },
            {
                "case_id": "CASE-TEST-FORENSIC-LOCK",
                "case_number": "CASE-TEST-FORENSIC-LOCK",
                "user_id": self.user_a,
                "raw_json": {"preserve_evidence": True, "is_test": True},
                "preserve_evidence": True
            },
            {
                "case_id": "CASE-DEMO-NORMAL",
                "case_number": "CASE-DEMO-NORMAL",
                "user_id": self.user_a,
                "preserve_evidence": False,
                "is_demo": True
            }
        ]

        with patch("core.case_store.is_authorized_caller", return_value=True), \
             patch("core.case_store.get_all_cases", return_value=cases_with_evidence), \
             patch("core.case_store._delete_single_case", return_value=True) as mock_del:

            res = cleanup_demo_cases(
                user_id=self.user_a,
                client=self.mock_client_a,
                dry_run=False
            )

            self.assertEqual(res["status"], "success")
            self.assertEqual(res["deleted_count"], 1)
            self.assertEqual(res["preserved_count"], 2)

            self.assertIn("CASE-DEMO-NORMAL", res["deleted_case_ids"])
            self.assertIn("CASE-DEMO-PRESERVED", res["protected_case_ids"])
            self.assertIn("CASE-TEST-FORENSIC-LOCK", res["protected_case_ids"])

            # Verify mock_del was only called for CASE-DEMO-NORMAL
            mock_del.assert_called_once_with("CASE-DEMO-NORMAL", client=self.mock_client_a)

    # -------------------------------------------------------------------------
    # 6. Cross-tenant deletion is rejected under RLS
    # -------------------------------------------------------------------------
    def test_06_cross_tenant_deletion_is_rejected_under_rls(self):
        """
        Verifies:
        1. User B cannot clean up User A's demo cases.
        2. Unauthenticated caller is denied with status 'denied'.
        3. Cross-tenant cases belonging to other users are protected from deletion.
        """
        # Case A: Unauthenticated caller denied
        res_unauth = cleanup_demo_cases(user_id=None, client=None)
        self.assertEqual(res_unauth["status"], "denied")
        self.assertEqual(res_unauth["deleted_count"], 0)

        # Case B: User B attempting to delete cases that belong to User A
        mixed_tenant_cases = [
            {
                "case_id": "CASE-DEMO-USER-A",
                "case_number": "CASE-DEMO-USER-A",
                "user_id": self.user_a,  # Belongs to User A
                "is_demo": True
            },
            {
                "case_id": "CASE-DEMO-USER-B",
                "case_number": "CASE-DEMO-USER-B",
                "user_id": self.user_b,  # Belongs to User B
                "is_demo": True
            }
        ]

        with patch("core.case_store.is_authorized_caller", return_value=True), \
             patch("core.case_store.get_all_cases", return_value=mixed_tenant_cases), \
             patch("core.case_store._delete_single_case", return_value=True) as mock_del:

            # User B initiates cleanup
            res_b = cleanup_demo_cases(
                user_id=self.user_b,
                client=self.mock_client_b,
                dry_run=False
            )

            self.assertEqual(res_b["status"], "success")
            self.assertEqual(res_b["deleted_count"], 1)
            self.assertIn("CASE-DEMO-USER-B", res_b["deleted_case_ids"])
            # User A's case must be protected from User B's cleanup!
            self.assertIn("CASE-DEMO-USER-A", res_b["protected_case_ids"])
            mock_del.assert_called_once_with("CASE-DEMO-USER-B", client=self.mock_client_b)


if __name__ == "__main__":
    unittest.main()
