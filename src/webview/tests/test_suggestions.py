from collections.abc import Callable
from datetime import timedelta
from unittest.mock import patch

import pytest
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.listeners.cache_suggestions import cache_new_suggestions
from shared.models.cve import (
    AffectedProduct,
    CveRecord,
    Description,
    Metric,
    Organization,
    Version,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
)


@pytest.mark.parametrize(
    "status, remove_package, endpoint",
    [
        (CVEDerivationClusterProposal.Status.PENDING, True, "suggestions"),
        (CVEDerivationClusterProposal.Status.REJECTED, False, "dismissed"),
        (CVEDerivationClusterProposal.Status.ACCEPTED, True, "drafts"),
    ],
)
def test_package_removal(
    live_server: LiveServer,
    as_staff: Page,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_drv: Callable[..., NixDerivation],
    remove_package: bool,
    status: CVEDerivationClusterProposal.Status,
    endpoint: str,
    no_js: bool,
) -> None:
    """Helper method for testing package removal with different statuses"""
    drv1 = make_drv(pname="package1")
    drv2 = make_drv(pname="package2")
    suggestion = make_suggestion(
        status=status,
        drvs={
            drv1: ProvenanceFlags.PACKAGE_NAME_MATCH,
            drv2: ProvenanceFlags.PACKAGE_NAME_MATCH,
        },
    )
    cache_new_suggestions(suggestion)

    as_staff.goto(live_server.url + reverse(f"webview:{endpoint}_view"))
    if not remove_package:
        expect(as_staff.locator('input[value="package1"]')).to_have_count(0)
        return
    else:
        as_staff.locator('input[value="package1"]').click()
        if no_js:
            purge = as_staff.get_by_role("button", name="Purge deleted packages")
            purge.click()
        else:
            as_staff.reload()

    expect(
        as_staff.get_by_text("Matching in Nixpkgs").get_by_text("package1")
    ).to_have_count(0)


class PackageRemovalTests(TestCase):
    def setUp(self) -> None:
        # Create user and log in
        self.user = User.objects.create_user(username="admin", password="pw")
        self.user.is_staff = True
        self.user.save()

        # Create a GitHub social account for the user
        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "admin"},
        )

        self.client = Client()
        self.client.login(username="admin", password="pw")

        # Create CVE and related objects
        self.assigner = Organization.objects.create(uuid=1, short_name="foo")
        self.cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=self.assigner,
        )
        self.description = Description.objects.create(value="Test description")
        self.metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        self.affected_product = AffectedProduct.objects.create(
            package_name="dummy-package"
        )
        self.affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="1.0")
        )
        self.cve_container = self.cve_record.container.create(
            provider=self.assigner,
            title="Dummy Title",
        )
        self.cve_container.affected.add(self.affected_product)
        self.cve_container.descriptions.add(self.description)
        self.cve_container.metrics.add(self.metric)

        # Create maintainer and metadata
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="testuser",
            name="Test User",
            email="test@example.com",
        )
        self.meta1 = NixDerivationMeta.objects.create(
            description="First dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta1.maintainers.add(self.maintainer)

        self.meta2 = NixDerivationMeta.objects.create(
            description="Second dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta2.maintainers.add(self.maintainer)

        # Create evaluation and derivations
        self.evaluation = NixEvaluation.objects.create(
            channel=NixChannel.objects.create(
                staging_branch="release-24.05",
                channel_branch="nixos-24.05",
                head_sha1_commit="deadbeef",
                state=NixChannel.ChannelState.STABLE,
                release_version="24.05",
                repository="https://github.com/NixOS/nixpkgs",
            ),
            commit_sha1="deadbeef",
            state=NixEvaluation.EvaluationState.COMPLETED,
        )

        # Create two derivations for the same suggestion
        self.derivation1 = NixDerivation.objects.create(
            attribute="package1",
            derivation_path="/nix/store/package1.drv",
            name="package1-1.0",
            metadata=self.meta1,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        self.derivation2 = NixDerivation.objects.create(
            attribute="package2",
            derivation_path="/nix/store/package2.drv",
            name="package2-1.0",
            metadata=self.meta2,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create suggestion and link both derivations
        self.suggestion = CVEDerivationClusterProposal.objects.create(
            status=CVEDerivationClusterProposal.Status.PENDING,
            cve_id=self.cve_record.pk,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation1,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation2,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Cache the suggestion to populate the packages payload
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

    def test_packages_are_initially_present(self) -> None:
        # Verify both packages are in the cached payload
        cached_packages = self.suggestion.cached.payload["packages"]
        self.assertIn("package1", cached_packages)
        self.assertIn("package2", cached_packages)

    def test_restore_package(self) -> None:
        """Test removing a package from a suggestion in pending status (editable)"""
        # Request to keep only derivation1 (remove derivation2)
        url = reverse("webview:suggestions_view")
        response = self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )
        self.assertEqual(response.status_code, 200)

        # Verify package2 has been removed from the cached payload
        self.suggestion.refresh_from_db()
        cached_packages = self.suggestion.cached.payload["packages"]
        self.assertIn("package1", cached_packages)
        self.assertNotIn("package2", cached_packages)

        # Restore package2 by including both derivation IDs again
        restore_response = self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1", "package2"],
            },
        )
        self.assertEqual(restore_response.status_code, 200)

        # Refresh and verify both packages are present again in the cached payload
        self.suggestion.refresh_from_db()
        cached_packages = self.suggestion.cached.payload["packages"]
        self.assertIn("package1", cached_packages)
        self.assertIn("package2", cached_packages)


class PackageEditActivityLogTests(TestCase):
    def setUp(self) -> None:
        # Create user and log in
        self.user = User.objects.create_user(username="admin", password="pw")
        self.user.is_staff = True
        self.user.save()

        # Create a GitHub social account for the user
        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "admin"},
        )

        self.client = Client()
        self.client.login(username="admin", password="pw")

        # Create CVE and related objects
        self.assigner = Organization.objects.create(uuid=1, short_name="foo")
        self.cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=self.assigner,
        )
        self.description = Description.objects.create(value="Test description")
        self.metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        self.affected_product = AffectedProduct.objects.create(
            package_name="dummy-package"
        )
        self.affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="1.0")
        )
        self.cve_container = self.cve_record.container.create(
            provider=self.assigner,
            title="Dummy Title",
        )
        self.cve_container.affected.add(self.affected_product)
        self.cve_container.descriptions.add(self.description)
        self.cve_container.metrics.add(self.metric)

        # Create maintainer and metadata
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="testuser",
            name="Test User",
            email="test@example.com",
        )
        self.meta1 = NixDerivationMeta.objects.create(
            description="First dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta1.maintainers.add(self.maintainer)

        self.meta2 = NixDerivationMeta.objects.create(
            description="Second dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta2.maintainers.add(self.maintainer)

        # Create evaluation and derivations
        self.evaluation = NixEvaluation.objects.create(
            channel=NixChannel.objects.create(
                staging_branch="release-24.05",
                channel_branch="nixos-24.05",
                head_sha1_commit="deadbeef",
                state=NixChannel.ChannelState.STABLE,
                release_version="24.05",
                repository="https://github.com/NixOS/nixpkgs",
            ),
            commit_sha1="deadbeef",
            state=NixEvaluation.EvaluationState.COMPLETED,
        )

        # Create two derivations for the same suggestion
        self.derivation1 = NixDerivation.objects.create(
            attribute="package1",
            derivation_path="/nix/store/package1.drv",
            name="package1-1.0",
            metadata=self.meta1,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        self.derivation2 = NixDerivation.objects.create(
            attribute="package2",
            derivation_path="/nix/store/package2.drv",
            name="package2-1.0",
            metadata=self.meta2,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create suggestion and link both derivations
        self.suggestion = CVEDerivationClusterProposal.objects.create(
            status=CVEDerivationClusterProposal.Status.PENDING,
            cve_id=self.cve_record.pk,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation1,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation2,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Cache the suggestion to populate the packages payload
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

    def test_package_removal_creates_activity_log_entry(self) -> None:
        """Test that removing a package creates an activity log entry"""
        # Remove package2 by only selecting package1
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        # Check that activity log data is properly sent to the template context
        # by making a GET request to the suggestions view
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached to the suggestion object
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 1)

        # Verify the activity log entry matches what we expect
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "package.remove")
        self.assertEqual(log_entry.package_names[0], "package2")
        self.assertEqual(log_entry.username, "admin")

    def test_package_restoration_within_time_window_cancels_events(self) -> None:
        """Test that restoring a removed package within time window cancels both events"""

        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        with patch(
            "django.utils.timezone.now",
            return_value=timezone.now() + timedelta(seconds=5),
        ):
            self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "attribute": ["package1", "package2"],
                },
            )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains no events
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 0)

    def test_package_restoration_outside_time_window_preserves_events(self) -> None:
        """Test that restoring a removed package outside time window preserves both events"""
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        with patch(
            "django.utils.timezone.now",
            return_value=timezone.now() + timedelta(seconds=40),
        ):
            self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "attribute": ["package1", "package2"],
                },
            )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains both events
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 2)

        # Verify the activity log entries match what we expect
        log_removal = our_suggestion.activity_log[0]
        log_restoration = our_suggestion.activity_log[1]

        self.assertEqual(log_removal.action, "package.remove")
        self.assertEqual(log_removal.package_names[0], "package2")

        self.assertEqual(log_restoration.action, "package.add")
        self.assertEqual(log_restoration.package_names[0], "package2")

    def test_multiple_package_edits_are_batched_in_activity_log(self) -> None:
        """Test that multiple package edits by the same user are batched together"""
        # Create a third derivation
        meta3 = NixDerivationMeta.objects.create(
            description="Third dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        meta3.maintainers.add(self.maintainer)

        derivation3 = NixDerivation.objects.create(
            attribute="package3",
            derivation_path="/nix/store/package3.drv",
            name="package3-1.0",
            metadata=meta3,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=derivation3,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Re-cache the suggestion to include the new package
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

        # Remove multiple packages by only selecting package1
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains the batched event
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 1)

        # Verify the batched activity log entry matches what we expect
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "package.remove")
        self.assertEqual(len(log_entry.package_names), 2)
        self.assertIn("package2", log_entry.package_names)
        self.assertIn("package3", log_entry.package_names)

    def test_package_edits_by_different_users_not_batched(self) -> None:
        """Test that package edits by different users are not batched together"""
        # Create another user
        other_user = User.objects.create_user(username="other", password="pw")
        other_user.is_staff = True
        other_user.save()

        SocialAccount.objects.get_or_create(
            user=other_user,
            provider="github",
            uid="789012",
            extra_data={"login": "other"},
        )

        # First user removes package2
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        # Switch to other user and restore package2, then remove package1
        other_client = Client()
        other_client.login(username="other", password="pw")

        other_client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package2"],
            },
        )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains separate events for different users
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertGreaterEqual(len(our_suggestion.activity_log), 2)

        # Verify that the activity log entries have different usernames
        context_package_events = [
            e
            for e in our_suggestion.activity_log
            if hasattr(e, "action") and e.action.startswith("package.")
        ]
        context_usernames = {event.username for event in context_package_events}
        self.assertIn("admin", context_usernames)
        self.assertIn("other", context_usernames)


class MaintainersEditActivityLogTests(TestCase):
    def setUp(self) -> None:
        # Create user and log in
        self.user = User.objects.create_user(username="admin", password="pw")
        self.user.is_staff = True
        self.user.save()

        # Create a GitHub social account for the user
        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "admin"},
        )

        self.client = Client()
        self.client.login(username="admin", password="pw")

        # Create CVE and related objects
        self.assigner = Organization.objects.create(uuid=1, short_name="foo")
        self.cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=self.assigner,
        )
        self.description = Description.objects.create(value="Test description")
        self.metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        self.affected_product = AffectedProduct.objects.create(
            package_name="dummy-package"
        )
        self.affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="1.0")
        )
        self.cve_container = self.cve_record.container.create(
            provider=self.assigner,
            title="Dummy Title",
        )
        self.cve_container.affected.add(self.affected_product)
        self.cve_container.descriptions.add(self.description)
        self.cve_container.metrics.add(self.metric)

        # Create maintainers
        self.existing_maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="existinguser",
            name="Existing User",
            email="existing@example.com",
        )

        self.other_maintainer = NixMaintainer.objects.create(
            github_id=456,
            github="otheruser",
            name="Other User",
            email="other@example.com",
        )

        self.third_maintainer = NixMaintainer.objects.create(
            github_id=789,
            github="thirduser",
            name="Third User",
            email="third@example.com",
        )

        # Create metadata and derivation
        self.meta = NixDerivationMeta.objects.create(
            description="Dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta.maintainers.add(self.existing_maintainer)

        # Create evaluation and derivation
        self.evaluation = NixEvaluation.objects.create(
            channel=NixChannel.objects.create(
                staging_branch="release-24.05",
                channel_branch="nixos-24.05",
                head_sha1_commit="deadbeef",
                state=NixChannel.ChannelState.STABLE,
                release_version="24.05",
                repository="https://github.com/NixOS/nixpkgs",
            ),
            commit_sha1="deadbeef",
            state=NixEvaluation.EvaluationState.COMPLETED,
        )

        self.derivation = NixDerivation.objects.create(
            attribute="dummypackage",
            derivation_path="/nix/store/dummy.drv",
            name="dummy-package-1.0",
            metadata=self.meta,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create suggestion and link derivation
        self.suggestion = CVEDerivationClusterProposal.objects.create(
            status=CVEDerivationClusterProposal.Status.ACCEPTED,
            cve_id=self.cve_record.pk,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Cache the suggestion
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

    def test_maintainer_addition_creates_activity_log_entry(self) -> None:
        """Test that adding a maintainer creates an activity log entry"""
        # Add a maintainer that exists in the database but not in the suggestion
        url = reverse("webview:add_maintainer")
        response = self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "otheruser",
            },
        )
        self.assertEqual(response.status_code, 200)

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:drafts_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached to the suggestion object
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 1)

        # Verify the activity log entry matches what we expect
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "maintainers.add")
        self.assertEqual(log_entry.maintainers[0]["github"], "otheruser")
        self.assertEqual(log_entry.username, "admin")

    def test_maintainer_removal_creates_activity_log_entry(self) -> None:
        """Test that removing a maintainer creates an activity log entry"""
        # Remove the existing maintainer using SelectableMaintainerView
        url = reverse("webview:edit_maintainers")
        response = self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "edit_maintainer_id": str(self.existing_maintainer.github_id),
            },
        )
        self.assertEqual(response.status_code, 200)

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:drafts_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached to the suggestion object
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 1)

        # Verify the activity log entry matches what we expect
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "maintainers.remove")
        self.assertEqual(log_entry.maintainers[0]["github"], "existinguser")
        self.assertEqual(log_entry.username, "admin")

    def test_maintainer_restoration_within_time_window_cancels_events(self) -> None:
        """Test that restoring a removed maintainer within time window cancels both events"""

        # First remove the existing maintainer
        url = reverse("webview:edit_maintainers")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "edit_maintainer_id": str(self.existing_maintainer.github_id),
            },
        )

        # Then restore the maintainer by clicking the button again
        with patch(
            "django.utils.timezone.now",
            return_value=timezone.now() + timedelta(seconds=5),
        ):
            self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "edit_maintainer_id": str(self.existing_maintainer.github_id),
                },
            )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:drafts_view"))
        self.assertEqual(response.status_code, 200)

        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains no events
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 0)

    def test_maintainer_restoration_outside_time_window_preserves_events(self) -> None:
        """Test that restoring a removed maintainer outside time window preserves both events"""
        # First remove the existing maintainer
        url = reverse("webview:edit_maintainers")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "edit_maintainer_id": str(self.existing_maintainer.github_id),
            },
        )

        # Then restore the maintainer by clicking the button again
        with patch(
            "django.utils.timezone.now",
            return_value=timezone.now() + timedelta(seconds=40),
        ):
            self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "edit_maintainer_id": str(self.existing_maintainer.github_id),
                },
            )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:drafts_view"))
        self.assertEqual(response.status_code, 200)

        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains both events
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 2)

        # Verify the activity log entries match what we expect
        log_removal = our_suggestion.activity_log[0]
        log_restoration = our_suggestion.activity_log[1]

        self.assertEqual(log_removal.action, "maintainers.remove")
        self.assertEqual(log_removal.maintainers[0]["github"], "existinguser")

        self.assertEqual(log_restoration.action, "maintainers.add")
        self.assertEqual(log_restoration.maintainers[0]["github"], "existinguser")

    def test_multiple_maintainer_edits_are_batched_in_activity_log(self) -> None:
        """Test that multiple maintainer edits by the same user are batched together"""
        # Add two maintainers consecutively
        self.client.post(
            reverse("webview:add_maintainer"),
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "otheruser",
            },
        )
        self.client.post(
            reverse("webview:add_maintainer"),
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "thirduser",
            },
        )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:drafts_view"))
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify both additions are batched into a single log entry
        self.assertEqual(len(our_suggestion.activity_log), 1)
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "maintainers.add")
        self.assertEqual(len(log_entry.maintainers), 2)
        github_handles = [m["github"] for m in log_entry.maintainers]
        self.assertIn("otheruser", github_handles)
        self.assertIn("thirduser", github_handles)

    def test_maintainer_edits_by_different_users_not_batched(self) -> None:
        """Test that maintainer edits by different users are not batched together"""
        # Create another user
        other_user = User.objects.create_user(username="other", password="pw")
        other_user.is_staff = True
        other_user.save()

        SocialAccount.objects.get_or_create(
            user=other_user,
            provider="github",
            uid="789012",
            extra_data={"login": "other"},
        )

        # First user adds a maintainer
        self.client.post(
            reverse("webview:add_maintainer"),
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "otheruser",
            },
        )

        # Second user adds a different maintainer
        other_client = Client()
        other_client.login(username="other", password="pw")
        other_client.post(
            reverse("webview:add_maintainer"),
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "thirduser",
            },
        )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:drafts_view"))
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        self.assertGreaterEqual(len(our_suggestion.activity_log), 2)
        context_maintainer_events = [
            e
            for e in our_suggestion.activity_log
            if hasattr(e, "action") and e.action.startswith("maintainers.")
        ]
        context_usernames = {event.username for event in context_maintainer_events}
        self.assertIn("admin", context_usernames)
        self.assertIn("other", context_usernames)
