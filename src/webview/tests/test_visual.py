from django.test import LiveServerTestCase
from playwright.sync_api import expect
import pytest
from django.urls import reverse

from allauth.account.utils import get_login_redirect_url
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
from allauth.socialaccount.templatetags.socialaccount import provider_login_url
from django.contrib.auth import get_user_model, login
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

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
    MaintainersEdit,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
)

@pytest.fixture
def test_setup(db, client):
    # Create user and log in
    user = User.objects.create_user(username="admin", password="pw")
    user.is_staff = True
    user.save()

    # Create a GitHub social account for the user
    SocialAccount.objects.get_or_create(
        user=user,
        provider="github",
        uid="123456",
        extra_data={"login": "admin"},
    )

    client.login(username="admin", password="pw")

    # Create CVE and related objects
    assigner = Organization.objects.create(uuid=1, short_name="foo")
    cve_record = CveRecord.objects.create(
        cve_id="CVE-2025-0001",
        assigner=assigner,
    )
    description = Description.objects.create(value="Test description")
    metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
    affected_product = AffectedProduct.objects.create(
        package_name="dummy-package"
    )
    affected_product.versions.add(
        Version.objects.create(status=Version.Status.AFFECTED, version="1.0")
    )
    cve_container = cve_record.container.create(
        provider=assigner,
        title="Dummy Title",
    )
    cve_container.affected.add(affected_product)
    cve_container.descriptions.add(description)
    cve_container.metrics.add(metric)

    # Create maintainer and metadata
    maintainer = NixMaintainer.objects.create(
        github_id=123,
        github="testuser",
        name="Test User",
        email="test@example.com",
    )
    meta1 = NixDerivationMeta.objects.create(
        description="First dummy derivation",
        insecure=False,
        available=True,
        broken=False,
        unfree=False,
        unsupported=False,
    )
    meta1.maintainers.add(maintainer)
    meta2 = NixDerivationMeta.objects.create(
        description="Second dummy derivation",
        insecure=False,
        available=True,
        broken=False,
        unfree=False,
        unsupported=False,
    )
    meta2.maintainers.add(maintainer)

    # Create evaluation and derivations
    evaluation = NixEvaluation.objects.create(
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

    derivation1 = NixDerivation.objects.create(
        attribute="package1",
        derivation_path="/nix/store/package1.drv",
        name="package1-1.0",
        metadata=meta1,
        system="x86_64-linux",
        parent_evaluation=evaluation,
    )
    derivation2 = NixDerivation.objects.create(
        attribute="package2",
        derivation_path="/nix/store/package2.drv",
        name="package2-1.0",
        metadata=meta2,
        system="x86_64-linux",
        parent_evaluation=evaluation,
    )

    suggestion = CVEDerivationClusterProposal.objects.create(
        status=CVEDerivationClusterProposal.Status.PENDING,
        cve_id=cve_record.pk,
    )
    DerivationClusterProposalLink.objects.create(
        proposal=suggestion,
        derivation=derivation1,
        provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
    )
    DerivationClusterProposalLink.objects.create(
        proposal=suggestion,
        derivation=derivation2,
        provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
    )

    cache_new_suggestions(suggestion)
    suggestion.refresh_from_db()

    # Return dict with all objects for test access
    return {
        'user': user,
        'client': client,
        'cve_record': cve_record,
        'suggestion': suggestion,
    }

def test_visual(live_server, page, visual_compare, test_setup):
    page.goto(live_server.url)
    visual_compare(page.screenshot(full_page=True), "homepage")
    page.goto(live_server.url + reverse("webview:suggestions_view"))
    visual_compare(page.screenshot(full_page=True), "suggestions")

