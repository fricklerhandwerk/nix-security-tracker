from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
import responses
from github import Github

from shared.github_events import sync_github_events
from shared.models.issue import EventType, NixpkgsEvent, NixpkgsIssue
from shared.tests.fake_github import GRAPHQL_URL, FakeGitHub


@pytest.fixture
def fake_github() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    with responses.RequestsMock() as mock:
        mock.add_callback(
            responses.POST,
            GRAPHQL_URL,
            callback=fake.handle,
        )
        yield fake


def test_closed_issue_records_close_time(
    issue: NixpkgsIssue, fake_github: FakeGitHub
) -> None:
    NixpkgsEvent.objects.create(
        issue=issue,
        event_type=EventType.ISSUE | EventType.OPENED,
        url="https://github.com/NixOS/nixpkgs/issues/1",
    )
    fake_github.issues["NixOS/nixpkgs"] = {
        1: {
            "createdAt": "2026-10-01T00:00:00Z",
            "timeline": [
                {
                    "__typename": "ClosedEvent",
                    "createdAt": "2026-10-02T12:00:00Z",
                    "stateReason": "COMPLETED",
                },
            ],
        },
    }

    sync_github_events(Github())

    closed = NixpkgsEvent.objects.get(
        issue=issue,
        event_type=EventType.ISSUE | EventType.CLOSED | EventType.COMPLETED,
    )
    assert closed.occurred_at == datetime(2026, 10, 2, 12, tzinfo=UTC)
