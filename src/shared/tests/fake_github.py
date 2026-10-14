"""
In-memory stand-in for GitHub's GraphQL API, speaking GitHub's own vocabulary.
"""

import json
import os
from typing import Any

from graphql import GraphQLResolveInfo, build_schema, graphql_sync
from graphql.pyutils import camel_to_snake
from requests import PreparedRequest

with open(os.environ["GH_GRAPHQL_SCHEMA"]) as f:
    GITHUB_SCHEMA = build_schema(f.read())

# PyGithub addresses the endpoint with an explicit port.
GRAPHQL_URL = "https://api.github.com:443/graphql"


def page(
    nodes: list[dict[str, Any]],
    first: int | None = None,
    after: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    start = int(after) if after else 0
    end = start + first if first is not None else len(nodes)
    return {
        "totalCount": len(nodes),
        "nodes": nodes[start:end],
        "pageInfo": {
            "hasNextPage": end < len(nodes),
            "hasPreviousPage": start > 0,
            "startCursor": str(start),
            "endCursor": str(min(end, len(nodes))),
        },
    }


class FakeGitHub:
    def __init__(self) -> None:
        self.issues: dict[str, dict[int, dict[str, Any]]] = {}

    def issue(self, data: dict[str, Any]) -> dict[str, Any]:
        timeline = data.get("timeline", [])

        def timeline_items(_info: GraphQLResolveInfo, **args: Any) -> dict[str, Any]:
            # GitHub names the filter value for each item type by converting the type name, e.g. `CLOSED_EVENT` for `ClosedEvent`.
            item_types = args.get("itemTypes")
            nodes = [
                node
                for node in timeline
                if item_types is None
                or camel_to_snake(node["__typename"]).upper() in item_types
            ]
            return page(nodes, **args)

        return {**data, "timelineItems": timeline_items}

    def repository(
        self, _info: GraphQLResolveInfo, owner: str, name: str, **_: Any
    ) -> dict[str, Any] | None:
        issues = self.issues.get(f"{owner}/{name}")
        if issues is None:
            return None

        def issue(_info: GraphQLResolveInfo, number: int) -> dict[str, Any] | None:
            data = issues.get(number)
            return self.issue(data) if data is not None else None

        return {"issue": issue}

    def root(self) -> dict[str, Any]:
        return {
            "rateLimit": lambda _info, **_: {
                "cost": 1,
                "limit": 5000,
                "nodeCount": 0,
                "remaining": 5000,
                "resetAt": "2026-01-01T00:00:00Z",
                "used": 0,
            },
            "repository": self.repository,
        }

    def handle(self, request: PreparedRequest) -> tuple[int, dict[str, str], str]:
        assert isinstance(request.body, str | bytes)
        body = json.loads(request.body)
        result = graphql_sync(
            GITHUB_SCHEMA,
            body["query"],
            root_value=self.root(),
            variable_values=body.get("variables"),
        )
        response: dict[str, Any] = {"data": result.data}
        if result.errors:
            response["errors"] = [error.formatted for error in result.errors]
        return 200, {"Content-Type": "application/json"}, json.dumps(response)
