import asyncio

import pytest

import authentik_mcp.server as server


SECRET = "ak-very-secret-token-value"
NEW_NAMES = {"authentik_create_service_account"}


class FakeClient:
    def __init__(self):
        self.calls = []

    async def request(self, method, path, params=None, json_data=None):
        self.calls.append((method, path, params, json_data))
        if path == "/core/users/service_account/":
            return {
                "username": json_data["name"],
                "user_uid": "abc",
                "user_pk": 24,
                "group_pk": None,
                "token": SECRET,
            }
        if path == "/core/tokens/":
            # authentik's create response is metadata only; the key comes from view_key.
            return {"pk": "tok-uuid", "identifier": json_data["identifier"]}
        if path.endswith("/view_key/"):
            return {"key": SECRET}
        return {"pk": 24, **(json_data or {})}


@pytest.fixture
def client(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(server, "authentik_client", fake, raising=False)
    return fake


@pytest.mark.parametrize("user_type", server.USER_TYPES)
def test_create_user_passes_type_and_path(client, user_type):
    args = {
        "username": "svc",
        "email": "svc@example.com",
        "name": "svc",
        "type": user_type,
        "path": "goauthentik.io/service-accounts",
    }
    result = asyncio.run(server.call_tool("authentik_create_user", dict(args)))
    assert client.calls == [("POST", "/core/users/", None, args)]
    assert user_type in result[0].text


def test_update_user_passes_type_and_path(client):
    args = {"user_id": 24, "type": "service_account", "path": "goauthentik.io/service-accounts"}
    result = asyncio.run(server.call_tool("authentik_update_user", dict(args)))
    assert client.calls == [
        ("PATCH", "/core/users/24/", None, {"type": "service_account", "path": "goauthentik.io/service-accounts"})
    ]
    assert "service_account" in result[0].text


def test_create_service_account_hides_token_by_default(client):
    args = {"name": "x2d-claude", "create_group": True, "expiring": False}
    result = asyncio.run(server.call_tool("authentik_create_service_account", dict(args)))
    assert client.calls == [("POST", "/core/users/service_account/", None, args)]
    text = result[0].text
    assert SECRET not in text
    assert "x2d-claude" in text
    assert "24" in text
    assert "redacted" in text
    assert "service-account-x2d-claude-password" in text
    assert "pk 24" in text


def test_create_service_account_identifier_is_slugified(client):
    result = asyncio.run(server.call_tool("authentik_create_service_account", {"name": "CI.Bot"}))
    text = result[0].text
    assert "service-account-cibot-password" in text
    assert "service-account-CI.Bot-password" not in text
    assert "user CI.Bot" in text


@pytest.mark.parametrize("name,expected", [
    ("x2d-claude", "service-account-x2d-claude-password"),
    ("CI.Bot", "service-account-cibot-password"),
    ("My Svc_1", "service-account-my-svc_1-password"),
    ("café", "service-account-cafe-password"),
    ("Ünïcode Bot", "service-account-unicode-bot-password"),
    ("  foo  ", "service-account-foo-password"),
    ("---foo---", "service-account-foo-password"),
])
def test_service_account_token_identifier(name, expected):
    assert server.service_account_token_identifier(name) == expected


def test_create_service_account_reveal_token(client):
    result = asyncio.run(server.call_tool(
        "authentik_create_service_account", {"name": "x2d-claude", "reveal_token": True}
    ))
    # reveal_token is a tool-side switch and must not reach the API body.
    assert client.calls == [("POST", "/core/users/service_account/", None, {"name": "x2d-claude"})]
    assert SECRET in result[0].text
    assert "service-account-x2d-claude-password" not in result[0].text


@pytest.mark.parametrize("reveal", [False, True])
def test_create_token_reveal_guard(client, reveal):
    args = {"identifier": "svc-token", "user": 24}
    if reveal:
        args["reveal_token"] = True
    result = asyncio.run(server.call_tool("authentik_create_token", dict(args)))
    expected = [("POST", "/core/tokens/", None, {"identifier": "svc-token", "user": 24})]
    if reveal:
        expected.append(("GET", "/core/tokens/svc-token/view_key/", None, None))
    assert client.calls == expected
    assert (SECRET in result[0].text) is reveal
    assert "svc-token" in result[0].text


def test_create_token_reveal_quotes_identifier(client):
    result = asyncio.run(server.call_tool(
        "authentik_create_token", {"identifier": "a/b c", "user": 24, "reveal_token": True}
    ))
    assert client.calls[1] == ("GET", "/core/tokens/a%2Fb%20c/view_key/", None, None)
    assert SECRET in result[0].text


def test_redact_secrets_keeps_empty_and_other_fields():
    data = {"pk": 1, "key": "", "token": None, "identifier": "id"}
    assert server.redact_secrets(data, reveal=False) == data
    assert server.redact_secrets({"token": "s"}, reveal=True) == {"token": "s"}
    assert server.redact_secrets({"token": "s"}, reveal=False) == {"token": server.REDACTED}


def test_tool_schemas():
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert NEW_NAMES <= tools.keys()
    for name in ("authentik_create_user", "authentik_update_user"):
        props = tools[name].inputSchema["properties"]
        assert props["type"]["enum"] == server.USER_TYPES
        assert props["path"]["type"] == "string"
    sa = tools["authentik_create_service_account"].inputSchema
    assert sa["required"] == ["name"]
    assert set(sa["properties"]) == {"name", "create_group", "expiring", "expires", "reveal_token"}
    for name in ("authentik_create_service_account", "authentik_create_token"):
        reveal = tools[name].inputSchema["properties"]["reveal_token"]
        assert reveal["type"] == "boolean"
        assert reveal["default"] is False
        assert "transcript" in reveal["description"]
