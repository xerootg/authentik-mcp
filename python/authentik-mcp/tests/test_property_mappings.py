import asyncio

import pytest

import authentik_mcp.server as server


MAPPING_ID = "9a35c211-39b9-4f76-b76d-2b0af24075f5"
SUMMARY_PATH = f"/propertymappings/all/{MAPPING_ID}/"
SCOPE_PATH = f"/propertymappings/provider/scope/{MAPPING_ID}/"
SCOPE_MODEL = "authentik_providers_oauth2.scopemapping"
FIELDS = {"name": "Offline access", "scope_name": "offline_access", "expression": "return {}"}
NEW_NAMES = {
    "authentik_list_property_mappings",
    "authentik_list_scope_mappings",
    "authentik_get_property_mapping",
    "authentik_create_property_mapping",
    "authentik_update_property_mapping",
    "authentik_delete_property_mapping",
}


class FakeClient:
    def __init__(self):
        self.calls = []
        self.summary = {"pk": MAPPING_ID, "meta_model_name": SCOPE_MODEL}

    async def request(self, method, path, params=None, json_data=None):
        self.calls.append((method, path, params, json_data))
        if method == "GET" and path == SUMMARY_PATH:
            return self.summary
        return {"pk": MAPPING_ID, "name": "Offline access"}


@pytest.fixture
def client(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(server, "authentik_client", fake, raising=False)
    return fake


@pytest.mark.parametrize("tool,path,extra", [
    ("authentik_list_property_mappings", "/propertymappings/all/", {}),
    ("authentik_list_scope_mappings", "/propertymappings/provider/scope/", {"scope_name": "offline_access"}),
])
def test_list_mappings(client, tool, path, extra):
    params = {"search": "offline", "ordering": "name", "page": 2, "page_size": 5, **extra}
    result = asyncio.run(server.call_tool(tool, {**params, "unused": None}))
    assert client.calls == [("GET", path, params, None)]
    assert MAPPING_ID in result[0].text


@pytest.mark.parametrize("operation,method", [("get", "GET"), ("update", "PATCH")])
@pytest.mark.parametrize("mapping_type", [None, "provider/scope", "source/ldap"])
def test_get_and_update_mapping(client, operation, method, mapping_type):
    arguments = {"mapping_id": MAPPING_ID}
    if mapping_type is not None:
        arguments["mapping_type"] = mapping_type
    if operation == "update":
        arguments["data"] = FIELDS
    result = asyncio.run(server.call_tool(f"authentik_{operation}_property_mapping", arguments))
    expected = [] if mapping_type else [("GET", SUMMARY_PATH, None, None)]
    path = f"/propertymappings/{mapping_type or 'provider/scope'}/{MAPPING_ID}/"
    expected.append((method, path, None, FIELDS if operation == "update" else None))
    assert client.calls == expected
    assert MAPPING_ID in result[0].text


@pytest.mark.parametrize("mapping_type", [None, "provider/scope", "source/ldap"])
def test_create_mapping(client, mapping_type):
    arguments = {"data": FIELDS}
    if mapping_type is not None:
        arguments["mapping_type"] = mapping_type
    asyncio.run(server.call_tool("authentik_create_property_mapping", arguments))
    assert client.calls == [
        ("POST", f"/propertymappings/{mapping_type or 'provider/scope'}/", None, FIELDS)
    ]


def test_delete_mapping(client):
    result = asyncio.run(server.call_tool("authentik_delete_property_mapping", {"mapping_id": MAPPING_ID}))
    assert client.calls == [("DELETE", SUMMARY_PATH, None, None)]
    assert MAPPING_ID in result[0].text


def test_property_mapping_path_from_model():
    assert server.property_mapping_path_from_model(SCOPE_MODEL) == "provider/scope"
    with pytest.raises(ValueError, match="Unknown property mapping model.*mapping_type"):
        server.property_mapping_path_from_model("unknown.mapping")


@pytest.mark.parametrize("operation", ["get", "update"])
def test_unknown_model_requires_explicit_type(client, operation):
    client.summary["meta_model_name"] = "unknown.mapping"
    result = asyncio.run(server.call_tool(
        f"authentik_{operation}_property_mapping", {"mapping_id": MAPPING_ID, "data": FIELDS}
    ))
    assert client.calls == [("GET", SUMMARY_PATH, None, None)]
    assert "mapping_type" in result[0].text


def test_tool_registration():
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 61 + 6 + 1
    names = [tool.name for tool in tools]
    assert len(names) == len(set(names))
    assert NEW_NAMES <= set(names)
    for tool in tools:
        if tool.name not in NEW_NAMES:
            continue
        schema = tool.inputSchema
        assert set(schema.get("required", [])) <= schema["properties"].keys()
        if "mapping_type" in schema["properties"]:
            assert schema["properties"]["mapping_type"]["enum"] == server.PROPERTY_MAPPING_TYPES
        if tool.name == "authentik_create_property_mapping":
            assert schema["properties"]["mapping_type"]["default"] == "provider/scope"
            assert schema["required"] == ["data"]


def test_path_inputs_are_validated():
    import asyncio, uuid
    import authentik_mcp.server as srv
    fake = type("F", (), {"calls": [], "request": None})()
    async def req(m, p, params=None, json_data=None):
        fake.calls.append((m, p)); return {"meta_model_name": "authentik_providers_oauth2.scopemapping"}
    fake.request = req
    srv.authentik_client = fake
    good = str(uuid.uuid4())
    for name, args in [
        ("authentik_get_property_mapping", {"mapping_id": good, "mapping_type": "../../core/users"}),
        ("authentik_update_property_mapping", {"mapping_id": good, "data": {}, "mapping_type": "x/y"}),
        ("authentik_create_property_mapping", {"mapping_type": "../x", "data": {}}),
        ("authentik_get_property_mapping", {"mapping_id": "../../core/users"}),
        ("authentik_delete_property_mapping", {"mapping_id": "not-a-uuid"}),
    ]:
        before = len(fake.calls)
        try:
            out = asyncio.run(srv.call_tool(name, args))
            text = out[0].text
        except ValueError as e:
            text = str(e)
        assert len(fake.calls) == before, f"{name} reached the API with {args}"
        assert "must be" in text or "Error" in text or "error" in text
