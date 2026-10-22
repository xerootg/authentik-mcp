#!/usr/bin/env python3
"""
Authentik MCP Server - Full API Integration

This MCP server provides comprehensive access to Authentik's API including:
- User management (CRUD operations)
- Group management
- Application management
- Flow management
- Event monitoring
- System administration
- Provider management (typed create/update/delete for all provider types)
- Outpost management (instances, the providers they serve, and service connections)
- Policy management
- Property mapping management
- Source management
- Tenant management
- Token management
"""

import logging
from collections.abc import Sequence
from typing import Any
from urllib.parse import urljoin

import httpx
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import AnyUrl, BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("authentik-mcp")

# Provider types map 1:1 to authentik's type-specific API endpoints under /providers/<type>/.
# Providers must be created/updated through these typed endpoints; /providers/all/ is read-only.
PROVIDER_TYPES = [
    "oauth2",
    "proxy",
    "ldap",
    "saml",
    "radius",
    "scim",
    "rac",
    "ssf",
    "google_workspace",
    "microsoft_entra",
]


# Stage API paths under /stages/. Most map 1:1 from the Django app label
# (authentik_stages_<label>); a few live under a nested router.
STAGE_TYPES = [
    "authenticator/duo",
    "authenticator/email",
    "authenticator/endpoint_gdtc",
    "authenticator/sms",
    "authenticator/static",
    "authenticator/totp",
    "authenticator/validate",
    "authenticator/webauthn",
    "captcha",
    "consent",
    "deny",
    "dummy",
    "email",
    "identification",
    "invitation/stages",
    "mtls",
    "password",
    "prompt/stages",
    "redirect",
    "source",
    "user_delete",
    "user_login",
    "user_logout",
    "user_write",
]
_STAGE_PATH_OVERRIDES = {
    "invitation": "invitation/stages",
    "prompt": "prompt/stages",
}


def stage_path_from_model(meta_model_name: str) -> str:
    """Map a stage's meta_model_name (e.g. authentik_stages_password.passwordstage) to its API path."""
    label = meta_model_name.split(".", 1)[0].removeprefix("authentik_stages_")
    if label in _STAGE_PATH_OVERRIDES:
        return _STAGE_PATH_OVERRIDES[label]
    if label.startswith("authenticator_"):
        return "authenticator/" + label.removeprefix("authenticator_")
    return label


def policy_path_from_model(meta_model_name: str) -> str:
    """Map a policy's meta_model_name (e.g. authentik_policies_expression.expressionpolicy) to its API path."""
    label = meta_model_name.split(".", 1)[0]
    label = label.removeprefix("authentik_policies_").removeprefix("authentik_")
    return {"expiry": "password_expiry"}.get(label, label)

# Initialize MCP server
server: Server[None] = Server("authentik-mcp")


class AuthentikConfig(BaseModel):
    """Configuration for Authentik API client."""
    base_url: str = Field(..., description="Base URL of Authentik instance")
    token: str = Field(..., description="API token for authentication")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")


class AuthentikClient:
    """HTTP client for Authentik API."""

    def __init__(self, config: AuthentikConfig) -> None:
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {config.token}"},
            verify=config.verify_ssl,
            timeout=30.0,
        )

    async def request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an API request to Authentik."""
        url = urljoin(f"{self.base_url}/api/v3/", endpoint.lstrip("/"))

        try:
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
            )
            response.raise_for_status()
            if not response.content:
                return {}
            result = response.json()
            return result if isinstance(result, dict) else {"data": result}
        except httpx.HTTPStatusError as e:
            logger.exception(f"HTTP error {e.response.status_code}: {e.response.text}")
            raise
        except Exception as e:
            logger.exception(f"Request failed: {e!s}")
            raise

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()


# Global client instance
authentik_client: AuthentikClient | None = None


@server.list_resources()  # type: ignore[no-untyped-call,misc]
async def list_resources() -> list[Resource]:
    """List available Authentik resources."""
    return [
        Resource(
            uri=AnyUrl("authentik://users"),
            name="Users",
            mimeType="application/json",
            description="List and manage Authentik users",
        ),
        Resource(
            uri=AnyUrl("authentik://groups"),
            name="Groups",
            mimeType="application/json",
            description="List and manage Authentik groups",
        ),
        Resource(
            uri=AnyUrl("authentik://applications"),
            name="Applications",
            mimeType="application/json",
            description="List and manage Authentik applications",
        ),
        Resource(
            uri=AnyUrl("authentik://events"),
            name="Events",
            mimeType="application/json",
            description="View Authentik system events and audit logs",
        ),
        Resource(
            uri=AnyUrl("authentik://flows"),
            name="Flows",
            mimeType="application/json",
            description="List and manage Authentik authentication flows",
        ),
        Resource(
            uri=AnyUrl("authentik://providers"),
            name="Providers",
            mimeType="application/json",
            description="List and manage Authentik providers",
        ),
        Resource(
            uri=AnyUrl("authentik://stages"),
            name="Stages",
            mimeType="application/json",
            description="List Authentik flow stages of every type",
        ),
        Resource(
            uri=AnyUrl("authentik://outposts"),
            name="Outposts",
            mimeType="application/json",
            description="List and manage Authentik outposts and the providers they serve",
        ),
    ]


@server.read_resource()  # type: ignore[no-untyped-call,misc]
async def read_resource(uri: str) -> str:
    """Read a specific Authentik resource."""
    if not authentik_client:
        msg = "Authentik client not initialized"
        raise ValueError(msg)

    if uri == "authentik://users":
        data = await authentik_client.request("GET", "/core/users/")
        return f"Users:\n{data}"
    if uri == "authentik://groups":
        data = await authentik_client.request("GET", "/core/groups/")
        return f"Groups:\n{data}"
    if uri == "authentik://applications":
        data = await authentik_client.request("GET", "/core/applications/")
        return f"Applications:\n{data}"
    if uri == "authentik://events":
        data = await authentik_client.request("GET", "/events/events/")
        return f"Events:\n{data}"
    if uri == "authentik://flows":
        data = await authentik_client.request("GET", "/flows/instances/")
        return f"Flows:\n{data}"
    if uri == "authentik://providers":
        data = await authentik_client.request("GET", "/providers/all/")
        return f"Providers:\n{data}"
    if uri == "authentik://stages":
        data = await authentik_client.request("GET", "/stages/all/")
        return f"Stages:\n{data}"
    if uri == "authentik://outposts":
        data = await authentik_client.request("GET", "/outposts/instances/")
        return f"Outposts:\n{data}"
    msg = f"Unknown resource: {uri}"
    raise ValueError(msg)


@server.list_tools()  # type: ignore[no-untyped-call,misc]
async def list_tools() -> list[Tool]:
    """List available Authentik tools."""
    return [
        # User Management Tools
        Tool(
            name="authentik_list_users",
            description="List all users in Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering users"},
                    "is_active": {"type": "boolean", "description": "Filter by active status"},
                    "group": {"type": "string", "description": "Filter by group membership"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_user",
            description="Get details of a specific user",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "integer", "description": "User ID to retrieve"},
                },
                "required": ["user_id"],
            },
        ),
        Tool(
            name="authentik_create_user",
            description="Create a new user in Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username"},
                    "email": {"type": "string", "description": "Email address"},
                    "name": {"type": "string", "description": "Full name"},
                    "password": {"type": "string", "description": "Password"},
                    "is_active": {"type": "boolean", "description": "Whether user is active", "default": True},
                    "groups": {"type": "array", "items": {"type": "string"}, "description": "Group UUIDs to assign"},
                },
                "required": ["username", "email", "name"],
            },
        ),
        Tool(
            name="authentik_update_user",
            description="Update an existing user",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "integer", "description": "User ID to update"},
                    "username": {"type": "string", "description": "Username"},
                    "email": {"type": "string", "description": "Email address"},
                    "name": {"type": "string", "description": "Full name"},
                    "is_active": {"type": "boolean", "description": "Whether user is active"},
                    "groups": {"type": "array", "items": {"type": "string"}, "description": "Group UUIDs to assign"},
                },
                "required": ["user_id"],
            },
        ),
        Tool(
            name="authentik_delete_user",
            description="Delete a user from Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "integer", "description": "User ID to delete"},
                },
                "required": ["user_id"],
            },
        ),

        # Group Management Tools
        Tool(
            name="authentik_list_groups",
            description="List all groups in Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering groups"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_group",
            description="Get details of a specific group",
            inputSchema={
                "type": "object",
                "properties": {
                    "group_id": {"type": "string", "description": "Group ID to retrieve"},
                },
                "required": ["group_id"],
            },
        ),
        Tool(
            name="authentik_create_group",
            description="Create a new group in Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Group name"},
                    "is_superuser": {
                        "type": "boolean",
                        "description": "Whether group has superuser privileges",
                        "default": False,
                    },
                    "parent": {"type": "string", "description": "Parent group ID"},
                    "users": {"type": "array", "items": {"type": "integer"}, "description": "User IDs to add to group"},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="authentik_update_group",
            description="Update an existing group",
            inputSchema={
                "type": "object",
                "properties": {
                    "group_id": {"type": "string", "description": "Group ID to update"},
                    "name": {"type": "string", "description": "Group name"},
                    "is_superuser": {"type": "boolean", "description": "Whether group has superuser privileges"},
                    "parent": {"type": "string", "description": "Parent group ID"},
                    "users": {"type": "array", "items": {"type": "integer"}, "description": "User IDs to add to group"},
                },
                "required": ["group_id"],
            },
        ),
        Tool(
            name="authentik_delete_group",
            description="Delete a group from Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "group_id": {"type": "string", "description": "Group ID to delete"},
                },
                "required": ["group_id"],
            },
        ),

        # Application Management Tools
        Tool(
            name="authentik_list_applications",
            description="List all applications in Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering applications"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_application",
            description="Get details of a specific application",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_slug": {"type": "string", "description": "Application slug to retrieve"},
                },
                "required": ["app_slug"],
            },
        ),
        Tool(
            name="authentik_create_application",
            description="Create a new application in Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Application name"},
                    "slug": {"type": "string", "description": "Application slug"},
                    "provider": {"type": "integer", "description": "Provider ID"},
                    "meta_description": {"type": "string", "description": "Application description"},
                    "meta_publisher": {"type": "string", "description": "Application publisher"},
                    "policy_engine_mode": {
                        "type": "string",
                        "enum": ["all", "any"],
                        "description": "Policy engine mode",
                        "default": "any",
                    },
                },
                "required": ["name", "slug"],
            },
        ),
        Tool(
            name="authentik_check_application_access",
            description="Check whether a user passes an application's access policies (admin check_access)",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_slug": {"type": "string", "description": "Application slug"},
                    "for_user": {"type": "integer", "description": "User ID (pk) to evaluate"},
                },
                "required": ["app_slug", "for_user"],
            },
        ),
        Tool(
            name="authentik_update_application",
            description="Update an existing application",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_slug": {"type": "string", "description": "Application slug to update"},
                    "name": {"type": "string", "description": "Application name"},
                    "provider": {"type": "integer", "description": "Provider ID"},
                    "meta_description": {"type": "string", "description": "Application description"},
                    "meta_publisher": {"type": "string", "description": "Application publisher"},
                    "policy_engine_mode": {
                        "type": "string",
                        "enum": ["all", "any"],
                        "description": "Policy engine mode",
                    },
                },
                "required": ["app_slug"],
            },
        ),
        Tool(
            name="authentik_delete_application",
            description="Delete an application from Authentik",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_slug": {"type": "string", "description": "Application slug to delete"},
                },
                "required": ["app_slug"],
            },
        ),

        # Event Monitoring Tools
        Tool(
            name="authentik_list_events",
            description="List system events and audit logs",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "Filter by event action"},
                    "client_ip": {"type": "string", "description": "Filter by client IP"},
                    "username": {"type": "string", "description": "Filter by username"},
                    "ordering": {"type": "string", "description": "Field to order by", "default": "-created"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_event",
            description="Get details of a specific event",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {"type": "string", "description": "Event ID to retrieve"},
                },
                "required": ["event_id"],
            },
        ),

        # Flow Management Tools
        Tool(
            name="authentik_list_flows",
            description="List all authentication flows",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering flows"},
                    "designation": {"type": "string", "description": "Filter by flow designation"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_flow",
            description="Get details of a specific flow",
            inputSchema={
                "type": "object",
                "properties": {
                    "flow_slug": {"type": "string", "description": "Flow slug to retrieve"},
                },
                "required": ["flow_slug"],
            },
        ),

        Tool(
            name="authentik_create_flow",
            description=(
                "Create a flow. Required in 'data': name, slug, title, designation (authentication, "
                "authorization, enrollment, invalidation, recovery, stage_configuration, unenrollment). "
                "Optional: authentication (none, require_authenticated, require_unauthenticated, "
                "require_superuser, require_redirect, require_outpost), denied_action, layout. "
                "Add stages with authentik_create_flow_binding."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "object", "description": "Flow fields", "additionalProperties": True},
                },
                "required": ["data"],
            },
        ),
        Tool(
            name="authentik_delete_flow",
            description="Delete a flow by slug (its stage bindings go with it; the stages are kept)",
            inputSchema={
                "type": "object",
                "properties": {
                    "flow_slug": {"type": "string", "description": "Flow slug to delete"},
                },
                "required": ["flow_slug"],
            },
        ),
        Tool(
            name="authentik_update_flow",
            description=(
                "Update a flow by slug (PATCH: only included fields change), e.g. title, "
                "designation, authentication, denied_action, compatibility_mode, policy_engine_mode"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "flow_slug": {"type": "string", "description": "Flow slug to update"},
                    "data": {"type": "object", "description": "Fields to update", "additionalProperties": True},
                },
                "required": ["flow_slug", "data"],
            },
        ),
        Tool(
            name="authentik_list_flow_bindings",
            description=(
                "List stage bindings (which stages run in a flow, and in what order). Filter by "
                "'target' (the flow's pk UUID, not its slug) to see one flow's stages sorted by order."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Flow pk (UUID) to filter by"},
                    "stage": {"type": "string", "description": "Stage UUID to filter by"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_create_flow_binding",
            description=(
                "Bind a stage into a flow. Required: target (flow pk), stage (stage UUID), order. "
                "Optional: evaluate_on_plan, re_evaluate_policies, policy_engine_mode, invalid_response_action."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "object", "description": "Binding fields", "additionalProperties": True},
                },
                "required": ["data"],
            },
        ),
        Tool(
            name="authentik_update_flow_binding",
            description="Update a flow stage binding (PATCH), e.g. change its order or policy evaluation",
            inputSchema={
                "type": "object",
                "properties": {
                    "binding_id": {"type": "string", "description": "Binding UUID (fsb_uuid / pk)"},
                    "data": {"type": "object", "description": "Fields to update", "additionalProperties": True},
                },
                "required": ["binding_id", "data"],
            },
        ),
        Tool(
            name="authentik_delete_flow_binding",
            description="Remove a stage from a flow by deleting its binding (the stage itself is kept)",
            inputSchema={
                "type": "object",
                "properties": {
                    "binding_id": {"type": "string", "description": "Binding UUID"},
                },
                "required": ["binding_id"],
            },
        ),

        # Stage Management Tools
        Tool(
            name="authentik_list_stages",
            description=(
                "List stages of every type. Each result has pk, name, component and meta_model_name; "
                "use authentik_get_stage to read the full type-specific config."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering stages"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_stage",
            description=(
                "Get a stage's full type-specific config. stage_type is optional: when omitted it is "
                "looked up from the stage's meta_model_name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "stage_id": {"type": "string", "description": "Stage UUID"},
                    "stage_type": {"type": "string", "enum": STAGE_TYPES, "description": "Stage type (API path)"},
                },
                "required": ["stage_id"],
            },
        ),
        Tool(
            name="authentik_create_stage",
            description=(
                "Create a stage of the given type. Pass all fields via 'data' (at least 'name'). "
                "Read an existing stage of the same type with authentik_get_stage to learn field shapes. "
                "A new stage does nothing until bound into a flow with authentik_create_flow_binding."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "stage_type": {"type": "string", "enum": STAGE_TYPES, "description": "Stage type (API path)"},
                    "data": {"type": "object", "description": "Stage fields", "additionalProperties": True},
                },
                "required": ["stage_type", "data"],
            },
        ),
        Tool(
            name="authentik_update_stage",
            description=(
                "Update a stage (PATCH: only included fields change). stage_type is optional and is "
                "looked up when omitted. Identification stages validate user_fields even on PATCH, so "
                "include user_fields when changing one."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "stage_id": {"type": "string", "description": "Stage UUID"},
                    "stage_type": {"type": "string", "enum": STAGE_TYPES, "description": "Stage type (API path)"},
                    "data": {"type": "object", "description": "Fields to update", "additionalProperties": True},
                },
                "required": ["stage_id", "data"],
            },
        ),
        Tool(
            name="authentik_delete_stage",
            description="Delete a stage (also removes it from every flow it is bound to)",
            inputSchema={
                "type": "object",
                "properties": {
                    "stage_id": {"type": "string", "description": "Stage UUID"},
                },
                "required": ["stage_id"],
            },
        ),
        Tool(
            name="authentik_list_prompts",
            description="List prompt fields (used by prompt stages, e.g. in enrollment flows)",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),

        Tool(
            name="authentik_list_invitations",
            description="List enrollment invitations (the itoken links used by invitation stages)",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_create_invitation",
            description=(
                "Create an invitation. 'data' fields: name (slug-like, required), flow (enrollment flow pk; "
                "the link only works in that flow), single_use, expires (ISO datetime or null), fixed_data "
                "(values pre-filled into prompts). Share it as "
                "<authentik>/if/flow/<flow slug>/?itoken=<invitation pk>."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "object", "description": "Invitation fields", "additionalProperties": True},
                },
                "required": ["data"],
            },
        ),
        Tool(
            name="authentik_delete_invitation",
            description="Delete (revoke) an invitation",
            inputSchema={
                "type": "object",
                "properties": {
                    "invitation_id": {"type": "string", "description": "Invitation UUID"},
                },
                "required": ["invitation_id"],
            },
        ),

        # Policy Management Tools
        Tool(
            name="authentik_list_policies",
            description="List policies of every type (pk, name, component, meta_model_name, bound_to)",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering policies"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_policy",
            description="Get a policy's full type-specific config (type looked up automatically)",
            inputSchema={
                "type": "object",
                "properties": {
                    "policy_id": {"type": "string", "description": "Policy UUID"},
                },
                "required": ["policy_id"],
            },
        ),
        Tool(
            name="authentik_create_policy",
            description=(
                "Create a policy. policy_type is the API path under /policies/, e.g. expression, "
                "password, password_expiry, reputation, event_matcher, dummy, geoip, unique_password"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "policy_type": {"type": "string", "description": "Policy type (API path)"},
                    "data": {"type": "object", "description": "Policy fields", "additionalProperties": True},
                },
                "required": ["policy_type", "data"],
            },
        ),
        Tool(
            name="authentik_update_policy",
            description="Update a policy (PATCH; type looked up automatically)",
            inputSchema={
                "type": "object",
                "properties": {
                    "policy_id": {"type": "string", "description": "Policy UUID"},
                    "data": {"type": "object", "description": "Fields to update", "additionalProperties": True},
                },
                "required": ["policy_id", "data"],
            },
        ),
        Tool(
            name="authentik_list_policy_bindings",
            description=(
                "List policy bindings. Filter by 'target' = the policybindingmodel_ptr_id of the object "
                "the policy is bound to (flows and flow stage bindings both carry this field; it differs "
                "from their pk), or an application's pk."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target binding-model UUID"},
                    "policy": {"type": "string", "description": "Policy UUID"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_create_policy_binding",
            description=(
                "Bind a policy, group or user to a target (a policybindingmodel_ptr_id). Required: target, "
                "order, and one of policy / group / user. Optional: negate, enabled, timeout, failure_result."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "object", "description": "Binding fields", "additionalProperties": True},
                },
                "required": ["data"],
            },
        ),
        Tool(
            name="authentik_update_policy_binding",
            description="Update a policy binding (PATCH)",
            inputSchema={
                "type": "object",
                "properties": {
                    "binding_id": {"type": "string", "description": "Policy binding UUID"},
                    "data": {"type": "object", "description": "Fields to update", "additionalProperties": True},
                },
                "required": ["binding_id", "data"],
            },
        ),
        Tool(
            name="authentik_delete_policy_binding",
            description="Delete a policy binding",
            inputSchema={
                "type": "object",
                "properties": {
                    "binding_id": {"type": "string", "description": "Policy binding UUID"},
                },
                "required": ["binding_id"],
            },
        ),

        # Brand Management Tools
        Tool(
            name="authentik_list_brands",
            description=(
                "List brands. A brand selects the default flows for its domain: flow_authentication, "
                "flow_recovery, flow_enrollment (via identification stage), flow_user_settings, etc."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_update_brand",
            description="Update a brand (PATCH), e.g. set flow_recovery to a flow pk",
            inputSchema={
                "type": "object",
                "properties": {
                    "brand_id": {"type": "string", "description": "Brand UUID (brand_uuid)"},
                    "data": {"type": "object", "description": "Fields to update", "additionalProperties": True},
                },
                "required": ["brand_id", "data"],
            },
        ),
        Tool(
            name="authentik_get_system_info",
            description="Get authentik version and runtime info (admin/system)",
            inputSchema={"type": "object", "properties": {}},
        ),

        # Provider Management Tools
        Tool(
            name="authentik_list_providers",
            description="List all providers",
            inputSchema={
                "type": "object",
                "properties": {
                    "application__isnull": {"type": "boolean", "description": "Filter providers without applications"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_provider",
            description=(
                "Get details of a specific provider. Omit provider_type to read the polymorphic "
                "summary from /providers/all/; pass provider_type to read the full type-specific "
                "object (recommended before updating, so you can see every editable field)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "provider_id": {"type": "integer", "description": "Provider ID to retrieve"},
                    "provider_type": {
                        "type": "string",
                        "enum": PROVIDER_TYPES,
                        "description": "Provider type; when set, reads the typed endpoint for full fields",
                    },
                },
                "required": ["provider_id"],
            },
        ),
        Tool(
            name="authentik_create_provider",
            description=(
                "Create a provider of a given type. Authentik creates providers at type-specific "
                "endpoints, so pass the kind via 'provider_type' and all provider fields via 'data'. "
                "Most types require at least: name, authorization_flow, invalidation_flow. Common "
                "type-specific required fields - oauth2: client_type; proxy: external_host + mode "
                "(proxy|forward_single|forward_domain); ldap: base_dn; saml: acs_url; radius: "
                "shared_secret + client_networks; scim: url + token. Use authentik_get_provider "
                "(with provider_type) on an existing provider to learn the exact field shape."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "provider_type": {
                        "type": "string",
                        "enum": PROVIDER_TYPES,
                        "description": "Provider type (selects the API endpoint)",
                    },
                    "data": {
                        "type": "object",
                        "description": (
                            "Provider fields (name, authorization_flow, invalidation_flow, "
                            "and type-specific fields)"
                        ),
                        "additionalProperties": True,
                    },
                },
                "required": ["provider_type", "data"],
            },
        ),
        Tool(
            name="authentik_update_provider",
            description=(
                "Update an existing provider. Provide its 'provider_type', numeric 'provider_id', and "
                "a 'data' object with the fields to change (PATCH semantics: only included fields change)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "provider_type": {
                        "type": "string",
                        "enum": PROVIDER_TYPES,
                        "description": "Provider type (selects the API endpoint)",
                    },
                    "provider_id": {"type": "integer", "description": "Numeric provider ID (pk)"},
                    "data": {
                        "type": "object",
                        "description": "Fields to update",
                        "additionalProperties": True,
                    },
                },
                "required": ["provider_type", "provider_id", "data"],
            },
        ),
        Tool(
            name="authentik_delete_provider",
            description="Delete a provider by type and numeric ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "provider_type": {
                        "type": "string",
                        "enum": PROVIDER_TYPES,
                        "description": "Provider type (selects the API endpoint)",
                    },
                    "provider_id": {"type": "integer", "description": "Numeric provider ID (pk)"},
                },
                "required": ["provider_type", "provider_id"],
            },
        ),

        # Outpost Management Tools
        Tool(
            name="authentik_list_outposts",
            description="List outposts (proxy/ldap/radius/rac deployments that serve providers)",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering outposts"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_get_outpost",
            description="Get details of a specific outpost",
            inputSchema={
                "type": "object",
                "properties": {
                    "outpost_id": {"type": "string", "description": "Outpost UUID to retrieve"},
                },
                "required": ["outpost_id"],
            },
        ),
        Tool(
            name="authentik_create_outpost",
            description=(
                "Create an outpost. The 'providers' array holds the IDs of the providers this outpost "
                "serves, and 'type' must match those providers (a proxy outpost serves proxy providers, "
                "an ldap outpost serves ldap providers, etc.). Omit service_connection for a manually "
                "deployed outpost, or set it to a Docker/Kubernetes service-connection UUID to have "
                "authentik manage the deployment."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Outpost name"},
                    "type": {
                        "type": "string",
                        "enum": ["proxy", "ldap", "radius", "rac"],
                        "description": "Outpost type",
                        "default": "proxy",
                    },
                    "providers": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Provider IDs served by this outpost",
                    },
                    "service_connection": {
                        "type": "string",
                        "description": "Docker/Kubernetes service-connection UUID (omit for manual deployment)",
                    },
                    "config": {
                        "type": "object",
                        "description": "Outpost configuration overrides",
                        "additionalProperties": True,
                    },
                },
                "required": ["name", "providers"],
            },
        ),
        Tool(
            name="authentik_update_outpost",
            description=(
                "Update an existing outpost. Set 'providers' to change which providers it serves "
                "(this replaces the full list, so include every provider the outpost should keep)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "outpost_id": {"type": "string", "description": "Outpost UUID to update"},
                    "name": {"type": "string", "description": "Outpost name"},
                    "type": {
                        "type": "string",
                        "enum": ["proxy", "ldap", "radius", "rac"],
                        "description": "Outpost type",
                    },
                    "providers": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Provider IDs served by this outpost (replaces the existing list)",
                    },
                    "service_connection": {
                        "type": "string",
                        "description": "Docker/Kubernetes service-connection UUID",
                    },
                    "config": {
                        "type": "object",
                        "description": "Outpost configuration overrides",
                        "additionalProperties": True,
                    },
                },
                "required": ["outpost_id"],
            },
        ),
        Tool(
            name="authentik_delete_outpost",
            description="Delete an outpost",
            inputSchema={
                "type": "object",
                "properties": {
                    "outpost_id": {"type": "string", "description": "Outpost UUID to delete"},
                },
                "required": ["outpost_id"],
            },
        ),
        Tool(
            name="authentik_get_outpost_health",
            description="Get health/status of an outpost's connected instances",
            inputSchema={
                "type": "object",
                "properties": {
                    "outpost_id": {"type": "string", "description": "Outpost UUID"},
                },
                "required": ["outpost_id"],
            },
        ),
        Tool(
            name="authentik_list_outpost_service_connections",
            description=(
                "List outpost service connections (Docker/Kubernetes) that outposts can be deployed on. "
                "Use the returned UUIDs as 'service_connection' when creating or updating an outpost."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search term for filtering service connections"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),

        # Token Management Tools
        Tool(
            name="authentik_list_tokens",
            description="List API tokens",
            inputSchema={
                "type": "object",
                "properties": {
                    "user": {"type": "integer", "description": "Filter by user ID"},
                    "identifier": {"type": "string", "description": "Filter by token identifier"},
                    "ordering": {"type": "string", "description": "Field to order by"},
                    "page": {"type": "integer", "description": "Page number", "default": 1},
                    "page_size": {"type": "integer", "description": "Number of items per page", "default": 20},
                },
            },
        ),
        Tool(
            name="authentik_create_token",
            description="Create a new API token",
            inputSchema={
                "type": "object",
                "properties": {
                    "identifier": {"type": "string", "description": "Token identifier"},
                    "user": {"type": "integer", "description": "User ID for the token"},
                    "description": {"type": "string", "description": "Token description"},
                    "expires": {"type": "string", "format": "date-time", "description": "Token expiration date"},
                    "expiring": {"type": "boolean", "description": "Whether token expires", "default": True},
                },
                "required": ["identifier", "user"],
            },
        ),
    ]


@server.call_tool()  # type: ignore[misc]
async def call_tool(name: str, arguments: dict[str, Any]) -> Sequence[TextContent]:
    """Handle tool calls for Authentik operations."""
    if not authentik_client:
        return [TextContent(type="text", text="Error: Authentik client not initialized")]

    try:
        # User Management Tools
        if name == "authentik_list_users":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/core/users/", params=params)
            return [TextContent(type="text", text=f"Users: {data}")]

        if name == "authentik_get_user":
            user_id = arguments["user_id"]
            data = await authentik_client.request("GET", f"/core/users/{user_id}/")
            return [TextContent(type="text", text=f"User details: {data}")]

        if name == "authentik_create_user":
            data = await authentik_client.request("POST", "/core/users/", json_data=arguments)
            return [TextContent(type="text", text=f"Created user: {data}")]

        if name == "authentik_update_user":
            user_id = arguments.pop("user_id")
            data = await authentik_client.request("PATCH", f"/core/users/{user_id}/", json_data=arguments)
            return [TextContent(type="text", text=f"Updated user: {data}")]

        if name == "authentik_delete_user":
            user_id = arguments["user_id"]
            await authentik_client.request("DELETE", f"/core/users/{user_id}/")
            return [TextContent(type="text", text=f"Deleted user {user_id}")]

        # Group Management Tools
        if name == "authentik_list_groups":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/core/groups/", params=params)
            return [TextContent(type="text", text=f"Groups: {data}")]

        if name == "authentik_get_group":
            group_id = arguments["group_id"]
            data = await authentik_client.request("GET", f"/core/groups/{group_id}/")
            return [TextContent(type="text", text=f"Group details: {data}")]

        if name == "authentik_create_group":
            data = await authentik_client.request("POST", "/core/groups/", json_data=arguments)
            return [TextContent(type="text", text=f"Created group: {data}")]

        if name == "authentik_update_group":
            group_id = arguments.pop("group_id")
            data = await authentik_client.request("PATCH", f"/core/groups/{group_id}/", json_data=arguments)
            return [TextContent(type="text", text=f"Updated group: {data}")]

        if name == "authentik_delete_group":
            group_id = arguments["group_id"]
            await authentik_client.request("DELETE", f"/core/groups/{group_id}/")
            return [TextContent(type="text", text=f"Deleted group {group_id}")]

        # Application Management Tools
        if name == "authentik_list_applications":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/core/applications/", params=params)
            return [TextContent(type="text", text=f"Applications: {data}")]

        if name == "authentik_get_application":
            app_slug = arguments["app_slug"]
            data = await authentik_client.request("GET", f"/core/applications/{app_slug}/")
            return [TextContent(type="text", text=f"Application details: {data}")]

        if name == "authentik_create_application":
            data = await authentik_client.request("POST", "/core/applications/", json_data=arguments)
            return [TextContent(type="text", text=f"Created application: {data}")]

        if name == "authentik_check_application_access":
            app_slug = arguments["app_slug"]
            data = await authentik_client.request(
                "GET", f"/core/applications/{app_slug}/check_access/", params={"for_user": arguments["for_user"]},
            )
            return [TextContent(type="text", text=f"Access check for {app_slug}: {data}")]

        if name == "authentik_update_application":
            app_slug = arguments.pop("app_slug")
            data = await authentik_client.request("PATCH", f"/core/applications/{app_slug}/", json_data=arguments)
            return [TextContent(type="text", text=f"Updated application: {data}")]

        if name == "authentik_delete_application":
            app_slug = arguments["app_slug"]
            await authentik_client.request("DELETE", f"/core/applications/{app_slug}/")
            return [TextContent(type="text", text=f"Deleted application {app_slug}")]

        # Event Monitoring Tools
        if name == "authentik_list_events":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/events/events/", params=params)
            return [TextContent(type="text", text=f"Events: {data}")]

        if name == "authentik_get_event":
            event_id = arguments["event_id"]
            data = await authentik_client.request("GET", f"/events/events/{event_id}/")
            return [TextContent(type="text", text=f"Event details: {data}")]

        # Flow Management Tools
        if name == "authentik_list_flows":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/flows/instances/", params=params)
            return [TextContent(type="text", text=f"Flows: {data}")]

        if name == "authentik_get_flow":
            flow_slug = arguments["flow_slug"]
            data = await authentik_client.request("GET", f"/flows/instances/{flow_slug}/")
            return [TextContent(type="text", text=f"Flow details: {data}")]

        if name == "authentik_create_flow":
            data = await authentik_client.request("POST", "/flows/instances/", json_data=arguments["data"])
            return [TextContent(type="text", text=f"Created flow: {data}")]

        if name == "authentik_delete_flow":
            flow_slug = arguments["flow_slug"]
            await authentik_client.request("DELETE", f"/flows/instances/{flow_slug}/")
            return [TextContent(type="text", text=f"Deleted flow {flow_slug}")]

        if name == "authentik_update_flow":
            flow_slug = arguments["flow_slug"]
            data = await authentik_client.request(
                "PATCH", f"/flows/instances/{flow_slug}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Updated flow: {data}")]

        if name == "authentik_list_flow_bindings":
            params = {k: v for k, v in arguments.items() if v is not None}
            params.setdefault("ordering", "order")
            data = await authentik_client.request("GET", "/flows/bindings/", params=params)
            return [TextContent(type="text", text=f"Flow bindings: {data}")]

        if name == "authentik_create_flow_binding":
            data = await authentik_client.request("POST", "/flows/bindings/", json_data=arguments["data"])
            return [TextContent(type="text", text=f"Created flow binding: {data}")]

        if name == "authentik_update_flow_binding":
            binding_id = arguments["binding_id"]
            data = await authentik_client.request(
                "PATCH", f"/flows/bindings/{binding_id}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Updated flow binding: {data}")]

        if name == "authentik_delete_flow_binding":
            binding_id = arguments["binding_id"]
            await authentik_client.request("DELETE", f"/flows/bindings/{binding_id}/")
            return [TextContent(type="text", text=f"Deleted flow binding {binding_id}")]

        # Stage Management Tools
        if name == "authentik_list_stages":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/stages/all/", params=params)
            return [TextContent(type="text", text=f"Stages: {data}")]

        if name in ("authentik_get_stage", "authentik_update_stage", "authentik_delete_stage"):
            stage_id = arguments["stage_id"]
            stage_type = arguments.get("stage_type")
            if not stage_type:
                summary = await authentik_client.request("GET", f"/stages/all/{stage_id}/")
                stage_type = stage_path_from_model(summary["meta_model_name"])
            endpoint = f"/stages/{stage_type}/{stage_id}/"
            if name == "authentik_get_stage":
                data = await authentik_client.request("GET", endpoint)
                return [TextContent(type="text", text=f"Stage details ({stage_type}): {data}")]
            if name == "authentik_update_stage":
                data = await authentik_client.request("PATCH", endpoint, json_data=arguments["data"])
                return [TextContent(type="text", text=f"Updated stage ({stage_type}): {data}")]
            await authentik_client.request("DELETE", f"/stages/all/{stage_id}/")
            return [TextContent(type="text", text=f"Deleted stage {stage_id}")]

        if name == "authentik_create_stage":
            stage_type = arguments["stage_type"]
            data = await authentik_client.request("POST", f"/stages/{stage_type}/", json_data=arguments["data"])
            return [TextContent(type="text", text=f"Created stage ({stage_type}): {data}")]

        if name == "authentik_list_prompts":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/stages/prompt/prompts/", params=params)
            return [TextContent(type="text", text=f"Prompts: {data}")]

        if name == "authentik_list_invitations":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/stages/invitation/invitations/", params=params)
            return [TextContent(type="text", text=f"Invitations: {data}")]

        if name == "authentik_create_invitation":
            data = await authentik_client.request(
                "POST", "/stages/invitation/invitations/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Created invitation: {data}")]

        if name == "authentik_delete_invitation":
            invitation_id = arguments["invitation_id"]
            await authentik_client.request("DELETE", f"/stages/invitation/invitations/{invitation_id}/")
            return [TextContent(type="text", text=f"Deleted invitation {invitation_id}")]

        # Policy Management Tools
        if name == "authentik_list_policies":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/policies/all/", params=params)
            return [TextContent(type="text", text=f"Policies: {data}")]

        if name in ("authentik_get_policy", "authentik_update_policy"):
            policy_id = arguments["policy_id"]
            summary = await authentik_client.request("GET", f"/policies/all/{policy_id}/")
            policy_type = policy_path_from_model(summary["meta_model_name"])
            endpoint = f"/policies/{policy_type}/{policy_id}/"
            if name == "authentik_get_policy":
                data = await authentik_client.request("GET", endpoint)
                return [TextContent(type="text", text=f"Policy details ({policy_type}): {data}")]
            data = await authentik_client.request("PATCH", endpoint, json_data=arguments["data"])
            return [TextContent(type="text", text=f"Updated policy ({policy_type}): {data}")]

        if name == "authentik_create_policy":
            policy_type = arguments["policy_type"]
            data = await authentik_client.request(
                "POST", f"/policies/{policy_type}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Created policy ({policy_type}): {data}")]

        if name == "authentik_list_policy_bindings":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/policies/bindings/", params=params)
            return [TextContent(type="text", text=f"Policy bindings: {data}")]

        if name == "authentik_create_policy_binding":
            data = await authentik_client.request("POST", "/policies/bindings/", json_data=arguments["data"])
            return [TextContent(type="text", text=f"Created policy binding: {data}")]

        if name == "authentik_update_policy_binding":
            binding_id = arguments["binding_id"]
            data = await authentik_client.request(
                "PATCH", f"/policies/bindings/{binding_id}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Updated policy binding: {data}")]

        if name == "authentik_delete_policy_binding":
            binding_id = arguments["binding_id"]
            await authentik_client.request("DELETE", f"/policies/bindings/{binding_id}/")
            return [TextContent(type="text", text=f"Deleted policy binding {binding_id}")]

        # Brand Management Tools
        if name == "authentik_list_brands":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/core/brands/", params=params)
            return [TextContent(type="text", text=f"Brands: {data}")]

        if name == "authentik_update_brand":
            brand_id = arguments["brand_id"]
            data = await authentik_client.request(
                "PATCH", f"/core/brands/{brand_id}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Updated brand: {data}")]

        if name == "authentik_get_system_info":
            data = await authentik_client.request("GET", "/admin/version/")
            return [TextContent(type="text", text=f"Version: {data}")]

        # Provider Management Tools
        if name == "authentik_list_providers":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/providers/all/", params=params)
            return [TextContent(type="text", text=f"Providers: {data}")]

        if name == "authentik_get_provider":
            provider_id = arguments["provider_id"]
            provider_type = arguments.get("provider_type")
            endpoint = (
                f"/providers/{provider_type}/{provider_id}/"
                if provider_type
                else f"/providers/all/{provider_id}/"
            )
            data = await authentik_client.request("GET", endpoint)
            return [TextContent(type="text", text=f"Provider details: {data}")]

        if name == "authentik_create_provider":
            provider_type = arguments["provider_type"]
            data = await authentik_client.request(
                "POST", f"/providers/{provider_type}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Created provider: {data}")]

        if name == "authentik_update_provider":
            provider_type = arguments["provider_type"]
            provider_id = arguments["provider_id"]
            data = await authentik_client.request(
                "PATCH", f"/providers/{provider_type}/{provider_id}/", json_data=arguments["data"],
            )
            return [TextContent(type="text", text=f"Updated provider: {data}")]

        if name == "authentik_delete_provider":
            provider_type = arguments["provider_type"]
            provider_id = arguments["provider_id"]
            await authentik_client.request("DELETE", f"/providers/{provider_type}/{provider_id}/")
            return [TextContent(type="text", text=f"Deleted provider {provider_id}")]

        # Outpost Management Tools
        if name == "authentik_list_outposts":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/outposts/instances/", params=params)
            return [TextContent(type="text", text=f"Outposts: {data}")]

        if name == "authentik_get_outpost":
            outpost_id = arguments["outpost_id"]
            data = await authentik_client.request("GET", f"/outposts/instances/{outpost_id}/")
            return [TextContent(type="text", text=f"Outpost details: {data}")]

        if name == "authentik_create_outpost":
            data = await authentik_client.request("POST", "/outposts/instances/", json_data=arguments)
            return [TextContent(type="text", text=f"Created outpost: {data}")]

        if name == "authentik_update_outpost":
            outpost_id = arguments.pop("outpost_id")
            data = await authentik_client.request(
                "PATCH", f"/outposts/instances/{outpost_id}/", json_data=arguments,
            )
            return [TextContent(type="text", text=f"Updated outpost: {data}")]

        if name == "authentik_delete_outpost":
            outpost_id = arguments["outpost_id"]
            await authentik_client.request("DELETE", f"/outposts/instances/{outpost_id}/")
            return [TextContent(type="text", text=f"Deleted outpost {outpost_id}")]

        if name == "authentik_get_outpost_health":
            outpost_id = arguments["outpost_id"]
            data = await authentik_client.request("GET", f"/outposts/instances/{outpost_id}/health/")
            return [TextContent(type="text", text=f"Outpost health: {data}")]

        if name == "authentik_list_outpost_service_connections":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request(
                "GET", "/outposts/service_connections/all/", params=params,
            )
            return [TextContent(type="text", text=f"Service connections: {data}")]

        # Token Management Tools
        if name == "authentik_list_tokens":
            params = {k: v for k, v in arguments.items() if v is not None}
            data = await authentik_client.request("GET", "/core/tokens/", params=params)
            return [TextContent(type="text", text=f"Tokens: {data}")]

        if name == "authentik_create_token":
            data = await authentik_client.request("POST", "/core/tokens/", json_data=arguments)
            return [TextContent(type="text", text=f"Created token: {data}")]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except httpx.HTTPStatusError as e:
        logger.exception(f"Tool call failed: {e!s}")
        return [TextContent(
            type="text",
            text=f"Error: HTTP {e.response.status_code} {e.request.method} {e.request.url}: {e.response.text}",
        )]
    except Exception as e:
        logger.exception(f"Tool call failed: {e!s}")
        return [TextContent(type="text", text=f"Error: {e!s}")]


async def serve(base_url: str, token: str, *, verify_ssl: bool = True) -> None:
    """Run the MCP server against the given Authentik instance.

    Credentials are resolved by the CLI (see authentik_mcp.cli); this entry
    point just takes the resolved values.
    """
    global authentik_client
    config = AuthentikConfig(
        base_url=base_url,
        token=token,
        verify_ssl=verify_ssl,
    )
    authentik_client = AuthentikClient(config)

    # Test connection
    try:
        await authentik_client.request("GET", "/root/config/")
        logger.info("Successfully connected to Authentik API")
    except Exception as e:
        logger.exception(f"Failed to connect to Authentik API: {e}")
        await authentik_client.close()
        return

    # Run MCP server
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="authentik-mcp",
                    server_version="0.4.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        if authentik_client:
            await authentik_client.close()


def run() -> None:
    """Backward-compatible entry point: delegate to the CLI."""
    from authentik_mcp.cli import main  # noqa: PLC0415 (avoids a circular import)

    raise SystemExit(main())


if __name__ == "__main__":
    run()
