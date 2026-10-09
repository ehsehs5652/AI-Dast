"""Generic MCP client: connect MCP servers and reach their tools on demand."""

from __future__ import annotations

from aidast.recon.strix_engine.tools.mcp.agent_tools import (
    call_mcp,
    describe_mcp,
    get_mcp_tool_schema,
    list_mcps,
    search_mcp_tools,
)
from aidast.recon.strix_engine.tools.mcp.client import (
    ConnectedMcpServer,
    attach_mcp_requests,
    connect_mcp_servers,
)
from aidast.recon.strix_engine.tools.mcp.config import (
    BearerAuth,
    McpAuth,
    McpConnectionConfig,
)
from aidast.recon.strix_engine.tools.mcp.failures import FailureInfo, HttpStatusRecorder, classify
from aidast.recon.strix_engine.tools.mcp.loader import load_user_mcp_configs
from aidast.recon.strix_engine.tools.mcp.naming import namespaced_tool_name
from aidast.recon.strix_engine.tools.mcp.registry import (
    CALL_MCP_TOOL,
    DESCRIBE_MCP_TOOL,
    GET_MCP_TOOL_SCHEMA_TOOL,
    MCP_DISPATCH_TOOLS,
    MCP_REGISTRY_CONTEXT_KEY,
    SEARCH_MCP_TOOLS_TOOL,
    McpCallInfo,
    McpConnectionEntry,
    McpConnectionRequest,
    McpConnectionStatus,
    McpConnectionSummary,
    McpRegistry,
    resolve_mcp_call,
)
from aidast.recon.strix_engine.tools.mcp.session import McpConnectionUnavailableError, SupervisedMcpSession


__all__ = [
    "CALL_MCP_TOOL",
    "DESCRIBE_MCP_TOOL",
    "GET_MCP_TOOL_SCHEMA_TOOL",
    "MCP_DISPATCH_TOOLS",
    "MCP_REGISTRY_CONTEXT_KEY",
    "SEARCH_MCP_TOOLS_TOOL",
    "BearerAuth",
    "ConnectedMcpServer",
    "FailureInfo",
    "HttpStatusRecorder",
    "McpAuth",
    "McpCallInfo",
    "McpConnectionConfig",
    "McpConnectionEntry",
    "McpConnectionRequest",
    "McpConnectionStatus",
    "McpConnectionSummary",
    "McpConnectionUnavailableError",
    "McpRegistry",
    "SupervisedMcpSession",
    "attach_mcp_requests",
    "call_mcp",
    "classify",
    "connect_mcp_servers",
    "describe_mcp",
    "get_mcp_tool_schema",
    "list_mcps",
    "load_user_mcp_configs",
    "namespaced_tool_name",
    "resolve_mcp_call",
    "search_mcp_tools",
]
