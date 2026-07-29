import os

from mcp.server import MCPServer

from forgeflow.telemetry import configure_telemetry
from forgeflow_mcp.tools import (
    list_repository_tree,
    read_text_file,
    search_repository,
    summarize_dependency_manifests,
)

configure_telemetry()

mcp = MCPServer("ForgeFlow Repository Tools", stateless_http=True, json_response=True)
mcp.tool()(list_repository_tree)
mcp.tool()(read_text_file)
mcp.tool()(search_repository)
mcp.tool()(summarize_dependency_manifests)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8001"))
    mcp.run(transport="streamable-http", host=host, port=port)


if __name__ == "__main__":
    main()
