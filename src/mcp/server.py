# MCP Server implementation with tool registration

import logging
from typing import Dict, Any, Callable
from .schemas import ToolResponse

logger = logging.getLogger(__name__)

class MCPServer:
    """Simple MCP server for running tools"""

    def __init__(self):
        self._tools: Dict[str, Callable] = {}

    def register_tool(self, name: str, tool_func: Callable) -> None:
        """Register a tool function"""
        self._tools[name] = tool_func
        logger.info(f"Registered MCP tool: {name}")

    def list_tools(self) -> list[str]:
        """List all registered tools"""
        return list(self._tools.keys())

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered"""
        return name in self._tools

    async def run_tool(self, name: str, **kwargs) -> ToolResponse:
        """
        Run a tool by name with given arguments

        Args:
            name: Tool name
            **kwargs: Tool arguments

        Returns:
            ToolResponse with results

        Raises:
            ValueError: If tool is not registered
        """
        if not self.has_tool(name):
            available = self.list_tools()
            raise ValueError(f"Unknown tool '{name}'. Available tools: {available}")

        try:
            logger.info(f"Running tool: {name} with args: {kwargs}")
            tool_func = self._tools[name]

            # Call the tool function (assuming async for now)
            if hasattr(tool_func, '__call__'):
                result = await tool_func(**kwargs) if hasattr(tool_func, '__call__') else tool_func(**kwargs)
            else:
                # Synchronous call
                result = tool_func(**kwargs)

            logger.info(f"Tool {name} completed successfully")

            # Ensure result is a ToolResponse
            if isinstance(result, ToolResponse):
                return result
            else:
                # Wrap plain results in ToolResponse
                return ToolResponse(
                    success=True,
                    message=f"Tool {name} executed successfully",
                    data=result
                )

        except Exception as e:
            logger.error(f"Error running tool {name}: {str(e)}", exc_info=True)
            return ToolResponse(
                success=False,
                message=f"Tool {name} failed: {str(e)}"
            )

# Global MCP server instance
mcp_server = MCPServer()
