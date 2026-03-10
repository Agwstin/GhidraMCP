# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.5.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from typing import Any
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# List of configured Ghidra server URLs, each normalized to end with "/"
ghidra_servers: list[str] = [DEFAULT_GHIDRA_SERVER]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _resolve_server(server: str = None) -> str:
    """Get server URL, defaulting to first configured server."""
    if server:
        return server.rstrip("/") + "/"
    return ghidra_servers[0]


def _build_params(params: dict = None, program: str = None) -> dict:
    """Build query params, injecting program if specified."""
    p = dict(params or {})
    if program:
        p["program"] = program
    return p


def _parse_response(response: requests.Response) -> Any:
    """Parse JSON response from Ghidra. Extract data field or return error."""
    if not response.ok:
        return f"Error {response.status_code}: {response.text.strip()}"
    try:
        j = response.json()
        if isinstance(j, dict):
            if j.get("status") == "error":
                return f"Error: {j.get('message', 'Unknown error')}"
            if "data" in j:
                return j["data"]
        return j
    except Exception:
        return response.text.strip()


def safe_get(
    endpoint: str,
    params: dict = None,
    program: str = None,
    server: str = None,
    timeout: int = 15,
) -> Any:
    """Perform a GET request against a Ghidra server endpoint."""
    url = urljoin(_resolve_server(server), endpoint)
    p = _build_params(params, program)
    try:
        response = requests.get(url, params=p, timeout=timeout)
        response.encoding = "utf-8"
        return _parse_response(response)
    except Exception as e:
        return f"Request failed: {str(e)}"


def safe_post(
    endpoint: str,
    data: dict | str = None,
    program: str = None,
    server: str = None,
    timeout: int = 15,
) -> Any:
    """Perform a POST request against a Ghidra server endpoint."""
    url = urljoin(_resolve_server(server), endpoint)
    query_params = _build_params(program=program)
    try:
        if isinstance(data, dict):
            response = requests.post(
                url, data=data, params=query_params, timeout=timeout
            )
        elif isinstance(data, str):
            response = requests.post(
                url,
                data=data.encode("utf-8"),
                params=query_params,
                timeout=timeout,
            )
        else:
            response = requests.post(url, params=query_params, timeout=timeout)
        response.encoding = "utf-8"
        return _parse_response(response)
    except Exception as e:
        return f"Request failed: {str(e)}"


# ---------------------------------------------------------------------------
# Multi-server tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_servers(server: str = None) -> str:
    """
    List configured Ghidra servers and query /health on each.

    Args:
        server: Optional. If provided, query only this server. Otherwise query all.

    Returns aggregated health status for every server URL that was passed via
    --ghidra-server at startup.
    """
    servers_to_query = [_resolve_server(server)] if server else ghidra_servers
    lines: list[str] = []
    for srv in servers_to_query:
        result = safe_get("health", server=srv, timeout=10)
        lines.append(f"{srv} -> {result}")
    return "\n".join(lines)


@mcp.tool()
def list_all_programs(server: str = None) -> str:
    """
    Query /programs on Ghidra servers and return aggregated results.

    Args:
        server: Optional. If provided, query only this server. Otherwise query all.

    Useful when multiple Ghidra instances are running simultaneously with
    different binaries loaded.
    """
    servers_to_query = [_resolve_server(server)] if server else ghidra_servers
    lines: list[str] = []
    for srv in servers_to_query:
        result = safe_get("programs", server=srv, timeout=15)
        lines.append(f"=== {srv} ===")
        if isinstance(result, list):
            lines.extend(str(item) for item in result)
        else:
            lines.append(str(result))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Health / programs
# ---------------------------------------------------------------------------

@mcp.tool()
def health(server: str = None) -> str:
    """
    GET /health. Show the status of a Ghidra server instance.

    Args:
        server: Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        Server health status string or JSON payload.
    """
    return safe_get("health", server=server, timeout=10)


@mcp.tool()
def list_programs(server: str = None) -> str:
    """
    GET /programs. List all open programs/binaries in a Ghidra instance.

    Args:
        server: Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of open program names in the target Ghidra instance.
    """
    return safe_get("programs", server=server, timeout=15)


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

@mcp.tool()
def read_memory(
    address: str,
    length: int = 256,
    program: str = None,
    server: str = None,
) -> str:
    """
    GET /read_memory. Read raw bytes from a given address in the loaded binary.

    Args:
        address: Target address in hex format (e.g. "0x140001000").
        length:  Number of bytes to read (default: 256).
        program: Optional program name to target within a multi-program Ghidra session.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        Hex dump or error string.
    """
    return safe_get(
        "read_memory",
        {"address": address, "length": length},
        program=program,
        server=server,
        timeout=15,
    )


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@mcp.tool()
def list_structs(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    GET /list_structs. List all struct data types defined in the program.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of struct definitions.
    """
    return safe_get(
        "list_structs",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
        timeout=15,
    )


@mcp.tool()
def list_enums(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    GET /list_enums. List all enum data types defined in the program.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of enum definitions.
    """
    return safe_get(
        "list_enums",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
        timeout=15,
    )


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------

@mcp.tool()
def get_callgraph(
    name: str,
    depth: int = 1,
    program: str = None,
    server: str = None,
) -> str:
    """
    GET /get_callgraph. Retrieve the call graph for a function by name.

    Args:
        name:    Function name to build the call graph for.
        depth:   Call depth to traverse (default: 1).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        Call graph data as a string or structured object.
    """
    return safe_get(
        "get_callgraph",
        {"name": name, "depth": depth},
        program=program,
        server=server,
        timeout=15,
    )


# ---------------------------------------------------------------------------
# Batch decompile
# ---------------------------------------------------------------------------

@mcp.tool()
def batch_decompile(
    names: list[str],
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /batch_decompile. Decompile multiple functions in a single request.

    More efficient than calling decompile_function individually when you need
    to decompile several functions at once.

    Args:
        names:   List of function names to decompile.
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        Decompiled C code for all requested functions.
    """
    url = urljoin(_resolve_server(server), "batch_decompile")
    query_params = _build_params(program=program)
    try:
        response = requests.post(
            url,
            json={"names": names},
            params=query_params,
            timeout=120,
        )
        response.encoding = "utf-8"
        return _parse_response(response)
    except Exception as e:
        return f"Request failed: {str(e)}"


# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------

@mcp.tool()
def undo(program: str = None, server: str = None) -> str:
    """
    POST /undo. Undo the last analysis or renaming action in Ghidra.

    Args:
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        Confirmation string or error message.
    """
    return safe_post("undo", program=program, server=server, timeout=15)


# ---------------------------------------------------------------------------
# Existing tools (updated with program + server params)
# ---------------------------------------------------------------------------

@mcp.tool()
def list_methods(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List all function names in the program with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "methods",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def list_classes(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List all namespace/class names in the program with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "classes",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def decompile_function(
    name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.

    Args:
        name:    Function name to decompile.
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post("decompile", name, program=program, server=server, timeout=60)


@mcp.tool()
def rename_function(
    old_name: str,
    new_name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Rename a function by its current name to a new user-defined name.

    Args:
        old_name: Current function name.
        new_name: Desired new name.
        program:  Optional program name.
        server:   Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "renameFunction",
        {"oldName": old_name, "newName": new_name},
        program=program,
        server=server,
    )


@mcp.tool()
def rename_data(
    address: str,
    new_name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Rename a data label at the specified address.

    Args:
        address:  Target address in hex format.
        new_name: Desired new label name.
        program:  Optional program name.
        server:   Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "renameData",
        {"address": address, "newName": new_name},
        program=program,
        server=server,
    )


@mcp.tool()
def list_segments(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List all memory segments in the program with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "segments",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def list_imports(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List imported symbols in the program with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "imports",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def list_exports(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List exported functions/symbols with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "exports",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def list_namespaces(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List all non-global namespaces in the program with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "namespaces",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def list_data_items(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List defined data labels and their values with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "data",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def search_functions_by_name(
    query: str,
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    Search for functions whose name contains the given substring.

    Args:
        query:   Substring to search for in function names.
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(
        "searchFunctions",
        {"query": query, "offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def rename_variable(
    function_name: str,
    old_name: str,
    new_name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Rename a local variable within a function.

    Args:
        function_name: Name of the function containing the variable.
        old_name:      Current variable name.
        new_name:      Desired new variable name.
        program:       Optional program name.
        server:        Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "renameVariable",
        {"functionName": function_name, "oldName": old_name, "newName": new_name},
        program=program,
        server=server,
    )


@mcp.tool()
def get_function_by_address(
    address: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Get function information by its address.

    Args:
        address: Function address in hex format (e.g. "0x140001000").
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    result = safe_get(
        "get_function_by_address",
        {"address": address},
        program=program,
        server=server,
    )
    if isinstance(result, list):
        return "\n".join(str(item) for item in result)
    return str(result)


@mcp.tool()
def get_current_address(program: str = None, server: str = None) -> str:
    """
    Get the address currently selected by the user in the Ghidra GUI.

    Args:
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    result = safe_get("get_current_address", program=program, server=server)
    if isinstance(result, list):
        return "\n".join(str(item) for item in result)
    return str(result)


@mcp.tool()
def get_current_function(program: str = None, server: str = None) -> str:
    """
    Get the function currently selected by the user in the Ghidra GUI.

    Args:
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    result = safe_get("get_current_function", program=program, server=server)
    if isinstance(result, list):
        return "\n".join(str(item) for item in result)
    return str(result)


@mcp.tool()
def list_functions(
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    List all functions in the database with pagination.

    Args:
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of results (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "list_functions",
        {"offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def decompile_function_by_address(
    address: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Decompile a function at the given address and return the decompiled C code.

    Args:
        address: Function address in hex format (e.g. "0x140001000").
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    result = safe_get(
        "decompile_function",
        {"address": address},
        program=program,
        server=server,
        timeout=60,
    )
    if isinstance(result, list):
        return "\n".join(str(item) for item in result)
    return str(result)


@mcp.tool()
def disassemble_function(
    address: str,
    program: str = None,
    server: str = None,
) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.

    Args:
        address: Function address in hex format (e.g. "0x140001000").
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_get(
        "disassemble_function",
        {"address": address},
        program=program,
        server=server,
    )


@mcp.tool()
def set_decompiler_comment(
    address: str,
    comment: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Set a comment for a given address in the function pseudocode (decompiler view).

    Args:
        address: Target address in hex format.
        comment: Comment text to set.
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "set_decompiler_comment",
        {"address": address, "comment": comment},
        program=program,
        server=server,
    )


@mcp.tool()
def set_disassembly_comment(
    address: str,
    comment: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Set a comment for a given address in the function disassembly listing.

    Args:
        address: Target address in hex format.
        comment: Comment text to set.
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "set_disassembly_comment",
        {"address": address, "comment": comment},
        program=program,
        server=server,
    )


@mcp.tool()
def rename_function_by_address(
    function_address: str,
    new_name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Rename a function identified by its address.

    Args:
        function_address: Address of the function in hex format.
        new_name:         Desired new function name.
        program:          Optional program name.
        server:           Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "rename_function_by_address",
        {"function_address": function_address, "new_name": new_name},
        program=program,
        server=server,
    )


@mcp.tool()
def set_function_prototype(
    function_address: str,
    prototype: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Set a function's prototype/signature (return type and parameter types).

    Args:
        function_address: Address of the function in hex format.
        prototype:        C-style prototype string, e.g. "int foo(int a, char *b)".
        program:          Optional program name.
        server:           Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "set_function_prototype",
        {"function_address": function_address, "prototype": prototype},
        program=program,
        server=server,
    )


@mcp.tool()
def set_local_variable_type(
    function_address: str,
    variable_name: str,
    new_type: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    Set the data type of a local variable within a function.

    Args:
        function_address: Address of the containing function in hex format.
        variable_name:    Name of the local variable to retype.
        new_type:         New data type string, e.g. "int *" or "DWORD".
        program:          Optional program name.
        server:           Optional Ghidra server URL. Defaults to the first configured server.
    """
    return safe_post(
        "set_local_variable_type",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
        },
        program=program,
        server=server,
    )


@mcp.tool()
def get_xrefs_to(
    address: str,
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    Get all cross-references pointing TO the specified address.

    Args:
        address: Target address in hex format (e.g. "0x1400010a0").
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of references to return (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of references to the specified address.
    """
    return safe_get(
        "xrefs_to",
        {"address": address, "offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def get_xrefs_from(
    address: str,
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    Get all cross-references originating FROM the specified address.

    Args:
        address: Source address in hex format (e.g. "0x1400010a0").
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of references to return (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of references from the specified address.
    """
    return safe_get(
        "xrefs_from",
        {"address": address, "offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def get_function_xrefs(
    name: str,
    offset: int = 0,
    limit: int = 100,
    program: str = None,
    server: str = None,
) -> list:
    """
    Get all cross-references to the specified function by name.

    Args:
        name:    Function name to look up references for.
        offset:  Pagination offset (default: 0).
        limit:   Maximum number of references to return (default: 100).
        program: Optional program name.
        server:  Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of references to the specified function.
    """
    return safe_get(
        "function_xrefs",
        {"name": name, "offset": offset, "limit": limit},
        program=program,
        server=server,
    )


@mcp.tool()
def list_strings(
    offset: int = 0,
    limit: int = 2000,
    filter_str: str = None,
    program: str = None,
    server: str = None,
) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset:     Pagination offset (default: 0).
        limit:      Maximum number of strings to return (default: 2000).
        filter_str: Optional substring filter to match within string content.
        program:    Optional program name.
        server:     Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        List of strings with their addresses.
    """
    params: dict = {"offset": offset, "limit": limit}
    if filter_str:
        params["filter"] = filter_str
    return safe_get("strings", params, program=program, server=server)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument(
        "--ghidra-server",
        type=str,
        nargs="+",
        default=[DEFAULT_GHIDRA_SERVER],
        help=f"One or more Ghidra server URLs (default: {DEFAULT_GHIDRA_SERVER})",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (only used for sse), default: 8081",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: stdio",
    )
    args = parser.parse_args()

    global ghidra_servers
    ghidra_servers = [
        url.rstrip("/") + "/" for url in args.ghidra_server
    ]

    if args.transport == "sse":
        try:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger().setLevel(logging.INFO)

            mcp.settings.log_level = "INFO"
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8081

            logger.info(f"Connecting to Ghidra server(s): {ghidra_servers}")
            logger.info(
                f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse"
            )
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
