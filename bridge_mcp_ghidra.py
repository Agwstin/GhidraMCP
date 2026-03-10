# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.8.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from typing import Any
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp import Context

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

@mcp.tool(annotations={"readOnlyHint": True, "title": "List Servers"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List All Programs"})
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

@mcp.tool(annotations={"readOnlyHint": True, "title": "Health Check"})
def health(server: str = None) -> str:
    """
    GET /health. Show the status of a Ghidra server instance.

    Args:
        server: Optional Ghidra server URL. Defaults to the first configured server.

    Returns:
        Server health status string or JSON payload.
    """
    return safe_get("health", server=server, timeout=10)


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Programs"})
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

@mcp.tool(annotations={"readOnlyHint": True, "title": "Read Memory"})
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

@mcp.tool(annotations={"readOnlyHint": True, "title": "List Structs"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Enums"})
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

@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Call Graph"})
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

@mcp.tool(annotations={"readOnlyHint": True, "title": "Batch Decompile"})
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

@mcp.tool(annotations={"destructiveHint": True, "title": "Undo Last Action"})
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

@mcp.tool(annotations={"readOnlyHint": True, "title": "List Methods"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Classes"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Decompile Function"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Rename Function"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Rename Data"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Segments"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Imports"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Exports"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Namespaces"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Data Items"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Search Functions"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Rename Variable"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Function By Address"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Current Address"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Current Function"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Functions"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Decompile By Address"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Disassemble Function"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Set Decompiler Comment"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Set Disassembly Comment"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Rename Function By Address"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Set Function Prototype"})
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


@mcp.tool(annotations={"destructiveHint": True, "title": "Set Variable Type"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get XRefs To"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get XRefs From"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Function XRefs"})
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


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Strings"})
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


# ── FORK: Struct/Enum CRUD tools ─────────────────────────────────────


@mcp.tool(annotations={"destructiveHint": True, "title": "Create Struct"})
def create_struct(
    name: str,
    size: int = 0,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /create_struct. Create a new structure data type.

    Args:
        name:    Name of the struct to create.
        size:    Initial size in bytes (default: 0 for auto).
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post(
        "create_struct",
        {"name": name, "size": str(size)},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Delete Struct"})
def delete_struct(
    name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /delete_struct. Delete a structure data type by name.

    Args:
        name:    Name of the struct to delete.
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post(
        "delete_struct",
        {"name": name},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Struct Details"})
def get_struct(
    name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    GET /get_struct. Get detailed info about a struct including all fields.

    Args:
        name:    Name of the struct.
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_get(
        "get_struct",
        {"name": name},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Add Struct Field"})
def add_struct_field(
    struct_name: str,
    field_type: str,
    field_name: str = None,
    offset: int = -1,
    field_size: int = -1,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /add_struct_field. Add a field to an existing structure.

    Args:
        struct_name: Name of the target struct.
        field_type:  Data type of the field (e.g. "int", "char", "DWORD").
        field_name:  Optional name for the field.
        offset:      Byte offset within struct (-1 to append at end).
        field_size:  Override field size in bytes (-1 for automatic).
        program:     Optional program name.
        server:      Optional Ghidra server URL.
    """
    params = {
        "struct_name": struct_name,
        "field_type": field_type,
        "offset": str(offset),
        "field_size": str(field_size),
    }
    if field_name:
        params["field_name"] = field_name
    return safe_post("add_struct_field", params, program=program, server=server)


@mcp.tool(annotations={"destructiveHint": True, "title": "Create Enum"})
def create_enum(
    name: str,
    size: int = 4,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /create_enum. Create a new enum data type.

    Args:
        name:    Name of the enum to create.
        size:    Size in bytes (default: 4).
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post(
        "create_enum",
        {"name": name, "size": str(size)},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Add Enum Value"})
def add_enum_value(
    enum_name: str,
    entry_name: str,
    value: int,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /add_enum_value. Add a named value to an existing enum.

    Args:
        enum_name:  Name of the target enum.
        entry_name: Name of the enum entry.
        value:      Integer value.
        program:    Optional program name.
        server:     Optional Ghidra server URL.
    """
    return safe_post(
        "add_enum_value",
        {"enum_name": enum_name, "entry_name": entry_name, "value": str(value)},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Delete Enum"})
def delete_enum(
    name: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /delete_enum. Delete an enum data type by name.

    Args:
        name:    Name of the enum to delete.
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post(
        "delete_enum",
        {"name": name},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Apply Struct At Address"})
def apply_struct_at_address(
    struct_name: str,
    address: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /apply_struct_at_address. Apply a structure type at a memory address.

    Args:
        struct_name: Name of the struct to apply.
        address:     Target address in hex format.
        program:     Optional program name.
        server:      Optional Ghidra server URL.
    """
    return safe_post(
        "apply_struct_at_address",
        {"struct_name": struct_name, "address": address},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"readOnlyHint": True, "title": "List Data Types"})
def list_types(
    offset: int = 0,
    limit: int = 100,
    category: str = None,
    program: str = None,
    server: str = None,
) -> list:
    """
    GET /list_types. List all data types, optionally filtered by category.

    Args:
        offset:   Pagination offset (default: 0).
        limit:    Maximum results (default: 100).
        category: Optional category filter substring.
        program:  Optional program name.
        server:   Optional Ghidra server URL.
    """
    params: dict = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_types", params, program=program, server=server)


# ── END FORK: Struct/Enum CRUD ───────────────────────────────────────

# ── FORK: Async decompilation tools ──────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True, "title": "Decompile Async"})
def decompile_async(
    address: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /decompile_async. Start async decompilation, returns task_id immediately.

    For large functions that take a long time to decompile. Use get_task_status
    to poll progress and get_task_result to retrieve the result.

    Args:
        address: Function address in hex format.
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post(
        "decompile_async",
        {"address": address},
        program=program,
        server=server,
        timeout=15,
    )


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Task Status"})
def get_task_status(
    task_id: str,
    server: str = None,
) -> str:
    """
    GET /task_status. Check the status of an async task.

    Args:
        task_id: The task ID returned by decompile_async.
        server:  Optional Ghidra server URL.
    """
    return safe_get("task_status", {"task_id": task_id}, server=server)


@mcp.tool(annotations={"readOnlyHint": True, "title": "Get Task Result"})
def get_task_result(
    task_id: str,
    server: str = None,
) -> str:
    """
    GET /task_result. Retrieve the result of a completed async task.

    The task is removed after retrieval.

    Args:
        task_id: The task ID returned by decompile_async.
        server:  Optional Ghidra server URL.
    """
    return safe_get("task_result", {"task_id": task_id}, server=server, timeout=15)


# ── END FORK: Async decompilation ────────────────────────────────────

# ── FORK: Utility tools ─────────────────────────────────────────────


@mcp.tool(annotations={"destructiveHint": True, "title": "Save Program"})
def save(program: str = None, server: str = None) -> str:
    """
    POST /save. Save the current program to disk.

    Args:
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post("save", program=program, server=server, timeout=30)


@mcp.tool(annotations={"destructiveHint": True, "title": "Navigate To Address"})
def goto(
    address: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /goto. Navigate the Ghidra GUI to a specific address.

    Args:
        address: Target address in hex format.
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post("goto", {"address": address}, program=program, server=server)


@mcp.tool(annotations={"destructiveHint": True, "title": "Create Function"})
def create_function(
    address: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /create_function. Create a function at an address where none exists.

    Args:
        address: Target address in hex format.
        program: Optional program name.
        server:  Optional Ghidra server URL.
    """
    return safe_post(
        "create_function",
        {"address": address},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"readOnlyHint": True, "title": "Search Bytes"})
def search_bytes(
    pattern: str,
    max_results: int = 10,
    program: str = None,
    server: str = None,
) -> str:
    """
    GET /search_bytes. Search for a byte pattern in program memory.

    Use '??' for wildcard bytes (e.g. "4889??48" matches any byte in position 3).

    Args:
        pattern:     Hex byte pattern (e.g. "4889e5", "48??e5" for wildcards).
        max_results: Maximum results to return (default: 10).
        program:     Optional program name.
        server:      Optional Ghidra server URL.
    """
    return safe_get(
        "search_bytes",
        {"pattern": pattern, "max_results": max_results},
        program=program,
        server=server,
        timeout=30,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Write Memory"})
def write_memory(
    address: str,
    bytes_hex: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /write_memory. Patch bytes at a memory address.

    Args:
        address:   Target address in hex format.
        bytes_hex: Hex string of bytes to write (e.g. "90909090" for NOPs).
        program:   Optional program name.
        server:    Optional Ghidra server URL.
    """
    return safe_post(
        "write_memory",
        {"address": address, "bytes": bytes_hex},
        program=program,
        server=server,
    )


@mcp.tool(annotations={"destructiveHint": True, "title": "Set Calling Convention"})
def set_calling_convention(
    function_address: str,
    convention: str,
    program: str = None,
    server: str = None,
) -> str:
    """
    POST /set_calling_convention. Change a function's calling convention.

    Common conventions: __stdcall, __cdecl, __fastcall, __thiscall, __vectorcall.

    Args:
        function_address: Address of the function in hex format.
        convention:       Calling convention name (e.g. "__stdcall").
        program:          Optional program name.
        server:           Optional Ghidra server URL.
    """
    return safe_post(
        "set_calling_convention",
        {"function_address": function_address, "convention": convention},
        program=program,
        server=server,
    )


# ── END FORK: Utility tools ─────────────────────────────────────────

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
