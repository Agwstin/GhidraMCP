[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# GhidraMCP v2 (Fork)

> Fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) with multi-program support, JSON API, new analysis endpoints, and performance improvements.

GhidraMCP is a Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

## What's new in this fork

### Multi-program & multi-instance
- **Multiple binaries at once** — all endpoints accept `?program=name` to target any open program in the CodeBrowser
- **Multiple CodeBrowsers** — the Python bridge accepts multiple `--ghidra-server` URLs to connect to parallel Ghidra instances
- **Auto-port detection** — if port 8080 is busy, the plugin tries 8081-8090 automatically
- `list_servers`, `list_all_programs` tools to see everything at a glance

### New endpoints
| Endpoint | Description |
|---|---|
| `/health` | Server status, bound port, active program |
| `/programs` | All open programs with name, path, language |
| `/read_memory` | Raw hex bytes from any address |
| `/list_structs` | All structures with field details |
| `/list_enums` | All enums with values |
| `/get_callgraph` | Recursive callers/callees (configurable depth, cycle-safe) |
| `/batch_decompile` | Decompile multiple functions in one request |
| `/undo` | Revert the last transaction |

### Performance
- **O(1) function lookup** via SymbolTable instead of linear iteration
- **4-thread pool** on HTTP server (was single-threaded)
- **DecompInterface leak fixed** — always disposed in try-finally
- **Timeouts**: 60s decompile, 120s batch (was 5s — large functions would always fail)

### JSON API
All responses are now structured JSON:
```json
{"status": "ok", "data": [{"name": "main", "address": "0x401000"}]}
```

### Bugfixes
- `endTransaction` void return compilation error
- `list_functions` now has pagination
- `renameData` reports actual success/failure
- Valid JSON unicode escapes (`\u00xx` instead of `\x00`)
- `searchFunctions` returns empty array instead of error on no results
- `batch_decompile` JSON parser handles commas inside quoted strings

---

# Original Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

For **multiple Ghidra instances** running in parallel:
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8081/"
      ]
    }
  }
}
```

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source
1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
