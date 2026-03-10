package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * GhidraMCPPlugin exposes Ghidra program analysis over HTTP so that LLMs and
 * external tools can query and modify the open program through an MCP-compatible
 * REST-like interface.
 *
 * <p>All responses are JSON. Listing endpoints support pagination via
 * {@code offset} and {@code limit} query parameters. Most analysis endpoints
 * accept an optional {@code program} query parameter to target a specific open
 * program by name; when omitted the currently active program is used.</p>
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------

    private HttpServer server;
    private int actualPort = -1;

    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME     = "Server Port";
    private static final int    DEFAULT_PORT         = 8080;
    private static final int    PORT_SEARCH_RANGE    = 10;
    private static final int    MAX_READ_MEMORY_BYTES = 4096;

    // ── FORK: Async decompilation ───────────────────────────────────────────
    private final ConcurrentHashMap<String, AsyncTask> asyncTasks = new ConcurrentHashMap<>();
    private final AtomicLong taskCounter = new AtomicLong(0);
    private final ExecutorService asyncExecutor = Executors.newFixedThreadPool(2);
    // ── END FORK ────────────────────────────────────────────────────────────

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /**
     * Constructs the plugin, registers the port option and starts the HTTP server.
     *
     * @param tool the hosting PluginTool
     */
    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null,
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server on any port", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    // -----------------------------------------------------------------------
    // Server bootstrap
    // -----------------------------------------------------------------------

    /**
     * Creates and starts the embedded HTTP server, trying up to
     * {@value #PORT_SEARCH_RANGE} consecutive ports beginning at the configured
     * port.
     */
    private void startServer() throws IOException {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int basePort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        // Try up to PORT_SEARCH_RANGE consecutive ports.
        IOException lastException = null;
        for (int attempt = 0; attempt < PORT_SEARCH_RANGE; attempt++) {
            int port = basePort + attempt;
            try {
                server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
                actualPort = port;
                break;
            } catch (IOException e) {
                lastException = e;
                Msg.warn(this, "Port " + port + " is busy, trying next...");
            }
        }

        if (server == null) {
            throw new IOException(
                "Could not bind to any port in range [" + basePort + ", " + (basePort + PORT_SEARCH_RANGE - 1) + "]",
                lastException);
        }

        // ---- Register all endpoints ----------------------------------------

        // Health / metadata
        server.createContext("/health", exchange -> {
            sendJsonResponse(exchange, buildHealthJson());
        });

        server.createContext("/programs", exchange -> {
            sendJsonResponse(exchange, jsonOk(buildProgramsArray()));
        });

        // Listing endpoints (legacy path names preserved)
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, getAllFunctionNames(qparams, offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, getAllClassNames(qparams, offset, limit));
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listSegments(qparams, offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listImports(qparams, offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listExports(qparams, offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listNamespaces(qparams, offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listDefinedData(qparams, offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, searchFunctionsByName(qparams, searchTerm, offset, limit));
        });

        // Decompile (legacy POST body = function name)
        server.createContext("/decompile", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
            sendJsonResponse(exchange, decompileFunctionByName(qparams, name));
        });

        // Rename endpoints
        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean ok = renameFunction(qparams, params.get("oldName"), params.get("newName"));
            sendJsonResponse(exchange, ok ? jsonOk(jsonString("Renamed successfully"))
                                         : jsonError("Rename failed"));
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean ok = renameDataAtAddress(qparams, params.get("address"), params.get("newName"));
            sendJsonResponse(exchange, ok ? jsonOk(jsonString("Rename data successful"))
                                         : jsonError("Rename data failed"));
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            String result = renameVariableInFunction(
                qparams,
                params.get("functionName"),
                params.get("oldName"),
                params.get("newName"));
            sendJsonResponse(exchange, result);
        });

        // Function analysis
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, getFunctionByAddress(qparams, qparams.get("address")));
        });

        server.createContext("/get_current_address", exchange -> {
            sendJsonResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendJsonResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, listFunctions(qparams, offset, limit));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, decompileFunctionByAddress(qparams, qparams.get("address")));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, disassembleFunction(qparams, qparams.get("address")));
        });

        // Comment endpoints
        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean ok = setDecompilerComment(qparams, params.get("address"), params.get("comment"));
            sendJsonResponse(exchange, ok ? jsonOk(jsonString("Comment set successfully"))
                                         : jsonError("Failed to set comment"));
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean ok = setDisassemblyComment(qparams, params.get("address"), params.get("comment"));
            sendJsonResponse(exchange, ok ? jsonOk(jsonString("Comment set successfully"))
                                         : jsonError("Failed to set comment"));
        });

        // Prototype / type endpoints
        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean ok = renameFunctionByAddress(qparams, params.get("function_address"), params.get("new_name"));
            sendJsonResponse(exchange, ok ? jsonOk(jsonString("Function renamed successfully"))
                                         : jsonError("Failed to rename function"));
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            PrototypeResult result = setFunctionPrototype(qparams, params.get("function_address"), params.get("prototype"));
            if (result.isSuccess()) {
                String msg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    msg += " | warnings: " + result.getErrorMessage();
                }
                sendJsonResponse(exchange, jsonOk(jsonString(msg)));
            } else {
                sendJsonResponse(exchange, jsonError("Failed to set function prototype: " + result.getErrorMessage()));
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, setLocalVariableTypeEndpoint(qparams, params));
        });

        // XRef endpoints
        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, getXrefsTo(qparams, qparams.get("address"), offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, getXrefsFrom(qparams, qparams.get("address"), offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, getFunctionXrefs(qparams, qparams.get("name"), offset, limit));
        });

        // String listing
        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, listDefinedStrings(qparams, offset, limit, qparams.get("filter")));
        });

        // New endpoints
        server.createContext("/read_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, readMemory(qparams,
                qparams.get("address"),
                parseIntOrDefault(qparams.get("length"), 64)));
        });

        server.createContext("/list_structs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, listStructs(qparams, offset, limit));
        });

        server.createContext("/list_enums", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, listEnums(qparams, offset, limit));
        });

        server.createContext("/get_callgraph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int depth = Math.min(parseIntOrDefault(qparams.get("depth"), 1), 3);
            sendJsonResponse(exchange, getCallgraph(qparams, qparams.get("name"), depth));
        });

        server.createContext("/batch_decompile", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
            sendJsonResponse(exchange, batchDecompile(qparams, body));
        });

        server.createContext("/undo", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, undoLastAction(qparams));
        });

        // ── FORK: Struct/Enum CRUD endpoints ────────────────────────────────

        server.createContext("/create_struct", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, createStruct(qparams, params.get("name"),
                parseIntOrDefault(params.get("size"), 0)));
        });

        server.createContext("/delete_struct", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, deleteStruct(qparams, params.get("name")));
        });

        server.createContext("/get_struct", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, getStruct(qparams, qparams.get("name")));
        });

        server.createContext("/add_struct_field", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, addStructField(qparams, params.get("struct_name"),
                parseIntOrDefault(params.get("offset"), -1),
                params.get("field_type"), params.get("field_name"),
                parseIntOrDefault(params.get("field_size"), -1)));
        });

        server.createContext("/create_enum", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, createEnum(qparams, params.get("name"),
                parseIntOrDefault(params.get("size"), 4)));
        });

        server.createContext("/add_enum_value", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, addEnumValue(qparams, params.get("enum_name"),
                params.get("entry_name"),
                Long.parseLong(params.getOrDefault("value", "0"))));
        });

        server.createContext("/delete_enum", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, deleteEnum(qparams, params.get("name")));
        });

        server.createContext("/apply_struct_at_address", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, applyStructAtAddress(qparams,
                params.get("struct_name"), params.get("address")));
        });

        server.createContext("/list_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, listTypes(qparams, offset, limit, qparams.get("category")));
        });

        // ── END FORK: Struct/Enum CRUD ──────────────────────────────────────

        // ── FORK: Async decompilation endpoints ─────────────────────────────

        server.createContext("/decompile_async", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, decompileAsync(qparams, params.get("address")));
        });

        server.createContext("/task_status", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, getTaskStatus(qparams.get("task_id")));
        });

        server.createContext("/task_result", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, getTaskResult(qparams.get("task_id")));
        });

        // ── END FORK: Async decompilation ───────────────────────────────────

        // ── FORK: Utility endpoints ─────────────────────────────────────────

        server.createContext("/save", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, saveProgram(qparams));
        });

        server.createContext("/goto", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, goToAddress(qparams, params.get("address")));
        });

        server.createContext("/create_function", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, createFunction(qparams, params.get("address")));
        });

        server.createContext("/search_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 10);
            sendJsonResponse(exchange, searchBytes(qparams, qparams.get("pattern"), maxResults));
        });

        server.createContext("/write_memory", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, writeMemory(qparams, params.get("address"), params.get("bytes")));
        });

        server.createContext("/set_calling_convention", exchange -> {
            Map<String, String> params  = parsePostParams(exchange);
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, setCallingConvention(qparams,
                params.get("function_address"), params.get("convention")));
        });

        // ── END FORK: Utility endpoints ─────────────────────────────────────

        // ---- Start the server ----------------------------------------------
        server.setExecutor(Executors.newFixedThreadPool(4));
        final int boundPort = actualPort;
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + boundPort);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + boundPort, e);
                server = null;
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // -----------------------------------------------------------------------
    // Multi-program helpers
    // -----------------------------------------------------------------------

    /**
     * Returns the program identified by the {@code program} query parameter, or
     * falls back to the currently active program when the parameter is absent.
     *
     * @param qparams query parameters map (may be empty but not null)
     * @return resolved Program, or {@code null} if none is found
     */
    private Program resolveProgram(Map<String, String> qparams) {
        String name = qparams.get("program");
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return null;

        if (name != null && !name.isEmpty()) {
            Program[] all = pm.getAllOpenPrograms();
            if (all != null) {
                for (Program p : all) {
                    if (p.getName().equals(name)) return p;
                }
            }
            return null; // requested by name but not found
        }
        return pm.getCurrentProgram();
    }

    /**
     * Returns the currently active program, convenience wrapper.
     */
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    /**
     * Builds the JSON array describing all open programs.
     */
    private String buildProgramsArray() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "[]";
        Program[] all = pm.getAllOpenPrograms();
        if (all == null || all.length == 0) return "[]";

        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < all.length; i++) {
            Program p = all[i];
            if (i > 0) sb.append(",");
            sb.append("{");
            sb.append("\"name\":").append(jsonString(p.getName())).append(",");
            sb.append("\"path\":").append(jsonString(p.getDomainFile().getPathname())).append(",");
            sb.append("\"id\":").append(jsonString(Integer.toHexString(System.identityHashCode(p)))).append(",");
            sb.append("\"language\":").append(jsonString(p.getLanguageID().getIdAsString()));
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // JSON helpers
    // -----------------------------------------------------------------------

    /**
     * Wraps {@code data} in a success envelope: {@code {"status":"ok","data":...}}.
     */
    private String jsonOk(String data) {
        return "{\"status\":\"ok\",\"data\":" + data + "}";
    }

    /**
     * Wraps {@code msg} in an error envelope: {@code {"status":"error","message":"..."}}.
     */
    private String jsonError(String msg) {
        return "{\"status\":\"error\",\"message\":" + jsonString(msg) + "}";
    }

    /**
     * Returns the JSON representation of {@code s} with necessary characters
     * escaped: {@code "}, {@code \}, newlines, carriage returns, and tabs.
     */
    private String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    /**
     * Builds a JSON array from a list of already-encoded JSON values (strings,
     * objects, etc.).
     */
    private String jsonArray(List<String> jsonItems) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < jsonItems.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(jsonItems.get(i));
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Finds functions by exact name using the SymbolTable for O(1) lookup.
     * Falls back to iterating all functions if the symbol approach yields nothing.
     */
    private List<Function> findFunctionsByName(Program program, String name) {
        List<Function> result = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
        FunctionManager funcMgr = program.getFunctionManager();
        for (Symbol sym : symTable.getSymbols(name, null)) {
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                Function func = funcMgr.getFunctionAt(sym.getAddress());
                if (func != null) result.add(func);
            }
        }
        return result;
    }

    /**
     * Builds the JSON payload for the {@code /health} endpoint.
     */
    private String buildHealthJson() {
        Program current = getCurrentProgram();
        ProgramManager pm = tool.getService(ProgramManager.class);
        int programCount = 0;
        if (pm != null && pm.getAllOpenPrograms() != null) {
            programCount = pm.getAllOpenPrograms().length;
        }
        String activeName = (current != null) ? current.getName() : null;

        StringBuilder sb = new StringBuilder();
        sb.append("{\"status\":\"ok\",\"data\":{");
        sb.append("\"server\":\"running\",");
        sb.append("\"port\":").append(actualPort).append(",");
        sb.append("\"activeProgram\":").append(jsonString(activeName)).append(",");
        sb.append("\"programCount\":").append(programCount);
        sb.append("}}");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Listing methods (pagination-aware, program-aware)
    // -----------------------------------------------------------------------

    private String getAllFunctionNames(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(f.getName())).append(",");
            obj.append("\"address\":").append(jsonString(f.getEntryPoint().toString()));
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String getAllClassNames(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);

        List<String> items = new ArrayList<>();
        for (String name : sorted) {
            items.add("{\"name\":" + jsonString(name) + "}");
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String listSegments(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(block.getName())).append(",");
            obj.append("\"start\":").append(jsonString(block.getStart().toString())).append(",");
            obj.append("\"end\":").append(jsonString(block.getEnd().toString())).append(",");
            obj.append("\"size\":").append(block.getSize()).append(",");
            obj.append("\"permissions\":").append(jsonString(
                (block.isRead()    ? "r" : "-") +
                (block.isWrite()   ? "w" : "-") +
                (block.isExecute() ? "x" : "-")));
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String listImports(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(symbol.getName())).append(",");
            obj.append("\"address\":").append(jsonString(symbol.getAddress().toString()));
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String listExports(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                StringBuilder obj = new StringBuilder("{");
                obj.append("\"name\":").append(jsonString(s.getName())).append(",");
                obj.append("\"address\":").append(jsonString(s.getAddress().toString()));
                obj.append("}");
                items.add(obj.toString());
            }
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String listNamespaces(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        // NOTE: iterates ALL symbols to collect unique namespaces; no faster API available.
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);

        List<String> items = new ArrayList<>();
        for (String ns : sorted) {
            items.add("{\"name\":" + jsonString(ns) + "}");
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String listDefinedData(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    StringBuilder obj = new StringBuilder("{");
                    obj.append("\"address\":").append(jsonString(data.getAddress().toString())).append(",");
                    obj.append("\"label\":").append(jsonString(escapeNonAscii(label))).append(",");
                    obj.append("\"value\":").append(jsonString(escapeNonAscii(valRepr)));
                    obj.append("}");
                    items.add(obj.toString());
                }
            }
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String searchFunctionsByName(Map<String, String> qparams, String searchTerm, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (searchTerm == null || searchTerm.isEmpty()) return jsonError("Search term is required");

        String lower = searchTerm.toLowerCase();
        List<String> items = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().toLowerCase().contains(lower)) {
                StringBuilder obj = new StringBuilder("{");
                obj.append("\"name\":").append(jsonString(func.getName())).append(",");
                obj.append("\"address\":").append(jsonString(func.getEntryPoint().toString()));
                obj.append("}");
                items.add(obj.toString());
            }
        }
        Collections.sort(items);
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private String listFunctions(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(func.getName())).append(",");
            obj.append("\"address\":").append(jsonString(func.getEntryPoint().toString())).append(",");
            obj.append("\"signature\":").append(jsonString(func.getSignature().toString()));
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    // -----------------------------------------------------------------------
    // Decompile / disassemble
    // -----------------------------------------------------------------------

    private String decompileFunctionByName(Map<String, String> qparams, String name) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        // Fast lookup via getGlobalFunctions, fall back to substring iteration.
        List<Function> candidates = new ArrayList<>(findFunctionsByName(program,name));
        if (candidates.isEmpty()) return jsonError("Function not found: " + name);

        Function func = candidates.get(0);
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (result != null && result.decompileCompleted()) {
                return jsonOk(jsonString(result.getDecompiledFunction().getC()));
            }
            return jsonError("Decompilation failed");
        } finally {
            decomp.dispose();
        }
    }

    private String decompileFunctionByAddress(Map<String, String> qparams, String addressStr) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return jsonError("No function found at or containing address " + addressStr);

            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(program);
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return jsonOk(jsonString(result.getDecompiledFunction().getC()));
                }
                return jsonError("Decompilation failed");
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return jsonError("Error decompiling function: " + e.getMessage());
        }
    }

    private String disassembleFunction(Map<String, String> qparams, String addressStr) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return jsonError("No function found at or containing address " + addressStr);

            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end   = func.getBody().getMaxAddress();

            List<String> instrs = new ArrayList<>();
            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) break;
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                StringBuilder obj = new StringBuilder("{");
                obj.append("\"address\":").append(jsonString(instr.getAddress().toString())).append(",");
                obj.append("\"instruction\":").append(jsonString(instr.toString()));
                if (comment != null) {
                    obj.append(",\"comment\":").append(jsonString(comment));
                }
                obj.append("}");
                instrs.add(obj.toString());
            }
            return jsonOk(jsonArray(instrs));
        } catch (Exception e) {
            return jsonError("Error disassembling function: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Rename / modify methods
    // -----------------------------------------------------------------------

    private boolean renameFunction(Map<String, String> qparams, String oldName, String newName) {
        Program program = resolveProgram(qparams);
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    // Fast path: getGlobalFunctions by exact name.
                    for (Function func : findFunctionsByName(program,oldName)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameDataAtAddress(Map<String, String> qparams, String addressStr, String newName) {
        Program program = resolveProgram(qparams);
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                        successFlag.set(true);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
        return successFlag.get();
    }

    private String renameVariableInFunction(Map<String, String> qparams,
                                            String functionName,
                                            String oldVarName,
                                            String newVarName) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        // Fast function lookup
        Function func = null;
        List<Function> candidates = new ArrayList<>(findFunctionsByName(program,functionName));
        if (!candidates.isEmpty()) {
            func = candidates.get(0);
        } else {
            // Fallback: iterate for exact match
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(functionName)) { func = f; break; }
            }
        }
        if (func == null) return jsonError("Function not found: " + functionName);

        final Function finalFunc = func;
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(finalFunc, 30, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted()) return jsonError("Decompilation failed");

            HighFunction highFunction = result.getHighFunction();
            if (highFunction == null) return jsonError("Decompilation failed (no high function)");

            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            if (localSymbolMap == null) return jsonError("Decompilation failed (no local symbol map)");

            HighSymbol highSymbol = null;
            Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                String symbolName = symbol.getName();
                if (symbolName.equals(oldVarName)) highSymbol = symbol;
                if (symbolName.equals(newVarName)) {
                    return jsonError("A variable named '" + newVarName + "' already exists in this function");
                }
            }
            if (highSymbol == null) return jsonError("Variable not found: " + oldVarName);

            boolean commitRequired = checkFullCommit(highSymbol, highFunction);

            final HighSymbol finalHighSymbol = highSymbol;
            AtomicBoolean successFlag = new AtomicBoolean(false);
            try {
                SwingUtilities.invokeAndWait(() -> {
                    int tx = program.startTransaction("Rename variable");
                    try {
                        if (commitRequired) {
                            HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                                ReturnCommitOption.NO_COMMIT, finalFunc.getSignatureSource());
                        }
                        HighFunctionDBUtil.updateDBVariable(
                            finalHighSymbol, newVarName, null, SourceType.USER_DEFINED);
                        successFlag.set(true);
                    } catch (Exception e) {
                        Msg.error(this, "Failed to rename variable", e);
                    } finally {
                        program.endTransaction(tx, successFlag.get());
                    }
                });
            } catch (InterruptedException | InvocationTargetException e) {
                String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
                Msg.error(this, errorMsg, e);
                return jsonError(errorMsg);
            }
            return successFlag.get() ? jsonOk(jsonString("Variable renamed"))
                                     : jsonError("Failed to rename variable");
        } finally {
            decomp.dispose();
        }
    }

    // -----------------------------------------------------------------------
    // Function analysis helpers
    // -----------------------------------------------------------------------

    private String getFunctionByAddress(Map<String, String> qparams, String addressStr) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return jsonError("No function found at address " + addressStr);

            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(func.getName())).append(",");
            obj.append("\"address\":").append(jsonString(func.getEntryPoint().toString())).append(",");
            obj.append("\"signature\":").append(jsonString(func.getSignature().toString())).append(",");
            obj.append("\"bodyStart\":").append(jsonString(func.getBody().getMinAddress().toString())).append(",");
            obj.append("\"bodyEnd\":").append(jsonString(func.getBody().getMaxAddress().toString()));
            obj.append("}");
            return jsonOk(obj.toString());
        } catch (Exception e) {
            return jsonError("Error getting function: " + e.getMessage());
        }
    }

    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return jsonError("Code viewer service not available");
        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return jsonError("No current location");
        return jsonOk(jsonString(location.getAddress().toString()));
    }

    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return jsonError("Code viewer service not available");
        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return jsonError("No current location");

        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return jsonError("No function at current location: " + location.getAddress());

        StringBuilder obj = new StringBuilder("{");
        obj.append("\"name\":").append(jsonString(func.getName())).append(",");
        obj.append("\"address\":").append(jsonString(func.getEntryPoint().toString())).append(",");
        obj.append("\"signature\":").append(jsonString(func.getSignature().toString()));
        obj.append("}");
        return jsonOk(obj.toString());
    }

    /**
     * Returns the function at or containing {@code addr}, preferring an exact match.
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    // -----------------------------------------------------------------------
    // Comment setting
    // -----------------------------------------------------------------------

    private boolean setCommentAtAddress(Map<String, String> qparams,
                                        String addressStr, String comment,
                                        int commentType, String transactionName) {
        Program program = resolveProgram(qparams);
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }
        return success.get();
    }

    private boolean setDecompilerComment(Map<String, String> qparams, String addressStr, String comment) {
        return setCommentAtAddress(qparams, addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    private boolean setDisassemblyComment(Map<String, String> qparams, String addressStr, String comment) {
        return setCommentAtAddress(qparams, addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    // ── FORK: Async decompilation task ──────────────────────────────────────
    private static class AsyncTask {
        volatile String status = "pending"; // pending, running, completed, failed
        volatile String result = null;
        volatile String error = null;
    }
    // ── END FORK ────────────────────────────────────────────────────────────

    // -----------------------------------------------------------------------
    // PrototypeResult inner class (preserved exactly)
    // -----------------------------------------------------------------------

    /**
     * Holds the outcome of a prototype-setting operation, including any diagnostic messages.
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() { return success; }
        public String getErrorMessage() { return errorMessage; }
    }

    // -----------------------------------------------------------------------
    // Rename function by address / set prototype / set variable type
    // -----------------------------------------------------------------------

    private boolean renameFunctionByAddress(Map<String, String> qparams,
                                            String functionAddrStr, String newName) {
        Program program = resolveProgram(qparams);
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
                newName == null || newName.isEmpty()) return false;

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> performFunctionRename(program, functionAddrStr, newName, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }
        return success.get();
    }

    private void performFunctionRename(Program program, String functionAddrStr,
                                       String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }
            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    private PrototypeResult setFunctionPrototype(Map<String, String> qparams,
                                                 String functionAddrStr, String prototype) {
        Program program = resolveProgram(qparams);
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty())
            return new PrototypeResult(false, "Function address is required");
        if (prototype == null || prototype.isEmpty())
            return new PrototypeResult(false, "Function prototype is required");

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
                                        AtomicBoolean success, StringBuilder errorMessage) {
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);
            addPrototypeComment(program, func, prototype);
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);
        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), CodeUnit.PLATE_COMMENT, "Setting prototype: " + prototype);
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                                AtomicBoolean success, StringBuilder errorMessage) {
        int txProto = program.startTransaction("Set function prototype");
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            ghidra.app.services.DataTypeManagerService dtms =
                tool.getService(ghidra.app.services.DataTypeManagerService.class);
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);
            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED);
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());
            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Handler for the {@code /set_local_variable_type} endpoint; returns a JSON response.
     */
    private String setLocalVariableTypeEndpoint(Map<String, String> qparams, Map<String, String> params) {
        String functionAddress = params.get("function_address");
        String variableName    = params.get("variable_name");
        String newType         = params.get("new_type");

        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        StringBuilder info = new StringBuilder();
        DataTypeManager dtm = program.getDataTypeManager();
        DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
        if (directType != null) {
            info.append("Found type: ").append(directType.getPathName());
        } else if (newType != null && newType.startsWith("P") && newType.length() > 1) {
            String baseTypeName = newType.substring(1);
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                info.append("Found base type for pointer: ").append(baseType.getPathName());
            } else {
                info.append("Base type not found for pointer: ").append(baseTypeName);
            }
        } else {
            info.append("Type not found directly: ").append(newType);
        }

        boolean success = setLocalVariableType(qparams, functionAddress, variableName, newType);
        StringBuilder result = new StringBuilder("{");
        result.append("\"success\":").append(success).append(",");
        result.append("\"typeInfo\":").append(jsonString(info.toString()));
        result.append("}");
        return success ? jsonOk(result.toString()) : jsonError("Failed to set variable type: " + info);
    }

    private boolean setLocalVariableType(Map<String, String> qparams, String functionAddrStr,
                                         String variableName, String newType) {
        Program program = resolveProgram(qparams);
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
                variableName == null || variableName.isEmpty() ||
                newType == null || newType.isEmpty()) return false;

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() ->
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }
        return success.get();
    }

    private void applyVariableType(Program program, String functionAddrStr,
                                   String variableName, String newType, AtomicBoolean success) {
        DecompileResultsHolder holder = null;
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            holder = decompileFunctionInternal(func, program);
            if (holder == null) return;

            HighFunction highFunction = holder.results.getHighFunction();
            if (highFunction == null) { Msg.error(this, "No high function available"); return; }

            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }
            Msg.info(this, "Found high variable for: " + variableName +
                     " with current type " + highVar.getDataType().getName());

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);
            if (dataType == null) { Msg.error(this, "Could not resolve data type: " + newType); return; }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);
            updateVariableType(program, symbol, dataType, success);
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            if (holder != null) holder.dispose();
        }
    }

    private HighSymbol findSymbolByName(HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) return s;
        }
        return null;
    }

    /**
     * Holder that keeps a DecompInterface alive along with its results so the
     * HighFunction remains usable.  Callers MUST call {@link #dispose()} when done.
     */
    private static class DecompileResultsHolder {
        final DecompInterface decomp;
        final DecompileResults results;
        DecompileResultsHolder(DecompInterface decomp, DecompileResults results) {
            this.decomp = decomp;
            this.results = results;
        }
        void dispose() { decomp.dispose(); }
    }

    /**
     * Decompiles a function and returns a holder that MUST be disposed by the caller.
     * Returns {@code null} if decompilation fails (decompiler is already disposed in that case).
     */
    private DecompileResultsHolder decompileFunctionInternal(Function func, Program program) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile");
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
        if (results == null || !results.decompileCompleted()) {
            decomp.dispose();
            Msg.error(this, "Could not decompile function" + (results != null ? ": " + results.getErrorMessage() : ""));
            return null;
        }
        return new DecompileResultsHolder(decomp, results);
    }

    private void updateVariableType(Program program, HighSymbol symbol,
                                    DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            HighFunctionDBUtil.updateDBVariable(
                symbol, symbol.getName(), dataType, SourceType.USER_DEFINED);
            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    // -----------------------------------------------------------------------
    // New endpoints
    // -----------------------------------------------------------------------

    /**
     * Reads raw bytes from program memory and returns them as a lowercase hex string.
     */
    private String readMemory(Map<String, String> qparams, String addressStr, int length) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("address parameter is required");
        if (length <= 0 || length > MAX_READ_MEMORY_BYTES) {
            length = Math.max(1, Math.min(length, MAX_READ_MEMORY_BYTES));
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Memory mem = program.getMemory();
            byte[] bytes = new byte[length];
            int read = mem.getBytes(addr, bytes);

            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < read; i++) {
                hex.append(String.format("%02x", bytes[i] & 0xFF));
            }

            StringBuilder obj = new StringBuilder("{");
            obj.append("\"address\":").append(jsonString(addr.toString())).append(",");
            obj.append("\"bytes\":").append(jsonString(hex.toString())).append(",");
            obj.append("\"length\":").append(read);
            obj.append("}");
            return jsonOk(obj.toString());
        } catch (Exception e) {
            return jsonError("Error reading memory: " + e.getMessage());
        }
    }

    /**
     * Lists all structure data types defined in the program's DataTypeManager.
     */
    private String listStructs(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> items = new ArrayList<>();

        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (!(dt instanceof Structure)) continue;
            Structure struct = (Structure) dt;

            StringBuilder fields = new StringBuilder("[");
            boolean firstField = true;
            for (DataTypeComponent comp : struct.getComponents()) {
                if (!firstField) fields.append(",");
                firstField = false;
                fields.append("{");
                fields.append("\"name\":").append(jsonString(comp.getFieldName() != null
                    ? comp.getFieldName() : "field_" + comp.getOffset())).append(",");
                fields.append("\"type\":").append(jsonString(comp.getDataType().getName())).append(",");
                fields.append("\"offset\":").append(comp.getOffset());
                fields.append("}");
            }
            fields.append("]");

            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(struct.getName())).append(",");
            obj.append("\"path\":").append(jsonString(struct.getPathName())).append(",");
            obj.append("\"size\":").append(struct.getLength()).append(",");
            obj.append("\"fields\":").append(fields);
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    /**
     * Lists all enum data types defined in the program's DataTypeManager.
     */
    private String listEnums(Map<String, String> qparams, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> items = new ArrayList<>();

        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (!(dt instanceof ghidra.program.model.data.Enum)) continue;
            ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;

            StringBuilder values = new StringBuilder("{");
            String[] names = enumDt.getNames();
            for (int i = 0; i < names.length; i++) {
                if (i > 0) values.append(",");
                values.append(jsonString(names[i])).append(":").append(enumDt.getValue(names[i]));
            }
            values.append("}");

            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(enumDt.getName())).append(",");
            obj.append("\"values\":").append(values);
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    /**
     * Returns a call-graph JSON object for the named function up to the given depth.
     */
    private String getCallgraph(Map<String, String> qparams, String name, int depth) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (name == null || name.isEmpty()) return jsonError("name parameter is required");

        List<Function> candidates = new ArrayList<>(findFunctionsByName(program,name));
        if (candidates.isEmpty()) {
            // Fallback: iterate for exact match
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) { candidates.add(f); break; }
            }
        }
        if (candidates.isEmpty()) return jsonError("Function not found: " + name);

        Function root = candidates.get(0);
        TaskMonitor monitor = new ConsoleTaskMonitor();

        String callersJson = buildCallerCalleeArray(root.getCallingFunctions(monitor));
        String calleesJson = buildCallerCalleeArray(root.getCalledFunctions(monitor));

        StringBuilder obj = new StringBuilder("{");
        obj.append("\"function\":").append(jsonString(root.getName())).append(",");
        obj.append("\"address\":").append(jsonString(root.getEntryPoint().toString())).append(",");
        obj.append("\"callers\":").append(callersJson).append(",");
        obj.append("\"callees\":").append(calleesJson);

        // If depth > 1, recurse one more level for each callee (with cycle guard).
        Set<Address> visited = new HashSet<>();
        visited.add(root.getEntryPoint());
        if (depth > 1) {
            obj.append(",\"calleeGraphs\":[");
            Set<Function> callees = root.getCalledFunctions(monitor);
            boolean first = true;
            for (Function callee : callees) {
                if (visited.contains(callee.getEntryPoint())) continue;
                if (!first) obj.append(",");
                first = false;
                String sub = buildCallgraphNode(callee, depth - 1, monitor, visited);
                obj.append(sub);
            }
            obj.append("]");
        }

        obj.append("}");
        return jsonOk(obj.toString());
    }

    private String buildCallgraphNode(Function func, int depth, TaskMonitor monitor, Set<Address> visited) {
        visited.add(func.getEntryPoint());
        String callersJson = buildCallerCalleeArray(func.getCallingFunctions(monitor));
        String calleesJson = buildCallerCalleeArray(func.getCalledFunctions(monitor));

        StringBuilder obj = new StringBuilder("{");
        obj.append("\"function\":").append(jsonString(func.getName())).append(",");
        obj.append("\"address\":").append(jsonString(func.getEntryPoint().toString())).append(",");
        obj.append("\"callers\":").append(callersJson).append(",");
        obj.append("\"callees\":").append(calleesJson);

        if (depth > 1) {
            obj.append(",\"calleeGraphs\":[");
            Set<Function> callees = func.getCalledFunctions(monitor);
            boolean first = true;
            for (Function callee : callees) {
                if (visited.contains(callee.getEntryPoint())) continue;
                if (!first) obj.append(",");
                first = false;
                obj.append(buildCallgraphNode(callee, depth - 1, monitor, visited));
            }
            obj.append("]");
        }
        obj.append("}");
        return obj.toString();
    }

    private String buildCallerCalleeArray(Set<Function> functions) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Function f : functions) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"name\":").append(jsonString(f.getName()))
              .append(",\"address\":").append(jsonString(f.getEntryPoint().toString()))
              .append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Decompiles multiple functions by name from a JSON array body and returns
     * a map of function name to decompiled code.
     */
    private String batchDecompile(Map<String, String> qparams, String body) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (body == null || body.isEmpty()) return jsonError("Request body with JSON array is required");

        // Simple manual JSON array parse: strip [ ] and split by comma between quoted strings.
        List<String> names = parseJsonStringArray(body);
        if (names.isEmpty()) return jsonError("No function names provided");

        StringBuilder result = new StringBuilder("{");
        boolean first = true;
        for (String name : names) {
            if (!first) result.append(",");
            first = false;

            List<Function> candidates = new ArrayList<>(findFunctionsByName(program,name));
            if (candidates.isEmpty()) {
                result.append(jsonString(name)).append(":").append(jsonString("Function not found"));
                continue;
            }

            Function func = candidates.get(0);
            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(program);
                DecompileResults dr = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (dr != null && dr.decompileCompleted()) {
                    result.append(jsonString(name)).append(":").append(jsonString(dr.getDecompiledFunction().getC()));
                } else {
                    result.append(jsonString(name)).append(":").append(jsonString("Decompilation failed"));
                }
            } finally {
                decomp.dispose();
            }
        }
        result.append("}");
        return jsonOk(result.toString());
    }

    /**
     * Minimal parser: extracts string values from a JSON array like {@code ["a","b","c"]}.
     * Handles commas inside quoted strings correctly. Does not handle escaped quotes.
     */
    private List<String> parseJsonStringArray(String json) {
        List<String> result = new ArrayList<>();
        String trimmed = json.trim();
        if (trimmed.startsWith("[")) trimmed = trimmed.substring(1);
        if (trimmed.endsWith("]"))   trimmed = trimmed.substring(0, trimmed.length() - 1);

        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                String val = current.toString().trim();
                if (!val.isEmpty()) result.add(val);
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        String last = current.toString().trim();
        if (!last.isEmpty()) result.add(last);
        return result;
    }

    /**
     * Calls {@code program.undo()} to revert the last committed transaction.
     */
    private String undoLastAction(Map<String, String> qparams) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        try {
            AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                try {
                    program.undo();
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Undo failed", e);
                }
            });
            return success.get() ? jsonOk(jsonString("Undo successful"))
                                 : jsonError("Undo failed");
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Undo failed: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // XRef methods
    // -----------------------------------------------------------------------

    private String getXrefsTo(Map<String, String> qparams, String addressStr, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                StringBuilder obj = new StringBuilder("{");
                obj.append("\"from\":").append(jsonString(fromAddr.toString())).append(",");
                obj.append("\"type\":").append(jsonString(ref.getReferenceType().getName()));
                if (fromFunc != null) {
                    obj.append(",\"function\":").append(jsonString(fromFunc.getName()));
                }
                obj.append("}");
                refs.add(obj.toString());
            }
            return jsonOk(paginateJsonArray(refs, offset, limit));
        } catch (Exception e) {
            return jsonError("Error getting references to address: " + e.getMessage());
        }
    }

    private String getXrefsFrom(Map<String, String> qparams, String addressStr, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Reference[] references = program.getReferenceManager().getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                StringBuilder obj = new StringBuilder("{");
                obj.append("\"to\":").append(jsonString(toAddr.toString())).append(",");
                obj.append("\"type\":").append(jsonString(ref.getReferenceType().getName()));

                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    obj.append(",\"function\":").append(jsonString(toFunc.getName()));
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null && data.getLabel() != null) {
                        obj.append(",\"data\":").append(jsonString(data.getLabel()));
                    }
                }
                obj.append("}");
                refs.add(obj.toString());
            }
            return jsonOk(paginateJsonArray(refs, offset, limit));
        } catch (Exception e) {
            return jsonError("Error getting references from address: " + e.getMessage());
        }
    }

    private String getFunctionXrefs(Map<String, String> qparams, String functionName, int offset, int limit) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (functionName == null || functionName.isEmpty()) return jsonError("Function name is required");

        try {
            // Fast lookup via getGlobalFunctions
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : findFunctionsByName(program, functionName)) {
                Address entryPoint = function.getEntryPoint();
                ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Address fromAddr = ref.getFromAddress();
                    Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                    StringBuilder obj = new StringBuilder("{");
                    obj.append("\"from\":").append(jsonString(fromAddr.toString())).append(",");
                    obj.append("\"type\":").append(jsonString(ref.getReferenceType().getName()));
                    if (fromFunc != null) {
                        obj.append(",\"function\":").append(jsonString(fromFunc.getName()));
                    }
                    obj.append("}");
                    refs.add(obj.toString());
                }
            }
            if (refs.isEmpty()) return jsonError("No references found to function: " + functionName);
            return jsonOk(paginateJsonArray(refs, offset, limit));
        } catch (Exception e) {
            return jsonError("Error getting function references: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // String listing
    // -----------------------------------------------------------------------

    private String listDefinedStrings(Map<String, String> qparams, int offset, int limit, String filter) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        List<String> items = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null || !isStringData(data)) continue;
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (filter != null && !value.toLowerCase().contains(filter.toLowerCase())) continue;

            StringBuilder obj = new StringBuilder("{");
            obj.append("\"address\":").append(jsonString(data.getAddress().toString())).append(",");
            obj.append("\"value\":").append(jsonString(escapeString(value)));
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    private boolean isStringData(Data data) {
        if (data == null) return false;
        String typeName = data.getDataType().getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    private String escapeString(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127)  sb.append(c);
            else if (c == '\n')       sb.append("\\n");
            else if (c == '\r')       sb.append("\\r");
            else if (c == '\t')       sb.append("\\t");
            else                      sb.append(String.format("\\u%04x", (int) c & 0xFFFF));
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Type resolution logic (preserved from original)
    // -----------------------------------------------------------------------

    /**
     * Resolves a named data type, handling pointer conventions and common built-ins.
     *
     * @param dtm      the program's DataTypeManager
     * @param typeName the type name string to resolve
     * @return a DataType, never {@code null} (falls back to int if unresolvable)
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);
            if (baseTypeName.equals("VOID")) return new PointerDataType(dtm.getDataType("/void"));
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) return new PointerDataType(baseType);
            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        switch (typeName.toLowerCase()) {
            case "int":
            case "long":              return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":             return dtm.getDataType("/uint");
            case "short":             return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":              return dtm.getDataType("/ushort");
            case "char":
            case "byte":              return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":     return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":           return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":  return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":           return dtm.getDataType("/bool");
            case "void":              return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) return directType;
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) return result;
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) return dt;
            if (dt.getName().equalsIgnoreCase(name)) return dt;
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // checkFullCommit (preserved exactly from original)
    // -----------------------------------------------------------------------

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     *
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction  is the given HighFunction
     * @return true if there is a difference (and a full commit is required)
     */
    protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) return false;
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) return true;
        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) return true;
            VariableStorage storage = param.getStorage();
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Utility: HTTP, params, pagination
    // -----------------------------------------------------------------------

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            for (String p : query.split("&")) {
                String[] kv = p.split("=", 2);
                if (kv.length == 2) {
                    try {
                        String key   = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String key   = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Applies offset/limit pagination to a list of JSON item strings and returns
     * a JSON array literal.
     */
    private String paginateJsonArray(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), start + limit);
        if (start >= items.size()) return "[]";
        return jsonArray(items.subList(start, end));
    }

    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try { return Integer.parseInt(val); }
        catch (NumberFormatException e) { return defaultValue; }
    }

    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) sb.append(c);
            else { sb.append("\\x"); sb.append(Integer.toHexString(c & 0xFF)); }
        }
        return sb.toString();
    }

    /**
     * Writes a JSON response with {@code Content-Type: application/json; charset=utf-8}.
     */
    private void sendJsonResponse(HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ── FORK: Struct/Enum CRUD methods ──────────────────────────────────────

    private String createStruct(Map<String, String> qparams, String name, int size) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (name == null || name.isEmpty()) return jsonError("Struct name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create struct");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    ghidra.program.model.data.StructureDataType struct =
                        new ghidra.program.model.data.StructureDataType(
                            new ghidra.program.model.data.CategoryPath("/"), name, Math.max(size, 0), dtm);
                    dtm.addDataType(struct, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating struct", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Struct '" + name + "' created"))
                             : jsonError("Failed to create struct");
    }

    private String deleteStruct(Map<String, String> qparams, String name) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (name == null || name.isEmpty()) return jsonError("Struct name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete struct");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, name);
                    if (dt instanceof Structure) {
                        dtm.remove(dt, new ConsoleTaskMonitor());
                        success.set(true);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error deleting struct", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Struct '" + name + "' deleted"))
                             : jsonError("Struct not found or delete failed");
    }

    private String getStruct(Map<String, String> qparams, String name) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (name == null || name.isEmpty()) return jsonError("Struct name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (!(dt instanceof Structure)) return jsonError("Struct not found: " + name);

        Structure struct = (Structure) dt;
        StringBuilder fields = new StringBuilder("[");
        boolean first = true;
        for (DataTypeComponent comp : struct.getComponents()) {
            if (!first) fields.append(",");
            first = false;
            fields.append("{");
            fields.append("\"name\":").append(jsonString(comp.getFieldName() != null
                ? comp.getFieldName() : "field_" + comp.getOffset())).append(",");
            fields.append("\"type\":").append(jsonString(comp.getDataType().getName())).append(",");
            fields.append("\"offset\":").append(comp.getOffset()).append(",");
            fields.append("\"size\":").append(comp.getLength());
            fields.append("}");
        }
        fields.append("]");

        StringBuilder obj = new StringBuilder("{");
        obj.append("\"name\":").append(jsonString(struct.getName())).append(",");
        obj.append("\"path\":").append(jsonString(struct.getPathName())).append(",");
        obj.append("\"size\":").append(struct.getLength()).append(",");
        obj.append("\"numComponents\":").append(struct.getNumComponents()).append(",");
        obj.append("\"fields\":").append(fields);
        obj.append("}");
        return jsonOk(obj.toString());
    }

    private String addStructField(Map<String, String> qparams, String structName,
                                   int offset, String fieldType, String fieldName, int fieldSize) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (structName == null || structName.isEmpty()) return jsonError("struct_name is required");
        if (fieldType == null || fieldType.isEmpty()) return jsonError("field_type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (!(dt instanceof Structure)) return;
                    Structure struct = (Structure) dt;

                    DataType fType = resolveDataType(dtm, fieldType);
                    if (fType == null) return;

                    if (offset >= 0) {
                        int size = fieldSize > 0 ? fieldSize : fType.getLength();
                        struct.replaceAtOffset(offset, fType, size,
                            fieldName != null ? fieldName : "field_" + offset, null);
                    } else {
                        struct.add(fType, fieldSize > 0 ? fieldSize : fType.getLength(),
                            fieldName != null ? fieldName : "field_" + struct.getLength(), null);
                    }
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error adding struct field", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Field added to struct '" + structName + "'"))
                             : jsonError("Failed to add field");
    }

    private String createEnum(Map<String, String> qparams, String name, int size) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (name == null || name.isEmpty()) return jsonError("Enum name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    ghidra.program.model.data.EnumDataType enumDt =
                        new ghidra.program.model.data.EnumDataType(
                            new ghidra.program.model.data.CategoryPath("/"), name, Math.max(size, 1));
                    dtm.addDataType(enumDt, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating enum", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Enum '" + name + "' created"))
                             : jsonError("Failed to create enum");
    }

    private String addEnumValue(Map<String, String> qparams, String enumName,
                                 String entryName, long value) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (enumName == null || enumName.isEmpty()) return jsonError("enum_name is required");
        if (entryName == null || entryName.isEmpty()) return jsonError("entry_name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add enum value");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (dt instanceof ghidra.program.model.data.Enum) {
                        ((ghidra.program.model.data.Enum) dt).add(entryName, value);
                        success.set(true);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error adding enum value", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Value '" + entryName + "' added to enum '" + enumName + "'"))
                             : jsonError("Enum not found or add failed");
    }

    private String deleteEnum(Map<String, String> qparams, String name) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (name == null || name.isEmpty()) return jsonError("Enum name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete enum");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, name);
                    if (dt instanceof ghidra.program.model.data.Enum) {
                        dtm.remove(dt, new ConsoleTaskMonitor());
                        success.set(true);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error deleting enum", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Enum '" + name + "' deleted"))
                             : jsonError("Enum not found or delete failed");
    }

    private String applyStructAtAddress(Map<String, String> qparams,
                                         String structName, String addressStr) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (structName == null || structName.isEmpty()) return jsonError("struct_name is required");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("address is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply struct at address");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (!(dt instanceof Structure)) return;

                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    ghidra.program.model.data.DataUtilities.createData(program, addr, dt,
                        dt.getLength(), ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error applying struct", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Struct '" + structName + "' applied at " + addressStr))
                             : jsonError("Failed to apply struct");
    }

    private String listTypes(Map<String, String> qparams, int offset, int limit, String category) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> items = new ArrayList<>();

        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (category != null && !category.isEmpty()) {
                if (!dt.getCategoryPath().toString().toLowerCase().contains(category.toLowerCase())) continue;
            }
            StringBuilder obj = new StringBuilder("{");
            obj.append("\"name\":").append(jsonString(dt.getName())).append(",");
            obj.append("\"path\":").append(jsonString(dt.getPathName())).append(",");
            obj.append("\"size\":").append(dt.getLength()).append(",");
            obj.append("\"kind\":").append(jsonString(dt.getClass().getSimpleName()));
            obj.append("}");
            items.add(obj.toString());
        }
        return jsonOk(paginateJsonArray(items, offset, limit));
    }

    // ── END FORK: Struct/Enum CRUD ──────────────────────────────────────────

    // ── FORK: Async decompilation methods ───────────────────────────────────

    private String decompileAsync(Map<String, String> qparams, String addressStr) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("address is required");

        String taskId = "task_" + taskCounter.incrementAndGet();
        AsyncTask task = new AsyncTask();
        task.status = "pending";
        asyncTasks.put(taskId, task);

        // Resolve function on the calling thread (Ghidra API is not thread-safe)
        Address addr;
        Function func;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
            func = getFunctionForAddress(program, addr);
        } catch (Exception e) {
            asyncTasks.remove(taskId);
            return jsonError("Invalid address: " + addressStr);
        }
        if (func == null) {
            asyncTasks.remove(taskId);
            return jsonError("No function at address: " + addressStr);
        }

        final Function finalFunc = func;
        asyncExecutor.submit(() -> {
            task.status = "running";
            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(program);
                DecompileResults result = decomp.decompileFunction(finalFunc, 120, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    task.result = result.getDecompiledFunction().getC();
                    task.status = "completed";
                } else {
                    task.error = "Decompilation failed";
                    task.status = "failed";
                }
            } catch (Exception e) {
                task.error = e.getMessage();
                task.status = "failed";
            } finally {
                decomp.dispose();
            }
        });

        return jsonOk("{\"task_id\":" + jsonString(taskId) + "}");
    }

    private String getTaskStatus(String taskId) {
        if (taskId == null || taskId.isEmpty()) return jsonError("task_id is required");
        AsyncTask task = asyncTasks.get(taskId);
        if (task == null) return jsonError("Task not found: " + taskId);

        StringBuilder obj = new StringBuilder("{");
        obj.append("\"task_id\":").append(jsonString(taskId)).append(",");
        obj.append("\"status\":").append(jsonString(task.status));
        if (task.error != null) {
            obj.append(",\"error\":").append(jsonString(task.error));
        }
        obj.append("}");
        return jsonOk(obj.toString());
    }

    private String getTaskResult(String taskId) {
        if (taskId == null || taskId.isEmpty()) return jsonError("task_id is required");
        AsyncTask task = asyncTasks.remove(taskId);
        if (task == null) return jsonError("Task not found: " + taskId);

        if (!"completed".equals(task.status)) {
            asyncTasks.put(taskId, task); // put it back
            return jsonError("Task not completed yet, status: " + task.status);
        }
        return jsonOk(jsonString(task.result));
    }

    // ── END FORK: Async decompilation ───────────────────────────────────────

    // ── FORK: Utility methods ───────────────────────────────────────────────

    private String saveProgram(Map<String, String> qparams) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        try {
            program.getDomainFile().save(new ConsoleTaskMonitor());
            return jsonOk(jsonString("Program saved: " + program.getName()));
        } catch (Exception e) {
            return jsonError("Save failed: " + e.getMessage());
        }
    }

    private String goToAddress(Map<String, String> qparams, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return jsonError("address is required");

        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ghidra.app.services.GoToService goToService = tool.getService(ghidra.app.services.GoToService.class);
            if (goToService == null) return jsonError("GoTo service not available");

            AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                success.set(goToService.goTo(addr));
            });
            return success.get() ? jsonOk(jsonString("Navigated to " + addressStr))
                                 : jsonError("Failed to navigate to " + addressStr);
        } catch (Exception e) {
            return jsonError("GoTo failed: " + e.getMessage());
        }
    }

    private String createFunction(Map<String, String> qparams, String addressStr) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("address is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    ghidra.app.cmd.function.CreateFunctionCmd cmd =
                        new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                    success.set(cmd.applyTo(program, new ConsoleTaskMonitor()));
                } catch (Exception e) {
                    Msg.error(this, "Error creating function", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Function created at " + addressStr))
                             : jsonError("Failed to create function at " + addressStr);
    }

    private String searchBytes(Map<String, String> qparams, String pattern, int maxResults) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (pattern == null || pattern.isEmpty()) return jsonError("pattern is required (hex string, e.g. '4889e5')");

        try {
            // Convert hex string to byte array
            String hex = pattern.replaceAll("\\s+", "");
            byte[] searchBytes = new byte[hex.length() / 2];
            byte[] mask = new byte[searchBytes.length];
            for (int i = 0; i < searchBytes.length; i++) {
                String byteStr = hex.substring(i * 2, i * 2 + 2);
                if (byteStr.equals("??")) {
                    searchBytes[i] = 0;
                    mask[i] = 0;
                } else {
                    searchBytes[i] = (byte) Integer.parseInt(byteStr, 16);
                    mask[i] = (byte) 0xFF;
                }
            }

            Memory mem = program.getMemory();
            List<String> results = new ArrayList<>();
            Address start = program.getMinAddress();
            int found = 0;

            while (start != null && found < maxResults) {
                Address addr = mem.findBytes(start, searchBytes, mask, true, new ConsoleTaskMonitor());
                if (addr == null) break;

                Function func = program.getFunctionManager().getFunctionContaining(addr);
                StringBuilder obj = new StringBuilder("{");
                obj.append("\"address\":").append(jsonString(addr.toString()));
                if (func != null) {
                    obj.append(",\"function\":").append(jsonString(func.getName()));
                }
                obj.append("}");
                results.add(obj.toString());

                start = addr.add(1);
                found++;
            }
            return jsonOk(jsonArray(results));
        } catch (Exception e) {
            return jsonError("Search failed: " + e.getMessage());
        }
    }

    private String writeMemory(Map<String, String> qparams, String addressStr, String hexBytes) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonError("address is required");
        if (hexBytes == null || hexBytes.isEmpty()) return jsonError("bytes is required (hex string)");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Write memory");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    String hex = hexBytes.replaceAll("\\s+", "");
                    byte[] bytes = new byte[hex.length() / 2];
                    for (int i = 0; i < bytes.length; i++) {
                        bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                    }
                    program.getMemory().setBytes(addr, bytes);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error writing memory", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Wrote " + (hexBytes.replaceAll("\\s+", "").length() / 2) + " bytes at " + addressStr))
                             : jsonError("Failed to write memory");
    }

    private String setCallingConvention(Map<String, String> qparams,
                                         String functionAddrStr, String convention) {
        Program program = resolveProgram(qparams);
        if (program == null) return jsonError("No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return jsonError("function_address is required");
        if (convention == null || convention.isEmpty()) return jsonError("convention is required");

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set calling convention");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    Function func = getFunctionForAddress(program, addr);
                    if (func != null) {
                        func.setCallingConvention(convention);
                        success.set(true);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error setting calling convention", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return jsonError("Failed: " + e.getMessage());
        }
        return success.get() ? jsonOk(jsonString("Calling convention set to '" + convention + "'"))
                             : jsonError("Failed to set calling convention");
    }

    // ── END FORK: Utility methods ───────────────────────────────────────────

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    @Override
    public void dispose() {
        // ── FORK: Async executor cleanup ────────────────────────────────────
        asyncExecutor.shutdownNow();
        asyncTasks.clear();
        // ── END FORK ────────────────────────────────────────────────────────
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1);
            server = null;
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
