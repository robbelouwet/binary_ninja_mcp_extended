/**
 * MCP Tool definitions for Binary Ninja integration.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BinjaHttpClient } from "./client.js";

export function registerTools(server: McpServer, client: BinjaHttpClient): void {
  // Helper function to get active filename
  async function getActiveFilename(): Promise<string> {
    const data = await client.getJson<{ filename?: string }>("status");
    if (data && typeof data === "object" && "filename" in data) {
      return (data as { filename: string }).filename || "(none)";
    }
    return "(none)";
  }

  // ===== Function Analysis Tools =====

  server.tool(
    "list_methods",
    "List all function names in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const filename = await getActiveFilename();
      const lines = await client.getLines("methods", { offset, limit });
      return {
        content: [{ type: "text", text: `File: ${filename}\n${lines.join("\n")}` }],
      };
    }
  );

  server.tool(
    "get_entry_points",
    "List entry point(s) of the loaded binary.",
    {},
    async () => {
      const data = await client.getJson<{ entry_points?: Array<{ address: string; name?: string }> }>("entryPoints");
      if (!data || "error" in data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      const entryPoints = (data as { entry_points?: Array<{ address: string; name?: string }> }).entry_points || [];
      const lines = entryPoints.map((ep) => {
        const addr = ep.address;
        const name = ep.name || "(unknown)";
        return `${addr}\t${name}`;
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "search_functions_by_name",
    "Search for functions whose name contains the given substring.",
    {
      query: z.string().describe("Search query string"),
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ query, offset = 0, limit = 100 }) => {
      if (!query) {
        return { content: [{ type: "text", text: "Error: query string is required" }] };
      }
      const lines = await client.getLines("searchFunctions", { query, offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "decompile_function",
    "Decompile a specific function by name and return the decompiled C code.",
    {
      name: z.string().describe("Function name or address"),
    },
    async ({ name }) => {
      const filename = await getActiveFilename();
      const data = await client.getJson<{ decompiled?: string; error?: string }>("decompile", { name });
      if (!data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: no response` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: ${data.error}` }] };
      }
      const decompiled = (data as { decompiled?: string }).decompiled;
      return { content: [{ type: "text", text: `File: ${filename}\n\n${decompiled || ""}` }] };
    }
  );

  server.tool(
    "get_il",
    "Get IL for a function in the selected view (hlil, mlil, llil).",
    {
      name_or_address: z.string().describe("Function name or address (hex like 0x401000)"),
      view: z.enum(["hlil", "mlil", "llil"]).default("hlil").describe("IL view: hlil, mlil, or llil"),
      ssa: z.boolean().default(false).describe("Request SSA form (MLIL/LLIL only)"),
    },
    async ({ name_or_address, view = "hlil", ssa = false }) => {
      const filename = await getActiveFilename();
      const ident = name_or_address.trim();
      const params: Record<string, string | number> = { view, ssa: ssa ? 1 : 0 };
      if (ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)) {
        params.address = ident;
      } else {
        params.name = ident;
      }
      const data = await client.getJson<{ il?: string; error?: unknown }>("il", params);
      if (!data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: no response` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: ${JSON.stringify(data.error)}` }] };
      }
      const il = (data as { il?: string }).il;
      return { content: [{ type: "text", text: `File: ${filename}\n\n${il || ""}` }] };
    }
  );

  server.tool(
    "fetch_disassembly",
    "Retrieve the disassembled code of a function as assembly mnemonic instructions.",
    {
      name: z.string().describe("Function name"),
    },
    async ({ name }) => {
      const filename = await getActiveFilename();
      const data = await client.getJson<{ assembly?: string; error?: string }>("assembly", { name });
      if (!data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: no response` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: ${(data as { error: string }).error}` }] };
      }
      const assembly = (data as { assembly?: string }).assembly;
      return { content: [{ type: "text", text: `File: ${filename}\n\n${assembly || ""}` }] };
    }
  );

  // ===== Rename Tools =====

  server.tool(
    "rename_function",
    "Rename a function by its current name. The configured prefix will be automatically prepended if not present.",
    {
      old_name: z.string().describe("Current function name"),
      new_name: z.string().describe("New function name"),
    },
    async ({ old_name, new_name }) => {
      const result = await client.post("renameFunction", { oldName: old_name, newName: new_name });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "rename_single_variable",
    "Rename a variable in a function.",
    {
      function_name: z.string().describe("Function name"),
      variable_name: z.string().describe("Current variable name"),
      new_name: z.string().describe("New variable name"),
    },
    async ({ function_name, variable_name, new_name }) => {
      const data = await client.getJson<{ status?: string; error?: string }>("renameVariable", {
        functionName: function_name,
        variableName: variable_name,
        newName: new_name,
      });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("status" in data) {
        return { content: [{ type: "text", text: (data as { status: string }).status }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "rename_multi_variables",
    "Rename multiple local variables in one call.",
    {
      function_identifier: z.string().describe("Function name or address (hex)"),
      mapping_json: z.string().optional().describe("JSON object old->new"),
      pairs: z.string().optional().describe("Comma-separated old:new pairs"),
      renames_json: z.string().optional().describe("JSON array of {old,new} objects"),
    },
    async ({ function_identifier, mapping_json, pairs, renames_json }) => {
      const ident = function_identifier.trim();
      const params: Record<string, string> = {};
      if (ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)) {
        params.address = ident;
      } else {
        params.functionName = ident;
      }

      if (renames_json) {
        try {
          JSON.parse(renames_json);
          params.renames = renames_json;
        } catch {
          return { content: [{ type: "text", text: "Error: renames_json is not valid JSON" }] };
        }
      } else if (mapping_json) {
        try {
          JSON.parse(mapping_json);
          params.mapping = mapping_json;
        } catch {
          return { content: [{ type: "text", text: "Error: mapping_json is not valid JSON" }] };
        }
      } else if (pairs) {
        params.pairs = pairs;
      } else {
        return { content: [{ type: "text", text: "Error: provide mapping_json, renames_json, or pairs" }] };
      }

      const data = await client.getJson<{ error?: string; total?: number; renamed?: number }>("renameVariables", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      const total = (data as { total?: number }).total;
      const renamed = (data as { renamed?: number }).renamed;
      return { content: [{ type: "text", text: `Batch rename: ${renamed}/${total} applied` }] };
    }
  );

  server.tool(
    "rename_data",
    "Rename a data label at the specified address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      new_name: z.string().describe("New name for the data label"),
    },
    async ({ address, new_name }) => {
      const result = await client.post("renameData", { address, newName: new_name });
      return { content: [{ type: "text", text: result }] };
    }
  );

  // ===== Comment Tools =====

  server.tool(
    "set_comment",
    "Set a comment at a specific address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      comment: z.string().describe("Comment text"),
    },
    async ({ address, comment }) => {
      const result = await client.post("comment", { address, comment });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "get_comment",
    "Get the comment at a specific address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
    },
    async ({ address }) => {
      const lines = await client.getLines("comment", { address });
      return { content: [{ type: "text", text: lines[0] ?? "" }] };
    }
  );

  server.tool(
    "delete_comment",
    "Delete the comment at a specific address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
    },
    async ({ address }) => {
      const result = await client.post("comment", { address, _method: "DELETE" });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "set_function_comment",
    "Set a comment for a function.",
    {
      function_name: z.string().describe("Function name"),
      comment: z.string().describe("Comment text"),
    },
    async ({ function_name, comment }) => {
      const result = await client.post("comment/function", { name: function_name, comment });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "get_function_comment",
    "Get the comment for a function.",
    {
      function_name: z.string().describe("Function name"),
    },
    async ({ function_name }) => {
      const lines = await client.getLines("comment/function", { name: function_name });
      return { content: [{ type: "text", text: lines[0] || "" }] };
    }
  );

  server.tool(
    "delete_function_comment",
    "Delete the comment for a function.",
    {
      function_name: z.string().describe("Function name"),
    },
    async ({ function_name }) => {
      const result = await client.post("comment/function", { name: function_name, _method: "DELETE" });
      return { content: [{ type: "text", text: result }] };
    }
  );

  // ===== Type Tools =====

  server.tool(
    "define_types",
    "Define types from a C code string.",
    {
      c_code: z.string().describe("C code containing type definitions"),
    },
    async ({ c_code }) => {
      const data = await client.getJson<{ error?: string } | unknown[]>("defineTypes", { cCode: c_code });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if (Array.isArray(data)) {
        return { content: [{ type: "text", text: `Defined types: ${data.join(", ")}` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "list_local_types",
    "List all local types in the database (paginated).",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(200).describe("Number of results to return"),
      include_libraries: z.boolean().default(false).describe("Include library types"),
    },
    async ({ offset = 0, count = 200, include_libraries = false }) => {
      const lines = await client.getLines("localTypes", {
        offset,
        limit: count,
        includeLibraries: include_libraries ? 1 : 0,
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "search_types",
    "Search local types whose name or declaration contains the substring.",
    {
      query: z.string().describe("Search query"),
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(200).describe("Number of results to return"),
      include_libraries: z.boolean().default(false).describe("Include library types"),
    },
    async ({ query, offset = 0, count = 200, include_libraries = false }) => {
      const lines = await client.getLines("searchTypes", {
        query,
        offset,
        limit: count,
        includeLibraries: include_libraries ? 1 : 0,
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_user_defined_type",
    "Retrieve definition of a user defined type (struct, enumeration, typedef, union).",
    {
      type_name: z.string().describe("Type name"),
    },
    async ({ type_name }) => {
      const lines = await client.getLines("getUserDefinedType", { name: type_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_type_info",
    "Resolve a type name and return its declaration and details (kind, members, enum values).",
    {
      type_name: z.string().describe("Type name"),
    },
    async ({ type_name }) => {
      const data = await client.getJson<Record<string, unknown>>("getTypeInfo", { name: type_name });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${String(data.error)}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    "declare_c_type",
    "Create or update a local type from a C declaration.",
    {
      c_declaration: z.string().describe("C type declaration"),
    },
    async ({ c_declaration }) => {
      const data = await client.getJson<{ error?: string; defined_types?: Record<string, unknown>; count?: number }>("declareCType", { declaration: c_declaration });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      if ((data as { defined_types?: Record<string, unknown> }).defined_types) {
        const names = Object.keys((data as { defined_types: Record<string, unknown> }).defined_types).join(", ");
        const count = (data as { count?: number }).count || 0;
        return { content: [{ type: "text", text: `Declared types (${count}): ${names}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "retype_variable",
    "Retype a variable in a function.",
    {
      function_name: z.string().describe("Function name"),
      variable_name: z.string().describe("Variable name"),
      type_str: z.string().describe("New type for the variable"),
    },
    async ({ function_name, variable_name, type_str }) => {
      const data = await client.getJson<{ status?: string; error?: string }>("retypeVariable", {
        functionName: function_name,
        variableName: variable_name,
        type: type_str,
      });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("status" in data) {
        return { content: [{ type: "text", text: (data as { status: string }).status }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "set_local_variable_type",
    "Set a local variable's type.",
    {
      function_address: z.string().describe("Function address or name"),
      variable_name: z.string().describe("Variable name"),
      new_type: z.string().describe("New type"),
    },
    async ({ function_address, variable_name, new_type }) => {
      const data = await client.getJson<{ status?: string; error?: string }>("setLocalVariableType", {
        functionAddress: function_address,
        variableName: variable_name,
        newType: new_type,
      });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ((data as { status?: string }).status === "ok") {
        const d = data as { variable?: string; function?: string; applied_type?: string };
        return { content: [{ type: "text", text: `Retyped ${d.variable} in ${d.function} to ${d.applied_type}` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // ===== Data Tools =====

  server.tool(
    "list_data_items",
    "List defined data labels and their values with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("data", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "hexdump_address",
    "Hexdump data starting at an address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      length: z.number().default(-1).describe("Number of bytes (use -1 for defined size)"),
    },
    async ({ address, length = -1 }) => {
      const params: Record<string, string | number> = { address };
      if (length !== undefined && length !== -1) {
        params.length = length;
      }
      const text = await client.getText("hexdump", params);
      return { content: [{ type: "text", text }] };
    }
  );

  server.tool(
    "hexdump_data",
    "Hexdump a data symbol by name or address.",
    {
      name_or_address: z.string().describe("Symbol name or address (hex)"),
      length: z.number().default(-1).describe("Number of bytes (use -1 for defined size)"),
    },
    async ({ name_or_address, length = -1 }) => {
      const ident = name_or_address.trim();
      if (ident.startsWith("0x")) {
        const params: Record<string, string | number> = { address: ident };
        if (length !== undefined && length !== -1) {
          params.length = length;
        }
        const text = await client.getText("hexdump", params);
        return { content: [{ type: "text", text }] };
      }
      const params: Record<string, string | number> = { name: ident };
      if (length !== undefined && length !== -1) {
        params.length = length;
      }
      const text = await client.getText("hexdumpByName", params);
      return { content: [{ type: "text", text }] };
    }
  );

  server.tool(
    "get_data_decl",
    "Return a declaration-like string and hexdump for a data symbol.",
    {
      name_or_address: z.string().describe("Symbol name or address (hex)"),
      length: z.number().default(-1).describe("Number of bytes"),
    },
    async ({ name_or_address, length = -1 }) => {
      const ident = name_or_address.trim();
      const params: Record<string, string | number> = ident.startsWith("0x")
        ? { address: ident }
        : { name: ident };
      if (length !== undefined && length !== -1) {
        params.length = length;
      }
      const data = await client.getJson<{
        error?: string;
        decl?: string;
        hexdump?: string;
        address?: string;
        name?: string;
      }>("getDataDecl", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      const decl = (data as { decl?: string }).decl || "(no declaration)";
      const hexdump = (data as { hexdump?: string }).hexdump || "";
      const addr = (data as { address?: string }).address || "";
      const name = (data as { name?: string }).name || ident;
      return {
        content: [{ type: "text", text: `Declaration (${addr} ${name}):\n${decl}\n\nHexdump:\n${hexdump}` }],
      };
    }
  );

  // ===== Cross-Reference Tools =====

  server.tool(
    "get_xrefs_to",
    "Get all cross references (code and data) to the given address.",
    {
      address: z.string().describe("Address (hex or decimal)"),
    },
    async ({ address }) => {
      const lines = await client.getLines("getXrefsTo", { address });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_field",
    "Get all cross references to a named struct field (member).",
    {
      struct_name: z.string().describe("Struct name"),
      field_name: z.string().describe("Field name"),
    },
    async ({ struct_name, field_name }) => {
      const lines = await client.getLines("getXrefsToField", { struct: struct_name, field: field_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_struct",
    "Get cross references/usages related to a struct name.",
    {
      struct_name: z.string().describe("Struct name"),
    },
    async ({ struct_name }) => {
      const lines = await client.getLines("getXrefsToStruct", { name: struct_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_type",
    "Get xrefs/usages related to a struct or type name.",
    {
      type_name: z.string().describe("Type name"),
    },
    async ({ type_name }) => {
      const lines = await client.getLines("getXrefsToType", { name: type_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_enum",
    "Get usages/xrefs of an enum by scanning for member values and matches.",
    {
      enum_name: z.string().describe("Enum name"),
    },
    async ({ enum_name }) => {
      const lines = await client.getLines("getXrefsToEnum", { name: enum_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_union",
    "Get cross references/usages related to a union type by name.",
    {
      union_name: z.string().describe("Union name"),
    },
    async ({ union_name }) => {
      const lines = await client.getLines("getXrefsToUnion", { name: union_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  // ===== Utility Tools =====

  server.tool(
    "function_at",
    "Retrieve the name of the function the address belongs to.",
    {
      address: z.string().describe("Address (hex format 0x00001)"),
    },
    async ({ address }) => {
      const lines = await client.getLines("functionAt", { address });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_stack_frame_vars",
    "Get stack frame variable information for a function (names, offsets, sizes, types).",
    {
      function_identifier: z.string().describe("Function name or address (hex)"),
    },
    async ({ function_identifier }) => {
      const ident = function_identifier.trim();
      const params: Record<string, string> = ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)
        ? { address: ident }
        : { name: ident };
      const data = await client.getJson<{ error?: string; stack_frame_vars?: string[] }>("getStackFrameVars", params);
      if (!data) {
        return { content: [{ type: "text", text: "" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: "" }] };
      }
      const vars = (data as { stack_frame_vars?: string[] }).stack_frame_vars;
      return { content: [{ type: "text", text: (vars || []).join("\n") }] };
    }
  );

  server.tool(
    "list_classes",
    "List all namespace/class names in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("classes", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_namespaces",
    "List all non-global namespaces in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("namespaces", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_segments",
    "List all memory segments in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("segments", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_sections",
    "List sections in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const data = await client.getJson<{ error?: string; sections?: Array<Record<string, unknown>> }>("sections", { offset, limit });
      if (!data || "error" in data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      const filename = await getActiveFilename();
      const sections = (data as { sections?: Array<Record<string, unknown>> }).sections || [];
      const lines = [`File: ${filename}`];
      for (const s of sections) {
        const start = (s as { start?: string }).start || "";
        const end = (s as { end?: string }).end || "";
        const size = (s as { size?: number }).size;
        const name = (s as { name?: string }).name || "(unnamed)";
        const sem = ((s as { semantics?: string }).semantics || (s as { type?: string }).type) || "";
        const tail = sem ? `\t${sem}` : "";
        lines.push(`${start}-${end}\t${size}\t${name}${tail}`);
      }
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_imports",
    "List imported symbols in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("imports", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_exports",
    "List exported functions/symbols with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("exports", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_strings",
    "List all strings in the database (paginated).",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, count = 100 }) => {
      const lines = await client.getLines("strings", { offset, limit: count });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_strings_filter",
    "List matching strings in the database (paginated, filtered).",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(100).describe("Number of results to return"),
      filter: z.string().optional().describe("Filter string"),
    },
    async ({ offset = 0, count = 100, filter = "" }) => {
      const lines = await client.getLines("strings/filter", { offset, limit: count, filter });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_all_strings",
    "List all strings in the database (aggregated across pages).",
    {
      batch_size: z.number().default(500).describe("Batch size for aggregation"),
    },
    async ({ batch_size = 500 }) => {
      const results: string[] = [];
      let offset = 0;
      while (true) {
        const data = await client.getJson<Record<string, unknown>>("strings", { offset, limit: batch_size });
        if (!data || !("strings" in data)) {
          break;
        }
        const stringsData = data.strings as Array<{ address?: string; length?: number; type?: string; value?: string }>;
        const items = Array.isArray(stringsData) ? stringsData : [];
        if (!items.length) {
          break;
        }
        for (const s of items) {
          const addr = s.address || "";
          const length = s.length;
          const stype = s.type || "";
          const value = s.value || "";
          results.push(`${addr}\t${length}\t${stype}\t${value}`);
        }
        if (items.length < batch_size) {
          break;
        }
        offset += batch_size;
      }
      return { content: [{ type: "text", text: results.join("\n") }] };
    }
  );

  server.tool(
    "get_binary_status",
    "Get the current status of the loaded binary.",
    {},
    async () => {
      const lines = await client.getLines("status");
      return { content: [{ type: "text", text: lines[0] || "" }] };
    }
  );

  server.tool(
    "list_binaries",
    "List managed/open binaries known to the server with ids and active flag.",
    {},
    async () => {
      const data = await client.getJson<{ error?: string; binaries?: Array<Record<string, unknown>> }>("binaries");
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: (data as { error: string }).error }] };
      }
      const binaries = (data as { binaries?: Array<Record<string, unknown>> }).binaries || [];
      const lines = binaries.map((it) => {
        const vid = (it as { id?: number }).id;
        const view_id = (it as { view_id?: number }).view_id;
        const fn = (it as { filename?: string }).filename;
        const basename = (it as { basename?: string }).basename || "";
        const selectors = (it as { selectors?: number[] }).selectors || [];
        const active = (it as { active?: boolean }).active;
        const label = basename || fn || "(unknown)";
        const full = fn || "(no filename)";
        const selectorText = selectors.map(String).join(", ");
        const mark = active ? " *active*" : "";
        const viewPart = view_id ? ` view=${view_id}` : "";
        return `${vid}. ${label}${viewPart}${mark}\n    path: ${full}\n    selectors: ${selectorText}`;
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "select_binary",
    "Select which binary to analyze by ordinal, internal view id, full path, or basename.",
    {
      view: z.string().describe("Ordinal, view id, full path, or basename"),
    },
    async ({ view }) => {
      const data = await client.getJson<{ error?: string; selected?: Record<string, unknown> }>("selectBinary", { view });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }
      const sel = (data as { selected?: Record<string, unknown> }).selected;
      if (sel) {
        const ordinal = (sel as { id?: number }).id || "?";
        const view_id = (sel as { view_id?: number }).view_id;
        const fn = (sel as { filename?: string }).filename || "";
        const basename = (sel as { basename?: string }).basename || "";
        const selectors = (sel as { selectors?: number[] }).selectors || [];
        const selectorText = selectors.map(String).join(", ");
        const displayName = basename || fn || "(unknown)";
        const viewPart = view_id ? ` (view ${view_id})` : "";
        const pathPart = fn ? `\nFull path: ${fn}` : "";
        return { content: [{ type: "text", text: `Selected ${ordinal}: ${displayName}${viewPart}${pathPart}\nSelectors: ${selectorText}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // ===== Binary Modification Tools =====

  server.tool(
    "set_function_prototype",
    "Set a function's prototype by name or address.",
    {
      name_or_address: z.string().describe("Function name or address"),
      prototype: z.string().describe("New function prototype"),
    },
    async ({ name_or_address, prototype }) => {
      const ident = name_or_address.trim();
      const params: Record<string, string> = { prototype };
      if (ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)) {
        params.address = ident;
      } else {
        params.name = ident;
      }
      const data = await client.getJson<{ status?: string; error?: string; address?: string; applied_type?: string }>("setFunctionPrototype", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("status" in data) {
        return { content: [{ type: "text", text: `Applied prototype at ${(data as { address?: string }).address}: ${(data as { applied_type?: string }).applied_type}` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "make_function_at",
    "Create a function at the given address.",
    {
      address: z.string().describe("Address (hex like 0x401000 or decimal)"),
      platform: z.string().optional().describe("Platform (e.g., linux-x86_64)"),
    },
    async ({ address, platform }) => {
      const params: Record<string, string> = { address };
      if (platform) {
        params.platform = platform;
      }
      const data = await client.getJson<{ error?: string; status?: string; address?: string; name?: string }>("makeFunctionAt", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }
      if ((data as { status?: string }).status === "exists") {
        return { content: [{ type: "text", text: `Function already exists at ${(data as { address?: string }).address}: ${(data as { name?: string }).name}` }] };
      }
      if ((data as { status?: string }).status === "ok") {
        return { content: [{ type: "text", text: `Created function at ${(data as { address?: string }).address}: ${(data as { name?: string }).name}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "list_platforms",
    "List all available platform names from Binary Ninja.",
    {},
    async () => {
      const data = await client.getJson<{ error?: string; platforms?: string[] }>("platforms");
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }
      const plats = (data as { platforms?: string[] }).platforms;
      if (!plats) {
        return { content: [{ type: "text", text: "(no platforms)" }] };
      }
      return { content: [{ type: "text", text: plats.join("\n") }] };
    }
  );

  server.tool(
    "patch_bytes",
    "Patch bytes at a given address in the binary.",
    {
      address: z.string().describe("Address (hex like 0x401000 or decimal)"),
      data: z.string().describe("Hex string of bytes to write (e.g., '90 90' or '9090')"),
      save_to_file: z.boolean().default(true).describe("Save patched binary to disk"),
    },
    async ({ address, data, save_to_file = true }) => {
      const result = await client.getJson<{
        error?: string;
        status?: string;
        original_bytes?: string;
        patched_bytes?: string;
        bytes_written?: number;
        bytes_requested?: number;
        saved_to_file?: boolean;
        saved_path?: string;
        warning?: string;
      }>("patch", { address, data, save_to_file: save_to_file ? 1 : 0 });
      if (!result) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in result) {
        return { content: [{ type: "text", text: `Error: ${(result as { error: string }).error}` }] };
      }
      const status = (result as { status?: string }).status;
      if (status === "ok" || status === "partial") {
        const orig = (result as { original_bytes?: string }).original_bytes || "";
        const patched = (result as { patched_bytes?: string }).patched_bytes || "";
        const written = (result as { bytes_written?: number }).bytes_written || 0;
        const requested = (result as { bytes_requested?: number }).bytes_requested || 0;
        const saved = (result as { saved_to_file?: boolean }).saved_to_file || false;
        const savedPath = (result as { saved_path?: string }).saved_path || "";
        const warning = (result as { warning?: string }).warning || "";

        let msg = `Patched ${written}/${requested} bytes at ${address}`;
        if (status === "partial") {
          msg += " (PARTIAL WRITE)";
        }
        if (warning) {
          msg += `\nWarning: ${warning}`;
        }
        if (orig) {
          msg += `\nOriginal: ${orig}`;
        }
        if (patched) {
          msg += `\nPatched:  ${patched}`;
        }
        if (saved) {
          msg += `\nSaved to file: ${savedPath}`;
        }
        return { content: [{ type: "text", text: msg }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "format_value",
    "Convert and annotate a value at an address in Binary Ninja.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      text: z.string().describe("Text to convert"),
      size: z.number().default(0).describe("Size in bytes"),
    },
    async ({ address, text, size = 0 }) => {
      const lines = await client.getLines("formatValue", { address, text, size });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "convert_number",
    "Convert a number or string to multiple representations (hex/dec/bin, C literals).",
    {
      text: z.string().describe("Number or string to convert (decimal, hex 0x7b, binary 0b1111011, char 'A', or string)"),
      size: z.number().default(0).describe("Size in bytes (0 for auto)"),
    },
    async ({ text, size = 0 }) => {
      const data = await client.getJson<Record<string, unknown>>("convertNumber", { text, size });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${String(data.error)}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // ---------- Debugging ----------

  // Client HTTP timeout (ms) that outlives the server-side pause timeout, or
  // 0 (no timeout) for an unbounded run.
  const httpTimeoutMs = (runTimeout: number): number => (runTimeout <= 0 ? 0 : (runTimeout + 20) * 1000);
  const runParams = (timeoutSeconds: number, context: boolean, extra: Record<string, string | number> = {}): Record<string, string | number> => ({
    timeout: timeoutSeconds,
    ...(context ? {} : { context: "0" }),
    ...extra,
  });
  const jsonText = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] });

  server.tool(
    "debug_set_breakpoint",
    "Set a breakpoint in the current binary. The location is a symbol/function name (e.g. 'checkResponse', 'main') OR an address (hex like 0x401000 or decimal) — names are resolved against the analysis. Optional condition only stops when true; it supports registers, arithmetic, comparisons, and memory dereference (e.g. \"rdi == 0x10\" or \"u32([rdi]) == 0x1234\") — see debug_evaluate for the full syntax. Returns the breakpoint with its id, resolved address, and symbol.",
    {
      location: z.string().describe("Symbol/function name, or address (hex 0x401000 or decimal)"),
      condition: z.string().default("").describe("Optional condition expression over registers/memory"),
    },
    async ({ location, condition = "" }) => {
      const body: Record<string, unknown> = { location };
      if (condition) body.condition = condition;
      return { content: [{ type: "text", text: await client.post("debug/breakpoint", body) }] };
    }
  );

  server.tool(
    "debug_list_breakpoints",
    "List all breakpoints currently set in the debugger.",
    {},
    async () => jsonText(await client.getJson("debug/breakpoint"))
  );

  server.tool(
    "debug_delete_breakpoint",
    "Delete a breakpoint by its id (see debug_list_breakpoints).",
    {
      id: z.number().describe("Breakpoint id to delete"),
    },
    async ({ id }) => {
      return { content: [{ type: "text", text: await client.post("debug/breakpoint", { id, _method: "DELETE" }) }] };
    }
  );

  server.tool(
    "debug_enable_breakpoint",
    "Enable a previously disabled breakpoint by its id.",
    {
      id: z.number().describe("Breakpoint id to enable"),
    },
    async ({ id }) => jsonText(await client.getJson("debug/breakpoint/enable", { id }))
  );

  server.tool(
    "debug_disable_breakpoint",
    "Disable a breakpoint by its id without deleting it. It stays in the list but execution will not stop there until re-enabled.",
    {
      id: z.number().describe("Breakpoint id to disable"),
    },
    async ({ id }) => jsonText(await client.getJson("debug/breakpoint/disable", { id }))
  );

  server.tool(
    "debug_set_watchpoint",
    "Set a hardware watchpoint that stops execution when memory is accessed. When the watched memory is accessed, run/continue stops with status 'watchpoint' naming this watchpoint. Hardware watchpoints are a limited resource (typically 4); exceeding the limit returns a clear error. Requires a live target.",
    {
      address: z.string().describe("Address to watch, hex like 0x4034d0 or decimal"),
      size: z.number().default(8).describe("Bytes to watch: 1, 2, 4, or 8"),
      type: z.enum(["write", "read", "readwrite"]).default("write").describe("Access type to trap"),
    },
    async ({ address, size = 8, type = "write" }) => ({
      content: [{ type: "text", text: await client.post("debug/watchpoint", { address, size, type }) }],
    })
  );

  server.tool(
    "debug_list_watchpoints",
    "List all hardware watchpoints (id, address, size, type, enabled).",
    {},
    async () => jsonText(await client.getJson("debug/watchpoint"))
  );

  server.tool(
    "debug_delete_watchpoint",
    "Delete a watchpoint by its id (see debug_list_watchpoints).",
    {
      id: z.number().describe("Watchpoint id to delete"),
    },
    async ({ id }) => ({
      content: [{ type: "text", text: await client.post("debug/watchpoint", { id, _method: "DELETE" }) }],
    })
  );

  server.tool(
    "debug_enable_watchpoint",
    "Enable a previously disabled watchpoint by its id.",
    {
      id: z.number().describe("Watchpoint id to enable"),
    },
    async ({ id }) => jsonText(await client.getJson("debug/watchpoint/enable", { id }))
  );

  server.tool(
    "debug_disable_watchpoint",
    "Disable a watchpoint by its id without deleting it (won't fire until re-enabled).",
    {
      id: z.number().describe("Watchpoint id to disable"),
    },
    async ({ id }) => jsonText(await client.getJson("debug/watchpoint/disable", { id }))
  );

  server.tool(
    "debug_run",
    "Launch the target under the debugger and run until it stops (BLOCKING). Runs to the first breakpoint by default; stop_at_entry halts at the entry point. If not stopped within timeout_seconds the target is auto-paused and returned with its location (status \"paused\"). Use timeout_seconds=0 to wait indefinitely.",
    {
      stop_at_entry: z.boolean().default(false).describe("Halt at the program entry point instead of the first breakpoint"),
      timeout_seconds: z.number().default(30).describe("Auto-pause after this many seconds (0 = wait indefinitely)"),
      context: z.boolean().default(true).describe("Attach the full context (thread/registers/stack/disasm/backtrace) to the stop result"),
      cmd_line: z.string().default("").describe("Command-line arguments for the target"),
      working_directory: z.string().default("").describe("Working directory to launch in"),
    },
    async ({ stop_at_entry = false, timeout_seconds = 30, context = true, cmd_line = "", working_directory = "" }) => {
      const params: Record<string, string | number> = { timeout: timeout_seconds };
      if (stop_at_entry) params.stop_at_entry = "1";
      if (!context) params.context = "0";
      if (cmd_line) params.cmd_line = cmd_line;
      if (working_directory) params.working_directory = working_directory;
      return jsonText(await client.getJson("debug/run", params, httpTimeoutMs(timeout_seconds)));
    }
  );

  server.tool(
    "debug_continue",
    "Continue a stopped target until it next stops (BLOCKING). Same stop-result and timeout_seconds semantics as debug_run.",
    {
      timeout_seconds: z.number().default(30).describe("Auto-pause after this many seconds (0 = wait indefinitely)"),
      context: z.boolean().default(true).describe("Attach the full context to the stop result"),
    },
    async ({ timeout_seconds = 30, context = true }) => {
      return jsonText(await client.getJson("debug/continue", runParams(timeout_seconds, context), httpTimeoutMs(timeout_seconds)));
    }
  );

  server.tool(
    "debug_pause",
    "Break into a running target (e.g. hung or looping) so it can be inspected. The in-flight debug_run/debug_continue returns with the stop location.",
    {},
    async () => jsonText(await client.getJson("debug/pause"))
  );

  server.tool(
    "debug_status",
    "Get debugger session status: the active backend adapter (LLDB/WinDbg — the command dialect for debug_backend_command), whether a target is live and running or halted, the current ip/function when halted, and how many breakpoints are set. Call this to learn the adapter dialect before using debug_backend_command. Works even before a target is launched.",
    {},
    async () => jsonText(await client.getJson("debug/status"))
  );

  server.tool(
    "debug_backend_command",
    "Run a raw command in the underlying debug adapter's console (LLDB/WinDbg) — an escape hatch for capabilities not yet wrapped as structured tools (e.g. hardware breakpoints/watchpoints via LLDB 'watchpoint set'/WinDbg 'ba', memory maps via 'memory region'). Returns the adapter's output plus which adapter is active. Call debug_status first if you don't know the active adapter (dialect). Requires a live target. Prefer structured debug_* tools for execution control.",
    {
      command: z.string().describe("Raw adapter command, e.g. LLDB 'memory region 0x401000' or WinDbg 'ba w4 0x401000'"),
    },
    async ({ command }) => ({
      content: [{ type: "text", text: await client.post("debug/backend", { command }) }],
    })
  );

  server.tool(
    "debug_list_modules",
    "List the images loaded in the running target (the executable and every shared library), each with its runtime load base and size. Requires a live target.",
    {},
    async () => jsonText(await client.getJson("debug/modules"))
  );

  server.tool(
    "debug_resolve_address",
    "Resolve a runtime address to its memory mapping and backing image. Finds the region (page mapping) containing the address and, when it is backed by a loaded image, reports the image's load base and the offset within the image such that image_base + image_offset == address. Returns mmap_base, mmap_end, permissions, region_label ([stack]/[heap]/[vdso]), image_name, image_base, image_offset. Purely descriptive — no static translation. Requires a live target.",
    {
      address: z.string().describe("Runtime address, hex like 0x7ffff7c28000 or decimal"),
    },
    async ({ address }) => jsonText(await client.getJson("debug/resolve", { address }))
  );

  server.tool(
    "debug_step",
    "Execute a single instruction, stepping INTO calls (BLOCKING). Returns where execution landed (same stop-result shape as debug_run). Requires a stopped target.",
    {
      timeout_seconds: z.number().default(30).describe("Auto-pause after this many seconds (0 = wait indefinitely)"),
      context: z.boolean().default(true).describe("Attach the full context to the stop result"),
    },
    async ({ timeout_seconds = 30, context = true }) =>
      jsonText(await client.getJson("debug/step", runParams(timeout_seconds, context), httpTimeoutMs(timeout_seconds)))
  );

  server.tool(
    "debug_step_over",
    "Execute a single instruction, stepping OVER calls (BLOCKING). A call runs to completion before stopping. Requires a stopped target.",
    {
      timeout_seconds: z.number().default(30).describe("Auto-pause after this many seconds (0 = wait indefinitely)"),
      context: z.boolean().default(true).describe("Attach the full context to the stop result"),
    },
    async ({ timeout_seconds = 30, context = true }) =>
      jsonText(await client.getJson("debug/stepover", runParams(timeout_seconds, context), httpTimeoutMs(timeout_seconds)))
  );

  server.tool(
    "debug_step_out",
    "Run until the current function returns to its caller, i.e. \"finish\" (BLOCKING). Requires a stopped target.",
    {
      timeout_seconds: z.number().default(30).describe("Auto-pause after this many seconds (0 = wait indefinitely)"),
      context: z.boolean().default(true).describe("Attach the full context to the stop result"),
    },
    async ({ timeout_seconds = 30, context = true }) =>
      jsonText(await client.getJson("debug/stepout", runParams(timeout_seconds, context), httpTimeoutMs(timeout_seconds)))
  );

  server.tool(
    "debug_run_to",
    "Resume until the target reaches a given address, i.e. \"advance\"/\"until\" (BLOCKING). Requires a live target.",
    {
      address: z.string().describe("Address, hex like 0x401000 or decimal"),
      timeout_seconds: z.number().default(30).describe("Auto-pause after this many seconds (0 = wait indefinitely)"),
      context: z.boolean().default(true).describe("Attach the full context to the stop result"),
    },
    async ({ address, timeout_seconds = 30, context = true }) =>
      jsonText(await client.getJson("debug/runto", runParams(timeout_seconds, context, { address }), httpTimeoutMs(timeout_seconds)))
  );

  server.tool(
    "debug_get_registers",
    "Read register values of the halted target, with pointer hints. Returns the important registers (general-purpose + pc/sp/flags) by default; pass full=true for the complete register file (sub-registers, segment, FPU/vector). Requires the target to be stopped.",
    {
      full: z.boolean().default(false).describe("Return the complete register file instead of just the important registers"),
    },
    async ({ full = false }) =>
      jsonText(await client.getJson("debug/registers", full ? { full: "1" } : {}))
  );

  server.tool(
    "debug_get_backtrace",
    "Get the call stack (backtrace) of a halted thread. Pass tid to backtrace a specific thread; 0 (default) uses the active thread. Requires the target to be stopped.",
    {
      tid: z.number().default(0).describe("Thread id to backtrace; 0 = active thread"),
    },
    async ({ tid = 0 }) => jsonText(await client.getJson("debug/backtrace", tid ? { tid } : {}))
  );

  server.tool(
    "debug_list_threads",
    "List the target's threads (tid, current rip, function, and which is active). Requires the target to be stopped.",
    {},
    async () => jsonText(await client.getJson("debug/threads"))
  );

  server.tool(
    "debug_select_thread",
    "Make a thread active by its tid. Subsequent inspection (registers, backtrace, context) targets the selected thread. Requires the target to be stopped.",
    {
      tid: z.number().describe("Thread id to make active"),
    },
    async ({ tid }) => jsonText(await client.getJson("debug/thread/select", { tid }))
  );

  server.tool(
    "debug_select_frame",
    "Select a stack frame by index (0 = innermost) as the inspection context. Returns that frame's context (pc, function, registers, stack, disassembly, backtrace). The selection PERSISTS: subsequent debug_context / debug_get_registers / debug_get_backtrace reflect it until changed or the target runs again. For a caller frame, pc/sp/fp are reliably unwound but a full register set is not available (only recoverable registers are shown). Requires the target to be stopped.",
    {
      frame: z.number().describe("Stack frame index; 0 = innermost"),
    },
    async ({ frame }) => jsonText(await client.getJson("debug/frame/select", { frame }))
  );

  server.tool(
    "debug_frame_up",
    "Move one stack frame toward the caller (older frame) and show its context. Like gdb's 'up'. Requires the target to be stopped.",
    {},
    async () => jsonText(await client.getJson("debug/frame/up"))
  );

  server.tool(
    "debug_frame_down",
    "Move one stack frame toward the callee (newer frame) and show its context. Like gdb's 'down'. Requires the target to be stopped.",
    {},
    async () => jsonText(await client.getJson("debug/frame/down"))
  );

  server.tool(
    "debug_context",
    "Get the full pwndbg-style context of the halted target in one call: active thread (tid+rip), important registers, a stack telescope (stack words with strings they point to), disassembly around the current PC, and the backtrace. This is what run/continue/step attach to their stop result by default (pass context=false there to omit and call this on demand). Requires a stopped target.",
    {},
    async () => jsonText(await client.getJson("debug/context"))
  );

  server.tool(
    "debug_read_memory",
    "Read memory from the halted target and return it as a hexdump. Errors clearly if the memory is not readable or unmapped. Requires the target to be stopped.",
    {
      address: z.string().describe("Address, hex like 0x401000 or decimal"),
      size: z.number().default(64).describe("Number of bytes to read"),
    },
    async ({ address, size = 64 }) => jsonText(await client.getJson("debug/memory", { address, size }))
  );

  server.tool(
    "debug_evaluate",
    "Evaluate an expression over the halted target's registers and memory. Safe, small language (no code execution): registers (rax, rsp, ...), int/hex literals, arithmetic (+ - * / % & | ^ << >> - ~), comparison/boolean (== != < <= > >=, and/or/not), and memory dereference: [expr] reads 8 bytes at expr, deref(expr) same, u8/u16/u32/u64(expr) and signed i8..i64(expr) read that many bytes. Examples: 'rax + 8', '[rsp]', 'u32([rdi]) == 0x1234', '[[rbp]]'. Returns hex + decimal; annotates a pointer that points at a string or known function. Requires the target to be stopped.",
    {
      expression: z.string().describe("Expression, e.g. '[rsp]' or 'rax + 8'"),
    },
    async ({ expression }) => ({
      content: [{ type: "text", text: await client.post("debug/evaluate", { expression }) }],
    })
  );

  server.tool(
    "debug_set_register",
    "Set a register's value in the halted target. The write is verified by reading it back; returns old and new values. Requires the target to be stopped.",
    {
      name: z.string().describe("Register name, e.g. rax, rip"),
      value: z.string().describe("Value, hex like 0x10 or decimal"),
    },
    async ({ name, value }) => ({
      content: [{ type: "text", text: await client.post("debug/setRegister", { name, value }) }],
    })
  );

  server.tool(
    "debug_write_memory",
    "Write bytes to the halted target's LIVE process memory (distinct from patch_bytes, which edits the static BinaryView). The region's permissions are checked first, so writing to non-writable or unmapped memory returns a clear error; the write is verified by reading it back. Requires the target to be stopped.",
    {
      address: z.string().describe("Address, hex like 0x401000 or decimal"),
      data: z.string().describe("Hex bytes, e.g. '90 90' or '9090'"),
    },
    async ({ address, data }) => ({
      content: [{ type: "text", text: await client.post("debug/writeMemory", { address, data }) }],
    })
  );

  server.tool(
    "debug_quit",
    "Terminate the running target under the debugger.",
    {},
    async () => jsonText(await client.getJson("debug/quit"))
  );
}
