# Binary Ninja MCP Server (TypeScript)

This is the TypeScript implementation of the Binary Ninja MCP bridge server. It provides a standalone MCP server that connects to a running Binary Ninja instance and exposes its capabilities through the Model Context Protocol.

## Features

- **Standalone MCP Server**: Run independently with any MCP client
- **60+ Tools**: Full access to Binary Ninja's reverse engineering and debugging capabilities
- **Easy Configuration**: CLI options and environment variables for host/port
- **TypeScript**: Full type safety and better developer experience

## Installation

### Using npx (Recommended)

```bash
npx -y binary-ninja-mcp
```

### Global Installation

```bash
npm install -g binary-ninja-mcp
binary-ninja-mcp
```

### From Source

```bash
cd bridge
npm install
npm run build
```

## Usage

### Command Line Options

```bash
# Connect to default (localhost:9009)
npx -y binary-ninja-mcp

# Connect to custom host/port
npx -y binary-ninja-mcp --host 192.168.1.100 --port 9009

# Show help
npx -y binary-ninja-mcp --help
```

### Environment Variables

```bash
# Set host and port via environment
BINJA_MCP_HOST=localhost BINJA_MCP_PORT=9009 npx -y binary-ninja-mcp
```

### MCP Client Configuration

#### Claude Desktop

Add to `~/.config/claude-desktop/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "binary-ninja-mcp": {
      "command": "npx",
      "args": ["-y", "binary-ninja-mcp", "--host", "localhost", "--port", "9009"]
    }
  }
}
```

#### Cline

Add to your Cline MCP configuration:

```json
{
  "mcpServers": {
    "binary-ninja-mcp": {
      "command": "npx",
      "args": ["-y", "binary-ninja-mcp"]
    }
  }
}
```

#### Custom Installation

If installed globally:

```json
{
  "mcpServers": {
    "binary-ninja-mcp": {
      "command": "binary-ninja-mcp",
      "args": ["--host", "localhost", "--port", "9009"]
    }
  }
}
```

## Available Tools

### Function Analysis

- `list_methods` - List all function names with pagination
- `get_entry_points` - List entry point(s) of the loaded binary
- `search_functions_by_name` - Search functions by name substring
- `decompile_function` - Decompile a function to C code
- `get_il` - Get IL (HLIL/MLIL/LLIL) for a function
- `fetch_disassembly` - Get assembly mnemonics for a function

### Rename Tools

- `rename_function` - Rename a function
- `rename_single_variable` - Rename a single variable
- `rename_multi_variables` - Batch rename multiple variables
- `rename_data` - Rename a data label

### Comment Tools

- `set_comment` - Set comment at an address
- `get_comment` - Get comment at an address
- `delete_comment` - Delete comment at an address
- `set_function_comment` - Set function comment
- `get_function_comment` - Get function comment
- `delete_function_comment` - Delete function comment

### Type Tools

- `define_types` - Define types from C code
- `list_local_types` - List local types
- `search_types` - Search types by name
- `get_user_defined_type` - Get user defined type definition
- `get_type_info` - Get type information
- `declare_c_type` - Declare C type
- `retype_variable` - Retype a variable
- `set_local_variable_type` - Set local variable type

### Data Tools

- `list_data_items` - List data labels
- `hexdump_address` - Hexdump at address
- `hexdump_data` - Hexdump data symbol
- `get_data_decl` - Get data declaration and hexdump

### Cross-Reference Tools

- `get_xrefs_to` - Get xrefs to address
- `get_xrefs_to_field` - Get xrefs to struct field
- `get_xrefs_to_struct` - Get xrefs to struct
- `get_xrefs_to_type` - Get xrefs to type
- `get_xrefs_to_enum` - Get xrefs to enum
- `get_xrefs_to_union` - Get xrefs to union

### Binary Modification Tools

- `set_function_prototype` - Set function prototype
- `make_function_at` - Create function at address
- `list_platforms` - List available platforms
- `patch_bytes` - Patch bytes in binary

### Debugging Tools

Interactive debugging: set breakpoints, run the target, and inspect its state
when it stops. `debug_run`/`debug_continue` block until the target next stops
(breakpoint, exit, crash, or timeout) and return a stop result describing what
happened; unexpected stops (crash/signal/timeout) attach registers + backtrace
automatically.

- `debug_set_breakpoint` - Set a breakpoint by symbol/function name or address, with an optional condition (e.g. `rdi == 0x10`)
- `debug_list_breakpoints` - List breakpoints
- `debug_delete_breakpoint` - Delete a breakpoint by id
- `debug_enable_breakpoint` / `debug_disable_breakpoint` - Enable/disable a breakpoint by id without deleting it
- `debug_set_watchpoint` - Set a hardware watchpoint (write/read/readwrite); a hit stops with status `watchpoint`
- `debug_list_watchpoints` / `debug_delete_watchpoint` - List / delete watchpoints
- `debug_enable_watchpoint` / `debug_disable_watchpoint` - Enable/disable a watchpoint by id
- `debug_run` - Launch and run until the next stop (blocking); `stop_at_entry` optional
- `debug_continue` - Continue until the next stop (blocking)
- `debug_step` - Single-instruction step into calls (blocking)
- `debug_step_over` - Single-instruction step over calls (blocking)
- `debug_step_out` - Run until the current function returns ("finish"; blocking)
- `debug_run_to` - Resume until a given address ("advance"/"until"; blocking)
- `debug_pause` - Break into a running (hung/looping) target
- `debug_context` - Full pwndbg-style context (thread, registers, stack telescope, disasm-at-PC, backtrace); auto-attached to stops
- `debug_status` - Session status: active adapter (dialect), live/running, current ip/function, breakpoint count
- `debug_backend_command` - Escape hatch: run a raw LLDB/WinDbg adapter command (e.g. watchpoints, memory maps)
- `debug_list_modules` - List loaded images (executable + shared libraries) with runtime bases
- `debug_resolve_address` - Resolve a runtime address to its mapping and backing image (mmap_base, image_base, image_name, image_offset)
- `debug_get_registers` - Read registers of the halted target
- `debug_get_backtrace` - Get the call stack of the halted target
- `debug_read_memory` - Read memory from the halted target as a hexdump (errors on non-readable/unmapped)
- `debug_set_register` - Set a register in the halted target (verified by readback)
- `debug_write_memory` - Write bytes to the halted target's live process memory (non-writable/unmapped regions error)
- `debug_quit` - Terminate the running target

### Utility Tools

- `function_at` - Find function at address
- `get_stack_frame_vars` - Get stack frame variables
- `list_classes` - List classes/namespaces
- `list_namespaces` - List namespaces
- `list_segments` - List memory segments
- `list_sections` - List sections
- `list_imports` - List imports
- `list_exports` - List exports
- `list_strings` - List strings
- `list_all_strings` - List all strings (aggregated)
- `get_binary_status` - Get binary status
- `list_binaries` - List open binaries
- `select_binary` - Select active binary
- `format_value` - Format and annotate value
- `convert_number` - Convert number representations

## Requirements

- Node.js 18.0.0 or higher
- A running Binary Ninja instance with the MCP plugin
- MCP client (Claude Desktop, Cline, etc.)

## License

GPL-3.0 - See LICENSE file for details.
