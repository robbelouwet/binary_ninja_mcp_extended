# Binary Ninja MCP

This repository contains a Binary Ninja plugin, MCP server, and bridge that enables seamless integration of Binary Ninja's capabilities with your favorite LLM client.

![Binary Ninja MCP Logo](images/logo-small.png)

## Features

- Seamless, real-time integration between Binary Ninja and MCP clients
- Enhanced reverse engineering workflow with AI assistance
- Support for every MCP client (Cline, Claude desktop, Roo Code, etc.)
- Open multiple binaries and switch the active target automatically

## Examples

### Solving a CTF Challenge

Check out [this demo video on YouTube](https://www.youtube.com/watch?v=0ffMHH39L_M) that uses the extension to solve a CTF challenge.

## Components

This repository contains two separate components:

1. A Binary Ninja plugin that provides an MCP server that exposes Binary Ninja's capabilities through HTTP endpoints. This can be used with any client that implements the MCP protocol.
2. A separate MCP bridge component that connects your favorite MCP client to the Binary Ninja MCP server.

## Prerequisites

- [Binary Ninja](https://binary.ninja/)
- Python 3.12+
- MCP client (those with auto-setup support are listed below)

## Installation

### MCP Client

Please install the MCP client before you install Binary Ninja MCP so that the MCP clients can be auto-setup. We currently support auto-setup for these MCP clients:

    1. Cline (recommended)
    2. Roo Code
    3. Claude Desktop (recommended)
    4. Cursor
    5. Windsurf
    6. Claude Code
    7. LM Studio

### Extension Installation

After the MCP client is installed, you can install the MCP server using the Binary Ninja Plugin Manager or manually. Both methods support auto-setup of MCP clients.

If your MCP client is not set, you should install it first then try to reinstall the extension.

#### Binary Ninja Plugin Manager

You may install the extension through Binary Ninja's Plugin Manager (`Plugins > Manage Plugins`).

![Plugin Manager](images/plugin-manager-listing.png)

#### Manual Install

To manually install the extension, this repository can be copied into the [Binary Ninja plugins folder](https://docs.binary.ninja/guide/plugins.html).

### [Optional] Manual Setup of the MCP Client

*You do NOT need to set this up manually if you use a supported MCP client and follow the installation steps before.*

You can also manage MCP client entries from the command line:

```bash
python scripts/mcp_client_installer.py --install    # auto setup supported MCP clients
python scripts/mcp_client_installer.py --uninstall  # remove entries and delete `.mcp_auto_setup_done`
python scripts/mcp_client_installer.py --config     # print a generic JSON config snippet
```

#### Using npm package (Recommended)

The recommended way to set up the MCP client is using the official npm package:

```bash
npx -y binary-ninja-mcp
```

For MCP clients, use this configuration:

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

Or if installed globally:

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

#### Using Python Bridge (Legacy)

For other MCP clients, use the Python bridge directly:

```json
{
    "mcpServers": {
        "binary_ninja_mcp": {
            "command": "/ABSOLUTE/PATH/TO/Binary Ninja/plugins/repositories/community/plugins/fosdickio_binary_ninja_mcp/.venv/bin/python",
            "args": [
                "/ABSOLUTE/PATH/TO/Binary Ninja/plugins/repositories/community/plugins/fosdickio_binary_ninja_mcp/bridge/binja_mcp_bridge.py"
            ]
        }
    }
}
```

Note: Replace `/ABSOLUTE/PATH/TO` with the actual absolute path to your project directory. The virtual environment's Python interpreter must be used to access the installed dependencies.

## Usage

1. Open Binary Ninja and load a binary
2. Click the button shown at left bottom corner
3. Start using it through your MCP client

You may now start prompting LLMs about the currently open binary (or binaries). Example prompts:

### CTF Challenges

```txt
You're the best CTF player in the world. Please solve this reversing CTF challenge in the <folder_name> folder using Binary Ninja. Rename ALL the function and the variables during your analyzation process (except for main function) so I can better read the code. Write a python solve script if you need. Also, if you need to create struct or anything, please go ahead. Reverse the code like a human reverser so that I can read the decompiled code that analyzed by you.
```

### Malware Analysis

```txt
Your task is to analyze an unknown file which is currently open in Binary Ninja. You can use the existing MCP server called "binary_ninja_mcp" to interact with the Binary Ninja instance and retrieve information, using the tools made available by this server. In general use the following strategy:

- Start from the entry point of the code
- If this function call others, make sure to follow through the calls and analyze these functions as well to understand their context
- If more details are necessary, disassemble or decompile the function and add comments with your findings
- Inspect the decompilation and add comments with your findings to important areas of code
- Add a comment to each function with a brief summary of what it does
- Rename variables and function parameters to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive, using mcp_ as prefix.
- NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
- When you finish your analysis, report how long the analysis took
- At the end, create a report with your findings.
- Based only on these findings, make an assessment on whether the file is malicious or not.
```

## Supported Capabilities

The following table lists the available MCP functions for use:

| Function                                                             | Description                                                                                                  |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `decompile_function`                                                 | Decompile a specific function by name and return HLIL-like code with addresses.                              |
| `get_il(name_or_address, view, ssa)`                                 | Get IL for a function in `hlil`, `mlil`, or `llil` (SSA supported for MLIL/LLIL).                            |
| `define_types`                                                       | Add type definitions from a C string type definition.                                                        |
| `delete_comment`                                                     | Delete the comment at a specific address.                                                                    |
| `delete_function_comment`                                            | Delete the comment for a function.                                                                           |
| `declare_c_type(c_declaration)`                                      | Create/update a local type from a single C declaration.                                                      |
| `format_value(address, text, size)`                                  | Convert a value and annotate it at an address in BN (adds a comment).                                        |
| `function_at`                                                        | Retrieve the name of the function the address belongs to.                                                    |
| `fetch_disassembly`                                              | Get the assembly representation of a function by name or address.                                            |
| `get_entry_points()`                                                 | List entry point(s) of the loaded binary.                                                                    |
| `get_binary_status`                                                  | Get the current status of the loaded binary.                                                                 |
| `get_comment`                                                        | Get the comment at a specific address.                                                                       |
| `get_function_comment`                                               | Get the comment for a function.                                                                              |
| `get_user_defined_type`                                              | Retrieve definition of a user-defined type (struct, enumeration, typedef, union).                            |
| `get_xrefs_to(address)`                                              | Get all cross references (code and data) to an address.                                                      |
| `get_data_decl(name_or_address, length)`                             | Return a C-like declaration and a hexdump for a data symbol or address.                                      |
| `hexdump_address(address, length)`                                   | Text hexdump at address. `length < 0` reads exact defined size if available.                                 |
| `hexdump_data(name_or_address, length)`                              | Hexdump by data symbol name or address. `length < 0` reads exact defined size if available.                  |
| `get_xrefs_to_enum(enum_name)`                                       | Get usages related to an enum (matches member constants in code).                                            |
| `get_xrefs_to_field(struct_name, field_name)`                        | Get all cross references to a named struct field.                                                            |
| `get_xrefs_to_struct(struct_name)`                                   | Get xrefs/usages related to a struct (members, globals, code refs).                                          |
| `get_xrefs_to_type(type_name)`                                       | Get xrefs/usages related to a struct/type (globals, refs, HLIL matches).                                     |
| `get_xrefs_to_union(union_name)`                                     | Get xrefs/usages related to a union (members, globals, code refs).                                           |
| `get_stack_frame_vars(function_identifier)`                          | Get stack frame variable information for a function (names, offsets, sizes, types).                           |
| `get_type_info(type_name)`                                           | Resolve a type and return declaration, kind, and members.                                                    |
| `get_callers(identifiers)`                                           | List callers plus call sites for one or more function identifiers.                                           |
| `get_callees(identifiers)`                                           | List callees plus call sites for one or more function identifiers.                                           |
| `make_function_at(address, platform)`                                | Create a function at an address. `platform` optional; use `default` to pick the BinaryView/platform default. |
| `list_platforms()`                                                   | List all available platform names.                                                                           |
| `list_binaries()`                                                    | List managed/open binaries with ids and active flag.                                                         |
| `select_binary(view)`                                                | Select active binary by id or filename.                                                                      |
| `list_all_strings()`                                                 | List all strings (no pagination; aggregates all pages).                                                      |
| `list_classes`                                                       | List all namespace/class names in the program.                                                               |
| `list_data_items`                                                    | List defined data labels and their values.                                                                   |
| `list_exports`                                                       | List exported functions/symbols.                                                                             |
| `list_imports`                                                       | List imported symbols in the program.                                                                        |
| `list_local_types(offset, count)`                                    | List local Types in the current database (name/kind/decl).                                                   |
| `list_methods`                                                       | List all function names in the program.                                                                      |
| `list_namespaces`                                                    | List all non-global namespaces in the program.                                                               |
| `list_segments`                                                      | List all memory segments in the program.                                                                     |
| `list_strings(offset, count)`                                        | List all strings in the database (paginated).                                                                |
| `list_strings_filter(offset, count, filter)`                         | List matching strings (paginated, filtered by substring).                                                    |
| `rename_data`                                                        | Rename a data label at the specified address.                                                                |
| `rename_function`                                                    | Rename a function by its current name to a new user-defined name.                                            |
| `rename_single_variable`                                             | Rename a single local variable inside a function.                                                            |
| `rename_multi_variables`                                             | Batch rename multiple local variables in a function (mapping or pairs).                                      |
| `set_local_variable_type(function_address, variable_name, new_type)` | Set a local variable's type.                                                                                 |
| `retype_variable`                                                    | Retype variable inside a given function.                                                                     |
| `search_functions_by_name`                                           | Search for functions whose name contains the given substring.                                                |
| `search_types(query, offset, count)`                                 | Search local Types by substring (name/decl).                                                                 |
| `set_comment`                                                        | Set a comment at a specific address.                                                                         |
| `set_function_comment`                                               | Set a comment for a function.                                                                                |
| `set_function_prototype(name_or_address, prototype)`                 | Set a function's prototype by name or address.                                                               |
| `patch_bytes(address, data, save_to_file)`                           | Patch raw bytes at an address (byte-level, not assembly). Can patch entire instructions by providing their bytecode. Address: hex (e.g., "0x401000") or decimal. Data: hex string (e.g., "90 90"). `save_to_file` (default True) saves to disk and re-signs on macOS. |

### Interactive Debugging

Drive Binary Ninja's debugger from the MCP client: set breakpoints, run the
target, and inspect its state when it stops — a debugging session comparable to
using a debugger by hand. `run`/`continue` **block** until the target next stops
(a breakpoint, exit, crash, or the timeout), so the returned stop result always
tells you exactly what happened.

Every halted stop auto-attaches a **pwndbg-style context** — active thread,
registers, a stack telescope, the disassembly around the current PC, and the
backtrace — so one call shows the whole picture. Pass `context=false` on
`run`/`continue`/`step` to omit it (useful for tight stepping loops), or call
`debug_context` on demand. Unexpected stops (crash/signal) always keep registers
and backtrace even with context off.

You can **switch the inspection context** to another thread (`debug_select_thread`)
or up/down the call stack (`debug_select_frame` / `debug_frame_up` /
`debug_frame_down`); the selection persists so subsequent registers/backtrace/
context reflect it, until you change it or the target runs again. (Caller frames
report unwound pc/sp/fp plus the recoverable registers — the callee clobbers the
rest, which are honestly omitted.)

| Function                                             | Description                                                                                                                                                             |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `debug_set_breakpoint(location, condition)`          | Set a breakpoint by symbol/function **name** (e.g. `"checkResponse"`) or address. Optional `condition` only stops when true; supports registers, arithmetic, comparisons, and memory dereference (e.g. `"rdi == 0x10"`, `"u32([rdi]) == 0x1234"`) — same syntax as `debug_evaluate`. |
| `debug_list_breakpoints()`                           | List all breakpoints with their ids, addresses, symbols, conditions, and enabled state.                                                                                |
| `debug_delete_breakpoint(id)`                        | Delete a breakpoint by id.                                                                                                                                              |
| `debug_enable_breakpoint(id)` / `debug_disable_breakpoint(id)` | Enable or disable a breakpoint by id (disabled ones stay in the list but don't fire).                                                                          |
| `debug_set_watchpoint(address, size, type)`         | Set a hardware watchpoint (`type`: write/read/readwrite). When the memory is accessed, run/continue stops with status `watchpoint` naming it. HW watchpoints are limited (~4); over the limit errors. |
| `debug_list_watchpoints()`                           | List all watchpoints (id, address, size, type, enabled).                                                                                                               |
| `debug_delete_watchpoint(id)`                        | Delete a watchpoint by id.                                                                                                                                              |
| `debug_enable_watchpoint(id)` / `debug_disable_watchpoint(id)` | Enable or disable a watchpoint by id.                                                                                                                          |
| `debug_run(stop_at_entry, timeout_seconds, ...)`     | Launch the target and run until it stops (blocking). Runs to the first breakpoint by default; `stop_at_entry` halts at the entry point instead.                        |
| `debug_continue(timeout_seconds)`                    | Continue a stopped target until it next stops (blocking).                                                                                                               |
| `debug_step(timeout_seconds)`                        | Execute a single instruction, stepping into calls (blocking).                                                                                                           |
| `debug_step_over(timeout_seconds)`                   | Execute a single instruction, stepping over calls (blocking).                                                                                                           |
| `debug_step_out(timeout_seconds)`                    | Run until the current function returns to its caller ("finish"; blocking).                                                                                              |
| `debug_run_to(address, timeout_seconds)`             | Resume until the target reaches an address ("advance"/"until"; blocking).                                                                                               |
| `debug_pause()`                                      | Break into a running target (e.g. hung or looping) so it can be inspected; the in-flight run/continue returns with the stop location.                                  |
| `debug_write_stdin(data)`                            | Write to the target's stdin (Linux/macOS) — feed an interactive prompt. Non-blocking; can be called while a `run`/`continue` is blocked on the target's read.          |
| `debug_context()`                                    | Full pwndbg-style context of the halted target: active thread, registers, stack telescope, disassembly around PC, backtrace. Auto-attached to run/continue/step stops (pass `context=false` to omit). |
| `debug_status()`                                     | Debugger session status: active adapter (dialect for `debug_backend_command`), live/running, current ip/function when halted, breakpoint count. Works before launch.        |
| `debug_backend_command(command)`                     | Escape hatch: run a raw command in the underlying adapter console (LLDB/WinDbg). For capabilities not yet wrapped (e.g. watchpoints, memory maps). Returns adapter + output. |
| `debug_list_modules()`                               | List the images loaded in the target (executable + shared libraries) with runtime load base and size.                                                                       |
| `debug_resolve_address(address)`                     | Resolve a runtime address to its memory mapping + backing image: `mmap_base`, `image_base`, `image_name`, `image_offset` (with `image_base + image_offset == address`). Descriptive only, no static translation. |
| `debug_get_registers(full)`                          | Read registers of the halted target, with pointer hints. Important registers by default; `full=true` for the complete file (sub-registers, segment, FPU/vector).       |
| `debug_get_backtrace(tid)`                           | Get the call stack of a halted thread (`tid` 0 = active thread).                                                                                                        |
| `debug_list_threads()`                               | List the target's threads (tid, rip, function, which is active).                                                                                                        |
| `debug_select_thread(tid)`                           | Make a thread active; subsequent inspection (registers/backtrace/context) targets it.                                                                                   |
| `debug_select_frame(frame)`                          | Select a stack frame (0 = innermost); subsequent context/registers/backtrace reflect it (persists). Caller frames report unwound pc/sp/fp + recoverable registers only. |
| `debug_frame_up()` / `debug_frame_down()`            | Move one frame toward the caller / callee (gdb `up`/`down`), returning that frame's context.                                                                            |
| `debug_read_memory(address, size)`                   | Read memory from the halted target as a hexdump. Errors clearly if the region is non-readable or unmapped.                                                              |
| `debug_evaluate(expression)`                         | Evaluate an expression over registers and memory: arithmetic/comparison/boolean plus memory dereference (`[expr]`, `deref/u8..u64/i8..i64`). Returns hex + decimal, annotating a pointer that points at a string/function. |
| `debug_set_register(name, value)`                    | Set a register in the halted target; verified by readback (returns old/new).                                                                                            |
| `debug_write_memory(address, data)`                  | Write hex bytes to the halted target's **live process** memory (distinct from `patch_bytes`, which edits the static view). Non-writable/unmapped regions error; verified by readback. |
| `debug_quit()`                                       | Terminate the running target.                                                                                                                                            |

**Stop results.** `debug_run`/`debug_continue` return a `status` of `breakpoint`,
`exited`, `crashed`, `signal`, `stopped`, or `paused`. For any *unexpected* stop
(a crash, a signal, or a timeout-pause) the register state and backtrace are
attached automatically, so you never have to guess why the target stopped.

**Blocking and hangs.** `run`/`continue` block up to `timeout_seconds`
(default 30); if the target hasn't stopped by then it is paused and returned
with its current location (`status: "paused"`, `timed_out: true`) so a hung or
long-running target is never fatal. Use `timeout_seconds=0` to wait
indefinitely and break in with `debug_pause` from a separate request.

These are the list of HTTP endpoints that can be called:

- `/allStrings`: All strings in one response.
- `/formatValue?address=<addr>&text=<value>&size=<n>`: Convert and set a comment at an address.
- `/getXrefsTo?address=<addr>`: Xrefs to address (code+data).
- `/getDataDecl?name=<symbol>|address=<addr>&length=<n>`: JSON with declaration-style string and a hexdump for a data symbol or address. Keys: `address`, `name`, `size`, `type`, `decl`, `hexdump`. `length < 0` reads exact defined size if available.
- `/hexdump?address=<addr>&length=<n>`: Text hexdump aligned at address; `length < 0` reads exact defined size if available.
- `/hexdumpByName?name=<symbol>&length=<n>`: Text hexdump by symbol name. Recognizes BN auto-labels like `data_<hex>`, `byte_<hex>`, `word_<hex>`, `dword_<hex>`, `qword_<hex>`, `off_<hex>`, `unk_<hex>`, and plain hex addresses.
- `/makeFunctionAt?address=<addr>&platform=<name|default>`: Create a function at an address (idempotent if already exists). `platform=default` uses the BinaryView/platform default.
- `/platforms`: List all available platform names.
- `/binaries` or `/views`: List managed/open binaries with ids and active flag.
- `/selectBinary?view=<id|filename>`: Select active binary for subsequent operations.
- `/data?offset=<n>&limit=<m>&length=<n>`: Defined data items with previews. `length` controls bytes read per item (capped at defined size). Default behavior reads exact defined size when available; `length=-1` forces exact-size.
- `/getXrefsToEnum?name=<enum>`: Enum usages by matching member constants.
- `/getXrefsToField?struct=<name>&field=<name>`: Xrefs to struct field.
- `/getXrefsToType?name=<type>`: Xrefs/usages related to a struct/type name.
- `/getTypeInfo?name=<type>`: Resolve a type and return declaration and details.
- `/getXrefsToUnion?name=<union>`: Union xrefs/usages (members, globals, refs).
- `/getStackFrameVars?name=<function>|address=<addr>`: Get stack frame variable information for a function.
- `/getCallers?identifiers=<name|addr>[,...]`: Return caller summaries (functions, call sites, HLIL/IL snippets) for one or more identifiers. Accepts `identifiers`, `identifier`, `names`, or `addresses` query params.
- `/getCallees?identifiers=<name|addr>[,...]`: Return callee summaries with the same schema as `/getCallers`, detailing every outgoing call target per request identifier.
- `/localTypes?offset=<n>&limit=<m>`: List local types.
- `/strings?offset=<n>&limit=<m>`: Paginated strings.
- `/strings/filter?offset=<n>&limit=<m>&filter=<substr>`: Filtered strings.
- `/searchTypes?query=<substr>&offset=<n>&limit=<m>`: Search local types by substring.
- `/patch` or `/patchBytes?address=<addr>&data=<hex>&save_to_file=<bool>`: Patch raw bytes at an address (byte-level, not assembly). Can patch entire instructions by providing their bytecode. Address: hex (e.g., "0x401000") or decimal. Data: hex string (e.g., "90 90"). `save_to_file` (default True) saves to disk and re-signs on macOS.
- `/renameVariables`: Batch rename locals in a function. Parameters:
  - Function: one of `functionAddress`, `address`, `function`, `functionName`, or `name`.
  - Provide renames via one of:
    - `renames`: JSON array of `{old, new}` objects
    - `mapping`: JSON object of `old->new`
    - `pairs`: compact string `old1:new1,old2:new2`
          Returns per-item results plus totals. Order is respected; later pairs can refer to earlier new names.

Interactive debugging endpoints:

- `/debug/breakpoint` (GET/POST/DELETE): list, add (`location` = symbol/function name or address, optional `condition`), or delete (`id`) a breakpoint.
- `/debug/breakpoint/enable?id=<id>` and `/debug/breakpoint/disable?id=<id>` (GET/POST): enable/disable a breakpoint without deleting it.
- `/debug/watchpoint` (GET/POST/DELETE): list, add (`address`, optional `size`=1/2/4/8, optional `type`=write/read/readwrite), or delete (`id`) a hardware watchpoint. On a hit, run/continue returns `status: "watchpoint"` with `watchpoint_id`.
- `/debug/watchpoint/enable?id=<id>` and `/debug/watchpoint/disable?id=<id>` (GET/POST): enable/disable a watchpoint.
- `/debug/run?stop_at_entry=<bool>&timeout=<seconds>` (GET/POST): launch and run until the next stop (blocking). `timeout<=0` waits indefinitely. Optional `cmd_line`, `working_directory`, `adapter_type`.
- `/debug/continue?timeout=<seconds>` (GET/POST): continue until the next stop (blocking).
- `/debug/step?timeout=<seconds>` (GET/POST): single-instruction step into calls (blocking).
- `/debug/stepover?timeout=<seconds>` (GET/POST): single-instruction step over calls (blocking).
- `/debug/stepout?timeout=<seconds>` (GET/POST): run until the current function returns (blocking).
- `/debug/runto?address=<addr>&timeout=<seconds>` (GET/POST): resume until an address is reached (blocking).
- `/debug/pause` (GET/POST): break into a running target so it can be inspected.
- `/debug/stdin?data=<text>` (GET/POST): write to the target's stdin (feed an interactive prompt); non-blocking, works while a run/continue is blocked. POST preferred for newlines.
- `/debug/context`: full halted-state context (thread, registers, stack telescope, disasm-at-PC, backtrace). Auto-attached to run/continue/step stops unless `context=0`.
- `/debug/evaluate?expression=<expr>` (GET/POST): evaluate an expression over registers and memory (arithmetic, comparison, boolean, and dereference `[expr]`/`deref`/`u8..u64`/`i8..i64`); returns hex + decimal with pointer annotations.
- `/debug/setRegister?name=<reg>&value=<val>` (GET/POST): set a register; verified by readback.
- `/debug/writeMemory?address=<addr>&data=<hex>` (GET/POST): write hex bytes to the live process; non-writable/unmapped regions error; verified by readback.
- `/debug/status`: session status — active adapter (dialect), live/running, current ip/function when halted, breakpoint count. Works before launch.
- `/debug/backend?command=<cmd>` (GET/POST): run a raw command in the underlying adapter console (LLDB/WinDbg); returns the active adapter and its output. POST preferred for commands with spaces.
- `/debug/modules`: list images loaded in the target (executable + shared libraries) with runtime base and size.
- `/debug/resolve?address=<addr>`: resolve a runtime address to its mapping and backing image (`mmap_base`, `image_base`, `image_name`, `image_offset`).
- `/debug/registers?full=<bool>`: registers of the halted target (with pointer hints); `full=1` returns the complete register file.
- `/debug/backtrace?tid=<tid>`: call stack of the halted target's active thread, or thread `tid` when given.
- `/debug/threads`: list the target's threads (tid, rip, function, active).
- `/debug/thread/select?tid=<tid>` (GET/POST): make a thread active.
- `/debug/frame/select?frame=<index>` (GET/POST): select a stack frame (persists; inspection reflects it).
- `/debug/frame/up` and `/debug/frame/down` (GET/POST): move one frame toward the caller / callee.
- `/debug/memory?address=<addr>&size=<n>`: hexdump of memory from the halted target.
- `/debug/quit` (GET/POST): terminate the running target.

## Development

### Project Layout

```
plugin/
├── __init__.py      # Plugin entry point: server lifecycle, menu commands
├── settings.py      # Binary Ninja settings registration
├── ui.py            # Status bar indicator and UI notifications
├── server/
│   ├── http_server.py   # HTTP server and request dispatch
│   ├── router.py        # Route registry (@route decorator)
│   └── handlers/        # One module per endpoint domain
├── api/
│   └── endpoints.py     # Higher-level operations shared by handlers
├── core/
│   └── binary_operations.py  # Facade over domain mixins (views, functions,
│                              # data, types, comments, xrefs)
└── utils/               # Hexdump, number/string parsing helpers
bridge/                  # MCP stdio bridge that proxies to the HTTP server
```

To add an endpoint: write a handler in the matching `plugin/server/handlers/`
module (or a new one) and register it with `@route("/path")`; put any Binary
Ninja API logic in the corresponding `plugin/core/` mixin.

### Code Quality

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting. Configuration is in `ruff.toml`.

#### Running Ruff Manually

Check for issues:
```bash
ruff check .
```

Auto-fix issues:
```bash
ruff check --fix .
```

Check formatting issues:
```bash
ruff format --check .
```

Format code:
```bash
ruff format .
```

#### GitHub Actions

A GitHub Action workflow (`.github/workflows/lint-format.yml`) automatically runs Ruff on:

- Every push to the `main` branch
- Every pull request targeting the `main` branch

The workflow will fail if there are linting errors or formatting issues, ensuring code quality in CI.

## Contributing

Contributions are welcome. Please feel free to submit a pull request.
