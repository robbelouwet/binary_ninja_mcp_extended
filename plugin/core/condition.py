"""Safe evaluator for debugger expressions and breakpoint conditions.

Supports a deliberately small language so we never run arbitrary code:
register names, integer/hex literals, comparisons ``== != < <= > >=``,
arithmetic ``+ - * / % & | ^ << >>``, unary ``- ~ not``, boolean ``and``/``or``,
and memory dereference. Anything else (attribute access, arbitrary calls, names
that aren't registers) is rejected.

Memory dereference (only when a memory reader is provided):
- ``[expr]``            read 8 bytes (pointer-sized) at the address ``expr``
- ``deref(expr)``       same as ``[expr]``
- ``u8/u16/u32/u64(e)`` read that many bytes, unsigned
- ``i8/i16/i32/i64(e)`` read that many bytes, signed

    evaluate("rax + 8", regs)                     -> int
    evaluate("[rsp]", regs, read_mem)             -> the pointer on the stack top
    evaluate_condition("u32([rdi]) == 0x1234", …) -> bool
"""

import ast
import operator

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.floordiv,
    ast.Mod: operator.mod,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}

_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}

_UNARY_OPS = {
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Invert: operator.invert,
    ast.Not: operator.not_,
}

# Memory-read "functions": name -> (size_bytes, signed).
_MEM_FUNCS = {
    "deref": (8, False),
    "u8": (1, False),
    "u16": (2, False),
    "u32": (4, False),
    "u64": (8, False),
    "i8": (1, True),
    "i16": (2, True),
    "i32": (4, True),
    "i64": (8, True),
}


class ConditionError(ValueError):
    """Raised for a malformed or unsupported expression."""


class _Ctx:
    """Evaluation context: register values and an optional memory reader.

    ``read_mem(address, size)`` returns ``bytes`` (len == size) or None on a
    failed/inaccessible read.
    """

    def __init__(self, registers, read_mem=None):
        self.registers = registers
        self.read_mem = read_mem


def evaluate(expr: str, registers: dict[str, int], read_mem=None) -> int:
    """Evaluate ``expr`` and return its value (an int; bool for comparisons)."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ConditionError(f"invalid syntax: {e.msg}")
    return _eval(tree.body, _Ctx(registers, read_mem))


def evaluate_condition(expr: str, registers: dict[str, int], read_mem=None) -> bool:
    """Evaluate ``expr`` as a boolean (for breakpoint conditions)."""
    return bool(evaluate(expr, registers, read_mem))


def _read(ctx: _Ctx, address: int, size: int, signed: bool) -> int:
    if ctx.read_mem is None:
        raise ConditionError("memory access is not available here")
    data = ctx.read_mem(address, size)
    if not data or len(data) < size:
        raise ConditionError(f"cannot read {size} byte(s) at {hex(address)}")
    return int.from_bytes(bytes(data)[:size], "little", signed=signed)


def _eval(node, ctx: _Ctx):
    if isinstance(node, ast.BoolOp):
        values = [_eval(v, ctx) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        return any(values)

    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise ConditionError("unsupported unary operator")
        return op(_eval(node.operand, ctx))

    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise ConditionError("unsupported operator")
        return op(_eval(node.left, ctx), _eval(node.right, ctx))

    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op_node, right_node in zip(node.ops, node.comparators, strict=True):
            op = _CMP_OPS.get(type(op_node))
            if op is None:
                raise ConditionError("unsupported comparison")
            right = _eval(right_node, ctx)
            if not op(left, right):
                return False
            left = right
        return True

    # [expr] -> dereference (8 bytes, pointer-sized).
    if isinstance(node, ast.List):
        if len(node.elts) != 1:
            raise ConditionError("dereference [..] takes exactly one address")
        return _read(ctx, _eval(node.elts[0], ctx), 8, False)

    # deref(expr) / u8(expr) / i32(expr) / ... -> sized memory read.
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in _MEM_FUNCS:
            raise ConditionError("only memory-read functions (deref, u8..u64, i8..i64) are allowed")
        if len(node.args) != 1 or node.keywords:
            raise ConditionError(f"{node.func.id}(expr) takes exactly one address")
        size, signed = _MEM_FUNCS[node.func.id]
        return _read(ctx, _eval(node.args[0], ctx), size, signed)

    if isinstance(node, ast.Name):
        if node.id in ctx.registers:
            return ctx.registers[node.id]
        raise ConditionError(f"unknown register: {node.id}")

    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return node.value
        if isinstance(node.value, int):
            return node.value
        raise ConditionError("only integer literals are allowed")

    raise ConditionError("unsupported expression")
