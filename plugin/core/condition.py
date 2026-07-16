"""Safe evaluator for conditional-breakpoint expressions.

Supports a deliberately small language so we never run arbitrary code:
register names, integer/hex literals, the comparisons ``== != < <= > >=``,
arithmetic ``+ - * / % & | ^ << >>``, unary ``- ~ not``, and boolean
``and``/``or``. Anything else (calls, attribute access, names that aren't
registers) is rejected.

    evaluate_condition("rax == 0x10", {"rax": 16})       -> True
    evaluate_condition("rdi & 1 and rsi > rdi", regs)    -> bool
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


class ConditionError(ValueError):
    """Raised for a malformed or unsupported condition expression."""


def evaluate_condition(expr: str, registers: dict[str, int]) -> bool:
    """Evaluate ``expr`` against register values, returning a bool."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ConditionError(f"invalid syntax: {e.msg}")
    return bool(_eval(tree.body, registers))


def _eval(node, regs):
    if isinstance(node, ast.BoolOp):
        values = [_eval(v, regs) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        return any(values)

    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise ConditionError("unsupported unary operator")
        return op(_eval(node.operand, regs))

    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise ConditionError("unsupported operator")
        return op(_eval(node.left, regs), _eval(node.right, regs))

    if isinstance(node, ast.Compare):
        left = _eval(node.left, regs)
        for op_node, right_node in zip(node.ops, node.comparators, strict=True):
            op = _CMP_OPS.get(type(op_node))
            if op is None:
                raise ConditionError("unsupported comparison")
            right = _eval(right_node, regs)
            if not op(left, right):
                return False
            left = right
        return True

    if isinstance(node, ast.Name):
        if node.id in regs:
            return regs[node.id]
        raise ConditionError(f"unknown register: {node.id}")

    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return node.value
        if isinstance(node.value, int):
            return node.value
        raise ConditionError("only integer literals are allowed")

    raise ConditionError("unsupported expression")
