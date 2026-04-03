"""
Constraint Solver Worker — Z3-based constraint solving for VM-protected binaries.

Communicates with Node.js via stdin/stdout JSON protocol:
  - solve_constraints: solve a set of constraints using Z3 BitVec
  - check_sat: quick satisfiability check
"""

from __future__ import annotations

import sys
import json
import time
import traceback
from typing import Dict, List, Any, Optional


def _setup_z3():
    """Lazy Z3 import."""
    try:
        import z3
        return z3, True, None
    except ImportError as e:
        return None, False, str(e)


def solve_constraints(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Solve a set of constraints expressed as Z3 Python expressions.
    
    params:
      - constraints: list of {left, op, right} expression dicts
      - variables: list of {name, bits} variable declarations
      - timeout_ms: optional solver timeout
    """
    z3, available, err = _setup_z3()
    if not available:
        return {"ok": False, "errors": [f"Z3 not available: {err}"]}
    
    variables = params.get("variables", [])
    constraints = params.get("constraints", [])
    timeout_ms = params.get("timeout_ms", 30000)
    
    # Create solver
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    
    # Declare variables
    var_map: Dict[str, Any] = {}
    for v in variables:
        name = v["name"]
        bits = v.get("bits", 32)
        var_map[name] = z3.BitVec(name, bits)
    
    def build_expr(node):
        """Recursively build Z3 expression from dict AST."""
        if isinstance(node, (int, float)):
            return z3.BitVecVal(int(node), 32)
        
        kind = node.get("kind", "")
        
        if kind == "var":
            name = node["name"]
            if name not in var_map:
                bits = node.get("bits", 32)
                var_map[name] = z3.BitVec(name, bits)
            return var_map[name]
        
        if kind == "const":
            value = node["value"]
            bits = node.get("bits", 32)
            return z3.BitVecVal(value, bits)
        
        if kind == "binop":
            left = build_expr(node["left"])
            right = build_expr(node["right"])
            op = node["op"]
            
            op_map = {
                "+": lambda a, b: a + b,
                "-": lambda a, b: a - b,
                "*": lambda a, b: a * b,
                "/": lambda a, b: z3.UDiv(a, b),
                "%": lambda a, b: z3.URem(a, b),
                "^": lambda a, b: a ^ b,
                "&": lambda a, b: a & b,
                "|": lambda a, b: a | b,
                "<<": lambda a, b: a << b,
                ">>": lambda a, b: z3.LShR(a, b),
                "ADD": lambda a, b: a + b,
                "SUB": lambda a, b: a - b,
                "MUL": lambda a, b: a * b,
                "XOR": lambda a, b: a ^ b,
                "AND": lambda a, b: a & b,
                "OR": lambda a, b: a | b,
                "SHL": lambda a, b: a << b,
                "SHR": lambda a, b: z3.LShR(a, b),
            }
            
            fn = op_map.get(op)
            if fn is None:
                raise ValueError(f"Unknown binary operation: {op}")
            return fn(left, right)
        
        if kind == "unary":
            child = build_expr(node["child"])
            op = node["op"]
            if op in ("~", "NOT"):
                return ~child
            if op in ("-", "NEG"):
                return -child
            raise ValueError(f"Unknown unary operation: {op}")
        
        if kind == "rotate":
            child = build_expr(node["child"])
            bits = build_expr(node["bits"])
            direction = node.get("dir", "left")
            if direction == "left":
                return z3.RotateLeft(child, bits)
            return z3.RotateRight(child, bits)
        
        if kind == "func":
            # Special functions
            fname = node.get("name", "")
            args = [build_expr(a) for a in node.get("args", [])]
            if fname.upper() in ("CRC16", "CRC32"):
                # Cannot model as closed-form — create uninterpreted function
                bits = node.get("result_bits", 32)
                func = z3.Function(fname, *([z3.BitVecSort(32)] * len(args)), z3.BitVecSort(bits))
                return func(*args)
            raise ValueError(f"Unknown function: {fname}")
        
        raise ValueError(f"Unknown expression kind: {kind}")
    
    # Build and add constraints
    errors = []
    for i, c in enumerate(constraints):
        try:
            left_expr = build_expr(c["left"])
            right_expr = build_expr(c["right"])
            op = c.get("op", "==")
            
            if op == "==":
                solver.add(left_expr == right_expr)
            elif op == "!=":
                solver.add(left_expr != right_expr)
            elif op == "<":
                solver.add(z3.ULT(left_expr, right_expr))
            elif op == "<=":
                solver.add(z3.ULE(left_expr, right_expr))
            elif op == ">":
                solver.add(z3.UGT(left_expr, right_expr))
            elif op == ">=":
                solver.add(z3.UGE(left_expr, right_expr))
            else:
                errors.append(f"Constraint {i}: unknown operator '{op}'")
        except Exception as e:
            errors.append(f"Constraint {i}: {str(e)}")
    
    if errors:
        return {"ok": False, "errors": errors}
    
    # Solve
    result = solver.check()
    
    if result == z3.sat:
        model = solver.model()
        solution = {}
        for name, var in var_map.items():
            val = model.evaluate(var, model_completion=True)
            try:
                solution[name] = val.as_long()
            except Exception:
                solution[name] = str(val)
        
        return {
            "ok": True,
            "satisfiable": True,
            "solution": solution,
            "num_constraints": len(constraints),
            "num_variables": len(var_map),
        }
    
    elif result == z3.unsat:
        return {
            "ok": True,
            "satisfiable": False,
            "solution": None,
            "num_constraints": len(constraints),
            "num_variables": len(var_map),
        }
    
    else:
        return {
            "ok": True,
            "satisfiable": None,
            "solution": None,
            "reason": "timeout or unknown",
            "num_constraints": len(constraints),
            "num_variables": len(var_map),
        }


def check_sat(params: Dict[str, Any]) -> Dict[str, Any]:
    """Quick satisfiability check for a Z3 script string."""
    z3, available, err = _setup_z3()
    if not available:
        return {"ok": False, "errors": [f"Z3 not available: {err}"]}
    
    script = params.get("script", "")
    timeout_ms = params.get("timeout_ms", 10000)
    
    if not script:
        return {"ok": False, "errors": ["No Z3 script provided"]}
    
    # Execute in isolated namespace
    namespace: Dict[str, Any] = {"z3": z3}
    try:
        exec(script, namespace)  # noqa: S102
        result = namespace.get("result", None)
        solution = namespace.get("solution", None)
        
        return {
            "ok": True,
            "result": str(result) if result is not None else "unknown",
            "solution": solution,
        }
    except Exception as e:
        return {"ok": False, "errors": [f"Script execution error: {str(e)}"]}


COMMANDS = {
    "solve_constraints": solve_constraints,
    "check_sat": check_sat,
}


def main():
    """Main loop — stdin/stdout JSON protocol."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        start = time.time()
        try:
            request = json.loads(line)
            job_id = request.get("job_id", "unknown")
            tool = request.get("tool", "")
            params = request.get("params", {})
            
            handler = COMMANDS.get(tool)
            if handler is None:
                response = {
                    "job_id": job_id,
                    "ok": False,
                    "errors": [f"Unknown tool: {tool}"],
                    "data": None,
                    "artifacts": [],
                    "metrics": {},
                    "warnings": [],
                }
            else:
                result = handler(params)
                elapsed = (time.time() - start) * 1000
                response = {
                    "job_id": job_id,
                    "ok": result.get("ok", False),
                    "data": result,
                    "errors": result.get("errors", []),
                    "warnings": result.get("warnings", []),
                    "artifacts": [],
                    "metrics": {"elapsed_ms": round(elapsed, 2), "tool": tool},
                }
        
        except json.JSONDecodeError as e:
            response = {
                "job_id": "unknown",
                "ok": False,
                "errors": [f"JSON decode error: {str(e)}"],
                "data": None,
                "artifacts": [],
                "metrics": {},
                "warnings": [],
            }
        except Exception as e:
            response = {
                "job_id": request.get("job_id", "unknown") if "request" in dir() else "unknown",
                "ok": False,
                "errors": [f"Unexpected error: {str(e)}\n{traceback.format_exc()}"],
                "data": None,
                "artifacts": [],
                "metrics": {},
                "warnings": [],
            }
        
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
