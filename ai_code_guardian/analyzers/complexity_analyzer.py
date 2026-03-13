"""
complexity_analyzer.py
Analyses time & space complexity from code structure.
Uses AST to count loop nesting depth and estimate Big-O complexity.
"""

import ast
from typing import Dict, List


def analyse_complexity(code: str) -> Dict:
    """
    Analyse the time complexity of the provided code.
    Returns complexity label, nesting depth, and per-function breakdown.
    """
    result = {
        "overall_complexity": "O(1)",
        "max_nesting_depth": 0,
        "loop_count": 0,
        "nested_loop_count": 0,
        "function_complexities": [],
        "details": [],
        "parse_success": True,
    }

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        result["parse_success"] = False
        result["details"].append(f"Syntax error — cannot parse: {e}")
        return result

    # ── Analyse each function separately ─────────────────────────────────────
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_info = _analyse_function(node, code)
            result["function_complexities"].append(fn_info)

    # ── Module-level analysis ─────────────────────────────────────────────────
    module_depth, module_loops, module_nested = _count_loops(tree)
    result["max_nesting_depth"] = module_depth
    result["loop_count"] = module_loops
    result["nested_loop_count"] = module_nested
    result["overall_complexity"] = _depth_to_bigo(module_depth)

    # ── Build detail messages ─────────────────────────────────────────────────
    if module_nested > 0:
        result["details"].append(
            f"{module_nested} nested loop(s) detected → worst-case {result['overall_complexity']}"
        )
    if module_loops > 0 and module_nested == 0:
        result["details"].append(f"{module_loops} loop(s) detected → O(n)")
    if module_loops == 0:
        result["details"].append("No loops detected → O(1) constant time.")

    return result


def _count_loops(node: ast.AST, current_depth: int = 0):
    """
    Recursively count loops and measure nesting depth.
    Returns (max_depth, total_loops, nested_loops_count).
    """
    max_depth = current_depth
    total_loops = 0
    nested = 0

    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.For, ast.While)):
            total_loops += 1
            child_depth, child_loops, child_nested = _count_loops(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
            total_loops += child_loops
            # Any loop inside another loop is a nested loop
            if current_depth >= 1:
                nested += 1
            nested += child_nested
        else:
            child_depth, child_loops, child_nested = _count_loops(child, current_depth)
            max_depth = max(max_depth, child_depth)
            total_loops += child_loops
            nested += child_nested

    return max_depth, total_loops, nested


def _depth_to_bigo(depth: int) -> str:
    """Map loop nesting depth to Big-O notation."""
    mapping = {
        0: "O(1)",
        1: "O(n)",
        2: "O(n²)",
        3: "O(n³)",
        4: "O(n⁴)",
    }
    if depth >= 5:
        return f"O(n^{depth}) — extremely inefficient"
    return mapping.get(depth, "O(1)")


def _analyse_function(fn_node: ast.FunctionDef, source: str) -> Dict:
    """Analyse a single function node for complexity."""
    depth, loops, nested = _count_loops(fn_node)
    complexity = _depth_to_bigo(depth)
    return {
        "name": fn_node.name,
        "line": fn_node.lineno,
        "complexity": complexity,
        "loop_count": loops,
        "nested_loops": nested,
        "nesting_depth": depth,
    }


def get_complexity_recommendations(result: Dict) -> List[str]:
    """Generate human-readable recommendations based on complexity analysis."""
    recs = []
    depth = result["max_nesting_depth"]

    if depth >= 4:
        recs.append("🔴 Extremely deep nesting — consider divide-and-conquer or memoisation.")
    elif depth == 3:
        recs.append("🟠 Triple nested loops — look for O(n²) or O(n log n) alternatives.")
    elif depth == 2:
        recs.append("🟡 Quadratic complexity detected — consider hash maps or sorting-based solutions.")
    elif depth == 1:
        recs.append("🟢 Linear complexity — good. Ensure the loop body is O(1).")
    else:
        recs.append("✅ Constant time — excellent!")

    for fn in result.get("function_complexities", []):
        if fn["nesting_depth"] >= 2:
            recs.append(
                f"  • Function '{fn['name']}' (line {fn['line']}) has {fn['complexity']} complexity."
            )
    return recs