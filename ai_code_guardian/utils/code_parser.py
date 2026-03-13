"""
code_parser.py
Parses Python code using AST and extracts structural metrics.
"""

import ast
import re


def parse_code(code: str) -> dict:
    """
    Parse Python source code and extract metrics.
    Returns a dict with counts of loops, conditions, variables, functions, classes.
    Falls back to regex-based counting if AST parsing fails.
    """
    metrics = {
        "number_of_lines": len([l for l in code.splitlines() if l.strip()]),
        "number_of_loops": 0,
        "number_of_conditions": 0,
        "number_of_variables": 0,
        "number_of_functions": 0,
        "number_of_classes": 0,
        "max_nesting_depth": 0,
        "parse_success": False,
        "syntax_errors": [],
    }

    # --- AST-based extraction ---
    try:
        tree = ast.parse(code)
        metrics["parse_success"] = True

        loop_nodes = (ast.For, ast.While)
        cond_nodes = (ast.If,)
        assign_names = set()

        def _walk_depth(node, depth=0):
            """Recursively walk AST, track nesting depth."""
            metrics["max_nesting_depth"] = max(metrics["max_nesting_depth"], depth)

            if isinstance(node, loop_nodes):
                metrics["number_of_loops"] += 1
                for child in ast.iter_child_nodes(node):
                    _walk_depth(child, depth + 1)

            elif isinstance(node, cond_nodes):
                metrics["number_of_conditions"] += 1
                for child in ast.iter_child_nodes(node):
                    _walk_depth(child, depth + 1)

            elif isinstance(node, ast.FunctionDef):
                metrics["number_of_functions"] += 1
                for child in ast.iter_child_nodes(node):
                    _walk_depth(child, depth + 1)

            elif isinstance(node, ast.ClassDef):
                metrics["number_of_classes"] += 1
                for child in ast.iter_child_nodes(node):
                    _walk_depth(child, depth + 1)

            elif isinstance(node, ast.Assign):
                # Count unique assigned variable names
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assign_names.add(target.id)
                for child in ast.iter_child_nodes(node):
                    _walk_depth(child, depth)

            else:
                for child in ast.iter_child_nodes(node):
                    _walk_depth(child, depth)

        for node in ast.iter_child_nodes(tree):
            _walk_depth(node)

        metrics["number_of_variables"] = len(assign_names)

    except SyntaxError as e:
        # Fallback: regex counts
        metrics["syntax_errors"].append(str(e))
        metrics["number_of_loops"] = len(re.findall(r'\b(for|while)\b', code))
        metrics["number_of_conditions"] = len(re.findall(r'\bif\b', code))
        metrics["number_of_variables"] = len(re.findall(r'\b\w+\s*=\s*', code))

    return metrics