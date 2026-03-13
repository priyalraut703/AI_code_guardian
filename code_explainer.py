"""
code_explainer.py
Explains Python code in plain English using rule-based AST analysis.
Falls back gracefully — no external model required for demo.
Optional: swap in a HuggingFace model if GPU/RAM available.
"""

import ast
import re
from typing import Dict, List


def explain_code(code: str) -> Dict:
    """
    Produce a plain-English explanation of the submitted code.
    Returns a dict with: summary, structure, what_it_does, potential_issues.
    """
    explanation = {
        "summary": "",
        "structure": [],
        "what_it_does": [],
        "potential_issues": [],
        "line_count": len(code.splitlines()),
        "parse_success": True,
    }

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        explanation["parse_success"] = False
        explanation["summary"] = f"⚠️ Code has a syntax error and cannot be fully analysed: {e}"
        return explanation

    # ── Structural inventory ──────────────────────────────────────────────────
    imports = []
    functions = []
    classes = []
    assignments = []
    calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [a.name for a in node.names]
            imports.append(f"{module}.{', '.join(names)}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in node.args.args]
            functions.append({"name": node.name, "args": args, "line": node.lineno})
        elif isinstance(node, ast.ClassDef):
            classes.append({"name": node.name, "line": node.lineno})
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assignments.append(t.id)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.append(node.func.attr)

    # ── Build structure list ──────────────────────────────────────────────────
    if imports:
        explanation["structure"].append(
            f"📦 Imports {len(imports)} module(s): {', '.join(set(imports[:5]))}"
        )
    if classes:
        for c in classes:
            explanation["structure"].append(
                f"🏗️ Defines class '{c['name']}' (line {c['line']})"
            )
    if functions:
        for f in functions:
            arg_str = ", ".join(f["args"]) if f["args"] else "no arguments"
            explanation["structure"].append(
                f"🔧 Defines function '{f['name']}({arg_str})' at line {f['line']}"
            )
    if assignments:
        unique_vars = list(set(assignments))[:6]
        explanation["structure"].append(
            f"📝 Assigns variables: {', '.join(unique_vars)}"
        )

    # ── What it does ──────────────────────────────────────────────────────────
    loop_count = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While)))
    cond_count = sum(1 for n in ast.walk(tree) if isinstance(n, ast.If))
    try_count  = sum(1 for n in ast.walk(tree) if isinstance(n, ast.Try))

    if loop_count:
        explanation["what_it_does"].append(
            f"🔁 Contains {loop_count} loop(s) that iterate over data or ranges."
        )
    if cond_count:
        explanation["what_it_does"].append(
            f"🔀 Uses {cond_count} conditional branch(es) to control execution flow."
        )
    if try_count:
        explanation["what_it_does"].append(
            f"🛡️ Includes {try_count} try/except block(s) for error handling."
        )

    # Detect common patterns
    code_lower = code.lower()
    if "requests" in code_lower or "urllib" in code_lower:
        explanation["what_it_does"].append("🌐 Makes HTTP network requests.")
    if "open(" in code_lower:
        explanation["what_it_does"].append("📂 Reads from or writes to files on disk.")
    if "sqlite" in code_lower or "cursor" in code_lower or "execute" in code_lower:
        explanation["what_it_does"].append("🗄️ Interacts with a database.")
    if "class " in code_lower:
        explanation["what_it_does"].append("🏛️ Defines one or more object-oriented classes.")
    if "def " in code_lower:
        explanation["what_it_does"].append("⚙️ Encapsulates logic in reusable functions.")
    if "return" in code_lower:
        explanation["what_it_does"].append("↩️ Returns computed values from functions.")
    if "print(" in code_lower:
        explanation["what_it_does"].append("🖨️ Outputs data to the console.")
    if "argparse" in code_lower or "sys.argv" in code_lower:
        explanation["what_it_does"].append("⌨️ Accepts command-line arguments.")

    # ── Generate natural-language summary ─────────────────────────────────────
    lines = len(code.splitlines())
    fn_names = [f["name"] for f in functions]
    cls_names = [c["name"] for c in classes]

    summary_parts = [f"This is a {lines}-line Python script."]
    if cls_names:
        summary_parts.append(f"It defines the class(es): {', '.join(cls_names)}.")
    if fn_names:
        summary_parts.append(f"It contains function(s): {', '.join(fn_names[:4])}.")
    if loop_count:
        summary_parts.append(f"The code uses {loop_count} loop(s) for iteration.")
    if "requests" in code_lower:
        summary_parts.append("It communicates with external services via HTTP.")
    if "open(" in code_lower:
        summary_parts.append("File I/O operations are performed.")

    explanation["summary"] = " ".join(summary_parts)

    # ── Potential issues highlighted ──────────────────────────────────────────
    if loop_count >= 3:
        explanation["potential_issues"].append(
            "⚠️ Multiple nested loops may indicate O(n²) or worse complexity."
        )
    if not try_count and ("open(" in code_lower or "requests" in code_lower):
        explanation["potential_issues"].append(
            "⚠️ File/network operations without try/except blocks — unhandled exceptions possible."
        )
    if "eval(" in code_lower or "exec(" in code_lower:
        explanation["potential_issues"].append(
            "🚨 eval()/exec() detected — serious security risk."
        )
    if not functions and lines > 50:
        explanation["potential_issues"].append(
            "📐 No functions defined — consider refactoring into reusable functions."
        )

    return explanation
