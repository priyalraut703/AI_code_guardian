"""
energy_analyzer.py
Detects energy-inefficient coding patterns in Python source code.
Focuses on patterns that waste CPU cycles, memory, and I/O.
"""

import re
import ast
from typing import List, Dict


ENERGY_RULES: List[Dict] = [
    {
        "id": "ENE001",
        "name": "Deep nested loops",
        "pattern": None,  # Handled by AST check
        "severity": "HIGH",
        "message": "Deeply nested loops (3+ levels) cause excessive CPU usage.",
        "fix": "Flatten loops with list comprehensions, numpy vectorisation, or algorithmic improvements.",
    },
    {
        "id": "ENE002",
        "name": "String concatenation in loop",
        "pattern": r"for\s+.*:\s*\n.*\+=\s*['\"]",
        "severity": "MEDIUM",
        "message": "String += inside a loop creates many intermediate string objects.",
        "fix": "Collect strings in a list and use ''.join(parts) after the loop.",
    },
    {
        "id": "ENE003",
        "name": "Large list comprehension without generator",
        "pattern": r"\[.+\s+for\s+.+\s+in\s+range\s*\(\s*[1-9]\d{4,}",
        "severity": "MEDIUM",
        "message": "Large list comprehension allocates all items in memory at once.",
        "fix": "Use a generator expression (...) instead of [...] when you only iterate once.",
    },
    {
        "id": "ENE004",
        "name": "Redundant recomputation in loop",
        "pattern": r"for\s+\w+\s+in\s+range.*:\n(?:\s+.*\n)*?\s+\w+\s*=\s*len\s*\(",
        "severity": "MEDIUM",
        "message": "len() called inside a loop — result is constant, compute once.",
        "fix": "Assign n = len(collection) before the loop.",
    },
    {
        "id": "ENE005",
        "name": "Unnecessary global variable access",
        "pattern": r"\bglobal\b",
        "severity": "LOW",
        "message": "Global variables accessed inside functions slow down lookups.",
        "fix": "Pass values as function arguments or use local caching.",
    },
    {
        "id": "ENE006",
        "name": "sleep() in hot path",
        "pattern": r"time\.sleep\s*\(",
        "severity": "LOW",
        "message": "Busy-wait or sleep in computational code wastes CPU time.",
        "fix": "Replace with event-driven or callback-based approaches.",
    },
    {
        "id": "ENE007",
        "name": "Repeated file I/O in loop",
        "pattern": r"for\s+.+:\n(?:\s+.*\n)*?\s+open\s*\(",
        "severity": "HIGH",
        "message": "File open/close inside a loop is extremely I/O-intensive.",
        "fix": "Open files once outside the loop and pass the handle in.",
    },
    {
        "id": "ENE008",
        "name": "Unnecessary list copy",
        "pattern": r"list\s*\(\s*\w+\s*\)",
        "severity": "LOW",
        "message": "Unnecessary list copy increases memory usage.",
        "fix": "Use the original list directly if you don't need to modify it.",
    },
    {
        "id": "ENE009",
        "name": "Print inside tight loop",
        "pattern": r"for\s+.+:\n(?:\s+.*\n)*?\s+print\s*\(",
        "severity": "MEDIUM",
        "message": "print() inside loops causes repeated I/O flush overhead.",
        "fix": "Buffer output and print once after the loop, or use logging.",
    },
    {
        "id": "ENE010",
        "name": "Inefficient membership test on list",
        "pattern": r"\bif\s+\w+\s+in\s+\[",
        "severity": "LOW",
        "message": "Membership test on a list literal is O(n); use a set for O(1).",
        "fix": "Replace list literal with a set: if x in {a, b, c}",
    },
]


def analyse_energy(code: str) -> List[Dict]:
    """
    Scan code for energy-inefficient patterns.
    Returns a list of energy issue findings.
    """
    findings: List[Dict] = []
    lines = code.splitlines()

    # ── Regex-based checks ─────────────────────────────────────────────────
    for rule in ENERGY_RULES:
        if rule["pattern"] is None:
            continue  # Handled separately via AST
        for i, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line):
                findings.append(
                    {
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "line": i,
                        "code_snippet": line.strip(),
                        "message": rule["message"],
                        "fix": rule["fix"],
                    }
                )

    # ── AST check: deep nesting ────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        findings.extend(_ast_energy_checks(tree, lines))
    except SyntaxError:
        pass

    return findings


def _ast_energy_checks(tree: ast.AST, lines: list) -> List[Dict]:
    """AST-based energy efficiency checks."""
    issues = []

    def _loop_depth(node, depth=0):
        """Return max loop nesting depth under node."""
        if isinstance(node, (ast.For, ast.While)):
            depth += 1
        max_d = depth
        for child in ast.iter_child_nodes(node):
            max_d = max(max_d, _loop_depth(child, depth))
        return max_d

    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.While)):
            d = _loop_depth(node)
            if d >= 3:
                ln = getattr(node, "lineno", 0)
                issues.append(
                    {
                        "id": "ENE001",
                        "name": "Deep nested loops",
                        "severity": "HIGH",
                        "line": ln,
                        "code_snippet": lines[ln - 1].strip() if 0 < ln <= len(lines) else "",
                        "message": f"Loop nesting depth {d} — excessive CPU cycles.",
                        "fix": "Flatten loops with vectorisation, numpy, or algorithmic refactoring.",
                    }
                )

    return issues


def energy_score(findings: List[Dict]) -> int:
    """Compute a 0-100 energy score."""
    deductions = {"HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100
    for f in findings:
        score -= deductions.get(f["severity"], 5)
    return max(0, score)