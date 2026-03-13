"""
bug_detector.py
Detects logical bugs, suspicious patterns, and common coding mistakes.
"""

import ast
import re
from typing import List, Dict


# ── Pattern-based rules (regex) ──────────────────────────────────────────────
REGEX_RULES: List[Dict] = [
    {
        "id": "BUG001",
        "name": "Off-by-one loop",
        "pattern": r"range\s*\(\s*len\s*\(.+?\)\s*\+\s*1\s*\)",
        "severity": "HIGH",
        "message": "Potential off-by-one: iterating beyond list length.",
        "fix": "Use range(len(collection)) without +1 to avoid IndexError.",
    },
    {
        "id": "BUG002",
        "name": "Empty list indexing",
        "pattern": r"\[\s*\]\s*\[",
        "severity": "HIGH",
        "message": "Direct indexing on an empty list literal [] will raise IndexError.",
        "fix": "Check if the list is non-empty before indexing.",
    },
    {
        "id": "BUG003",
        "name": "Mutable default argument",
        "pattern": r"def\s+\w+\s*\(.*=\s*(\[\]|\{\}|\(\))\s*[,)]",
        "severity": "MEDIUM",
        "message": "Mutable default argument (list/dict/set) is shared across calls.",
        "fix": "Use None as default and initialise inside the function body.",
    },
    {
        "id": "BUG004",
        "name": "Bare except clause",
        "pattern": r"except\s*:",
        "severity": "MEDIUM",
        "message": "Bare 'except:' catches ALL exceptions including SystemExit.",
        "fix": "Catch specific exceptions, e.g. except ValueError:",
    },
    {
        "id": "BUG005",
        "name": "String comparison with ==",
        "pattern": r'if\s+\w+\s*==\s*["\']True["\']|if\s+\w+\s*==\s*["\']False["\']',
        "severity": "LOW",
        "message": "Comparing boolean values as strings is incorrect.",
        "fix": "Use the boolean literals True/False directly.",
    },
    {
        "id": "BUG006",
        "name": "Division without zero check",
        "pattern": r"[^=!<>]/\s*\b(?!0\b)\w+",
        "severity": "MEDIUM",
        "message": "Division detected — potential ZeroDivisionError if denominator is 0.",
        "fix": "Add a check: if denominator != 0 before dividing.",
    },
    {
        "id": "BUG007",
        "name": "Shadowing built-in name",
        "pattern": r"\b(list|dict|set|type|id|input|print|len|range|int|str|float)\s*=",
        "severity": "LOW",
        "message": "Variable name shadows a Python built-in.",
        "fix": "Rename the variable to avoid shadowing built-ins.",
    },
    {
        "id": "BUG008",
        "name": "Unused loop variable",
        "pattern": r"for\s+_\w+\s+in\s+",
        "severity": "LOW",
        "message": "Loop variable prefixed with _ but not matching convention exactly.",
        "fix": "Use plain _ for truly unused variables.",
    },
]


def detect_bugs(code: str) -> List[Dict]:
    """
    Run all bug-detection rules against the provided code.
    Returns a list of finding dicts.
    """
    findings: List[Dict] = []
    lines = code.splitlines()

    # ── Regex pass ────────────────────────────────────────────────────────────
    for rule in REGEX_RULES:
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

    # ── AST pass ─────────────────────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        findings.extend(_ast_checks(tree, lines))
    except SyntaxError:
        findings.append(
            {
                "id": "BUG999",
                "name": "Syntax Error",
                "severity": "HIGH",
                "line": 0,
                "code_snippet": "",
                "message": "Code has a syntax error and cannot be fully parsed.",
                "fix": "Fix all syntax errors before analysis.",
            }
        )

    return findings


def _ast_checks(tree: ast.AST, lines: list) -> List[Dict]:
    """AST-based bug checks."""
    issues = []

    for node in ast.walk(tree):
        # Check: comparing with None using == instead of 'is'
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(
                    comp, ast.Constant
                ) and comp.value is None:
                    ln = getattr(node, "lineno", 0)
                    issues.append(
                        {
                            "id": "BUG010",
                            "name": "None comparison with ==",
                            "severity": "LOW",
                            "line": ln,
                            "code_snippet": lines[ln - 1].strip() if ln > 0 and ln <= len(lines) else "",
                            "message": "Use 'is None' or 'is not None' to compare with None.",
                            "fix": "Replace == None with 'is None'.",
                        }
                    )

        # Check: assert statements (stripped in optimised bytecode)
        if isinstance(node, ast.Assert):
            ln = getattr(node, "lineno", 0)
            issues.append(
                {
                    "id": "BUG011",
                    "name": "Assert used for validation",
                    "severity": "MEDIUM",
                    "line": ln,
                    "code_snippet": lines[ln - 1].strip() if ln > 0 and ln <= len(lines) else "",
                    "message": "assert is disabled with -O flag; don't use for production validation.",
                    "fix": "Replace assert with explicit if/raise statements.",
                }
            )

    return issues


def generate_fix(finding: Dict) -> str:
    """Return the suggested fix string for a finding."""
    return finding.get("fix", "Review and refactor the flagged code.")