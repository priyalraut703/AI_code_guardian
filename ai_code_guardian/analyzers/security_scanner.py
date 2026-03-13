"""
security_scanner.py
Detects security vulnerabilities using pattern matching.
Covers: hardcoded credentials, SQL injection, unsafe file ops, shell injection, etc.
"""

import re
from typing import List, Dict


SECURITY_RULES: List[Dict] = [
    # ── Credentials ──────────────────────────────────────────────────────────
    {
        "id": "SEC001",
        "name": "Hardcoded Password",
        "pattern": r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
        "severity": "CRITICAL",
        "category": "Credentials",
        "message": "Hardcoded password detected in source code.",
        "fix": "Use environment variables or a secrets manager (e.g. os.getenv('PASSWORD')).",
    },
    {
        "id": "SEC002",
        "name": "Hardcoded API Key",
        "pattern": r'(?i)(api_key|apikey|api_secret|access_token|secret_key)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']',
        "severity": "CRITICAL",
        "category": "Credentials",
        "message": "Hardcoded API key or secret detected.",
        "fix": "Move secrets to environment variables and load with os.getenv().",
    },
    {
        "id": "SEC003",
        "name": "Hardcoded Private Key",
        "pattern": r'-----BEGIN\s+(RSA|EC|OPENSSH|DSA)?\s*PRIVATE KEY-----',
        "severity": "CRITICAL",
        "category": "Credentials",
        "message": "Private key material embedded in source code.",
        "fix": "Store keys in secure vaults; never commit to version control.",
    },
    # ── SQL Injection ─────────────────────────────────────────────────────────
    {
        "id": "SEC010",
        "name": "SQL Injection Risk (string format)",
        "pattern": r'(execute|cursor\.execute)\s*\(\s*["\'].*(SELECT|INSERT|UPDATE|DELETE).*%s.*["\']',
        "severity": "HIGH",
        "category": "Injection",
        "message": "String-formatted SQL query — susceptible to SQL injection.",
        "fix": "Use parameterised queries: cursor.execute(query, (params,))",
    },
    {
        "id": "SEC011",
        "name": "SQL Injection Risk (f-string)",
        "pattern": r'(execute|cursor\.execute)\s*\(\s*f["\'].*(SELECT|INSERT|UPDATE|DELETE)',
        "severity": "HIGH",
        "category": "Injection",
        "message": "F-string SQL query — user input can manipulate the query.",
        "fix": "Use parameterised queries instead of f-strings for SQL.",
    },
    # ── Shell / Command Injection ─────────────────────────────────────────────
    {
        "id": "SEC020",
        "name": "Shell Injection via os.system",
        "pattern": r'os\.system\s*\(',
        "severity": "HIGH",
        "category": "Injection",
        "message": "os.system() can execute arbitrary shell commands.",
        "fix": "Use subprocess.run() with a list of arguments and shell=False.",
    },
    {
        "id": "SEC021",
        "name": "Shell=True in subprocess",
        "pattern": r'subprocess\.\w+\(.*shell\s*=\s*True',
        "severity": "HIGH",
        "category": "Injection",
        "message": "shell=True makes subprocess vulnerable to shell injection.",
        "fix": "Pass command as a list and set shell=False.",
    },
    {
        "id": "SEC022",
        "name": "Dangerous eval() usage",
        "pattern": r'\beval\s*\(',
        "severity": "CRITICAL",
        "category": "Code Execution",
        "message": "eval() executes arbitrary code — extreme injection risk.",
        "fix": "Remove eval(); use ast.literal_eval() for safe data parsing.",
    },
    {
        "id": "SEC023",
        "name": "Dangerous exec() usage",
        "pattern": r'\bexec\s*\(',
        "severity": "CRITICAL",
        "category": "Code Execution",
        "message": "exec() executes arbitrary Python code.",
        "fix": "Avoid exec(); refactor to use explicit function calls.",
    },
    # ── Unsafe File Operations ────────────────────────────────────────────────
    {
        "id": "SEC030",
        "name": "Unsafe file path (user input)",
        "pattern": r'open\s*\(\s*(input|request\.|user_input)',
        "severity": "HIGH",
        "category": "File Operations",
        "message": "File opened with user-controlled path — path traversal risk.",
        "fix": "Sanitise file paths with os.path.basename() and restrict to allowed dirs.",
    },
    {
        "id": "SEC031",
        "name": "Pickle deserialization",
        "pattern": r'pickle\.loads?\s*\(',
        "severity": "HIGH",
        "category": "Deserialization",
        "message": "pickle.load() on untrusted data can execute arbitrary code.",
        "fix": "Use json or a safe serialization format for untrusted data.",
    },
    # ── Crypto / SSL ──────────────────────────────────────────────────────────
    {
        "id": "SEC040",
        "name": "SSL verification disabled",
        "pattern": r'verify\s*=\s*False',
        "severity": "MEDIUM",
        "category": "Crypto",
        "message": "SSL certificate verification is disabled.",
        "fix": "Always use verify=True (default) or provide a CA bundle path.",
    },
    {
        "id": "SEC041",
        "name": "Weak hash algorithm (MD5/SHA1)",
        "pattern": r'hashlib\.(md5|sha1)\s*\(',
        "severity": "MEDIUM",
        "category": "Crypto",
        "message": "MD5/SHA1 are cryptographically broken.",
        "fix": "Use hashlib.sha256() or stronger algorithms.",
    },
    # ── Debug / Dev leftovers ─────────────────────────────────────────────────
    {
        "id": "SEC050",
        "name": "Debug mode enabled",
        "pattern": r'(?i)debug\s*=\s*True',
        "severity": "MEDIUM",
        "category": "Configuration",
        "message": "Debug mode exposes stack traces and internal details.",
        "fix": "Set debug=False in production; use environment variables.",
    },
]


def scan_security(code: str) -> List[Dict]:
    """
    Scan code for security vulnerabilities.
    Returns a list of security findings.
    """
    findings: List[Dict] = []
    lines = code.splitlines()

    for rule in SECURITY_RULES:
        for i, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line):
                findings.append(
                    {
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "line": i,
                        "code_snippet": line.strip(),
                        "message": rule["message"],
                        "fix": rule["fix"],
                    }
                )

    return findings


def security_score(findings: List[Dict]) -> int:
    """Compute a 0-100 security score based on findings."""
    deductions = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100
    for f in findings:
        score -= deductions.get(f["severity"], 5)
    return max(0, score)