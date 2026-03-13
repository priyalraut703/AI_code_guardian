"""
report_generator.py
Computes final health scores and builds summary report.
"""

from typing import Dict, List


# ── Score deduction weights ───────────────────────────────────────────────────
BUG_DEDUCTIONS    = {"HIGH": 20, "MEDIUM": 12, "LOW": 5}
SEC_DEDUCTIONS    = {"CRITICAL": 25, "HIGH": 18, "MEDIUM": 10, "LOW": 4}
ENERGY_DEDUCTIONS = {"HIGH": 15, "MEDIUM": 8, "LOW": 3}
COMPLEXITY_PENALTY = {"O(n²)": 10, "O(n³)": 20, "O(n^4) — extremely inefficient": 30}


def compute_scores(
    bug_findings: List[Dict],
    sec_findings: List[Dict],
    energy_findings: List[Dict],
    complexity_result: Dict,
) -> Dict:
    """
    Compute individual and overall code health scores (0-100).

    Returns:
        Dict with bug_score, security_score, performance_score,
        energy_score, overall_score, grade.
    """

    # ── Bug score ─────────────────────────────────────────────────────────────
    bug_score = 100
    for f in bug_findings:
        bug_score -= BUG_DEDUCTIONS.get(f.get("severity", "LOW"), 5)
    bug_score = max(0, bug_score)

    # ── Security score ────────────────────────────────────────────────────────
    sec_score = 100
    for f in sec_findings:
        sec_score -= SEC_DEDUCTIONS.get(f.get("severity", "LOW"), 5)
    sec_score = max(0, sec_score)

    # ── Performance / complexity score ────────────────────────────────────────
    perf_score = 100
    complexity = complexity_result.get("overall_complexity", "O(1)")
    for key, penalty in COMPLEXITY_PENALTY.items():
        if key in complexity:
            perf_score -= penalty
            break
    perf_score = max(0, perf_score)

    # ── Energy score ──────────────────────────────────────────────────────────
    energy_score = 100
    for f in energy_findings:
        energy_score -= ENERGY_DEDUCTIONS.get(f.get("severity", "LOW"), 5)
    energy_score = max(0, energy_score)

    # ── Overall score (weighted average) ──────────────────────────────────────
    overall = int(
        bug_score    * 0.30 +
        sec_score    * 0.30 +
        perf_score   * 0.20 +
        energy_score * 0.20
    )
    overall = max(0, min(100, overall))

    return {
        "bug_score":        bug_score,
        "security_score":   sec_score,
        "performance_score": perf_score,
        "energy_score":     energy_score,
        "overall_score":    overall,
        "grade":            _grade(overall),
        "bug_count":        len(bug_findings),
        "sec_count":        len(sec_findings),
        "energy_count":     len(energy_findings),
    }


def _grade(score: int) -> str:
    """Map numeric score to letter grade."""
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def build_summary(scores: Dict, risk_result: Dict) -> str:
    """Build a human-readable summary paragraph."""
    grade = scores["grade"]
    overall = scores["overall_score"]
    risk = risk_result.get("label", "Unknown")

    parts = [
        f"**Overall Code Quality: {overall}/100 (Grade {grade})**",
        f"ML Risk Assessment: {risk}",
        "",
    ]

    if scores["bug_count"]:
        parts.append(f"- 🐞 {scores['bug_count']} bug issue(s) found (score: {scores['bug_score']}/100)")
    else:
        parts.append("- ✅ No bugs detected")

    if scores["sec_count"]:
        parts.append(f"- 🔐 {scores['sec_count']} security issue(s) found (score: {scores['security_score']}/100)")
    else:
        parts.append("- ✅ No security vulnerabilities detected")

    parts.append(f"- ⚡ Performance score: {scores['performance_score']}/100")
    parts.append(f"- 🌱 Energy efficiency: {scores['energy_score']}/100")

    return "\n".join(parts)