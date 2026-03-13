"""
app.py — AI Code Guardian
Main Streamlit dashboard. Run with: streamlit run app.py
"""

import sys
import os

# Ensure local packages resolve correctly when run from any working directory
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

from analyzers.bug_detector       import detect_bugs
from analyzers.security_scanner   import scan_security
from analyzers.complexity_analyzer import analyse_complexity, get_complexity_recommendations
from analyzers.energy_analyzer    import analyse_energy
from ml_models.risk_classifier    import predict_risk
from ai_engine.code_explainer     import explain_code
from utils.code_parser            import parse_code
from utils.report_generator       import compute_scores, build_summary


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Code Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS — dark cyber aesthetic ─────────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Space Grotesk', sans-serif;
    }

    /* Dark background */
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0d1b2a 50%, #0a1628 100%);
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1b2a 0%, #091525 100%);
        border-right: 1px solid #1e3a5f;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: rgba(13,27,42,0.8);
        border-radius: 12px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        color: #8bb8d4;
        font-weight: 600;
        font-size: 13px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #1e3a5f, #0e4d8a) !important;
        color: #e0f0ff !important;
    }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #0d1b2a, #102035);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 16px;
    }
    [data-testid="metric-container"] label {
        color: #7ab3d4 !important;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #e0f0ff !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 2rem !important;
    }

    /* Code areas */
    .stTextArea textarea {
        background: #07101d !important;
        color: #a8d4ff !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important;
        border: 1px solid #1e3a5f !important;
        border-radius: 8px !important;
    }

    /* Expanders */
    .streamlit-expanderHeader {
        background: #0d1b2a !important;
        border: 1px solid #1e3a5f !important;
        border-radius: 8px !important;
        color: #8bb8d4 !important;
    }

    /* Finding cards */
    .finding-card {
        background: linear-gradient(135deg, #0d1b2a, #0a1525);
        border-left: 4px solid;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 8px 0;
        font-family: 'Space Grotesk', sans-serif;
    }
    .finding-card.critical { border-color: #ff2d55; }
    .finding-card.high     { border-color: #ff6b35; }
    .finding-card.medium   { border-color: #ffd60a; }
    .finding-card.low      { border-color: #30d158; }

    /* Score badges */
    .score-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 14px;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Headers */
    h1, h2, h3 { color: #e0f0ff !important; }

    /* Dividers */
    hr { border-color: #1e3a5f !important; }

    /* Info/warning/error boxes */
    .stAlert { border-radius: 8px; }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #1e3a5f, #0e4d8a);
        color: #e0f0ff;
        border: 1px solid #2a5a8f;
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #2a5a8f, #1460a8);
        border-color: #4a8abf;
        transform: translateY(-1px);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        """
        <div style='text-align:center; padding: 20px 0;'>
            <div style='font-size:48px;'>🛡️</div>
            <h2 style='color:#e0f0ff; margin:8px 0 4px; font-family:"Space Grotesk",sans-serif;'>
                AI Code Guardian
            </h2>
            <p style='color:#4a8abf; font-size:12px; margin:0;'>
                Intelligent Code Analysis Platform
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown("### 📖 How to Use")
    st.markdown(
        """
        1. **Paste** your Python code in the **Code Input** tab.
        2. Click **🔍 Analyse Code** to run all checks.
        3. Navigate tabs to explore results.
        4. Review the **Code Health Dashboard** for an overview.
        """,
        unsafe_allow_html=False,
    )

    st.divider()

    st.markdown("### 🔬 Analysis Modules")
    st.markdown(
        """
        - 🐞 **Bug Detection** — logical issues
        - 🔐 **Security Scan** — vulnerabilities
        - ⚡ **Complexity** — Big-O estimation
        - 🌱 **Energy** — efficiency patterns
        - 🤖 **ML Risk** — RandomForest model
        - 💡 **AI Explain** — plain English
        - 📊 **Dashboard** — health scores
        """
    )

    st.divider()
    st.caption("v1.0 · Built for Hackathon Demo")
    st.caption("Powered by Python · Streamlit · sklearn")


# ── Default sample code ───────────────────────────────────────────────────────
SAMPLE_CODE = '''\
import os
import sqlite3

# Hardcoded credentials — security risk
password = "admin123"
api_key  = "sk-abc123XYZ789secretkey"

def fetch_user(username):
    """Fetch user from DB — SQL injection risk."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Unsafe: f-string in SQL
    cursor.execute(f"SELECT * FROM users WHERE name = \\'{username}\\'")
    return cursor.fetchall()

def find_duplicates(data):
    """O(n²) duplicate finder."""
    duplicates = []
    for i in range(len(data)):
        for j in range(len(data)):          # nested loop
            for k in range(len(data)):      # triple nested — O(n³)
                if i != j and data[i] == data[j]:
                    duplicates.append(data[i])
    return duplicates

def risky_divide(a, b):
    """No zero check — ZeroDivisionError risk."""
    result = a / b
    return result

def process_items(items=[]):   # mutable default arg bug
    results = ""
    for item in items:
        results += str(item)   # string concat in loop
    print(results)
    return results

# eval usage — critical security risk
user_input = input("Enter expression: ")
output = eval(user_input)
'''

# ── Session state initialisation ─────────────────────────────────────────────
if "analysed" not in st.session_state:
    st.session_state.analysed       = False
    st.session_state.bugs           = []
    st.session_state.security       = []
    st.session_state.complexity     = {}
    st.session_state.energy         = []
    st.session_state.risk           = {}
    st.session_state.explanation    = {}
    st.session_state.scores         = {}
    st.session_state.metrics        = {}
    st.session_state.code           = SAMPLE_CODE


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style='padding: 24px 0 16px;'>
        <h1 style='margin:0; font-size:2.4rem; font-family:"Space Grotesk",sans-serif;
                   background: linear-gradient(90deg,#4fc3f7,#29b6f6,#0288d1);
                   -webkit-background-clip:text; -webkit-text-fill-color:transparent;'>
            🛡️ AI Code Guardian
        </h1>
        <p style='color:#4a8abf; margin:4px 0 0; font-size:1rem;'>
            Intelligent Code Analysis Platform · Bug Detection · Security · Performance · AI Insights
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tabs = st.tabs(
    [
        "📝 Code Input",
        "🐞 Bug Detection",
        "🔐 Security",
        "⚡ Complexity",
        "🌱 Energy",
        "🤖 ML Risk",
        "💡 AI Explain",
        "📊 Dashboard",
    ]
)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Code Input
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[0]:
    st.markdown("### 📝 Paste Your Python Code")

    col_info1, col_info2, col_info3 = st.columns(3)
    with col_info1:
        st.info("🐍 Python code analysis")
    with col_info2:
        st.info("📏 Any length supported")
    with col_info3:
        st.info("⚡ Real-time analysis")

    st.session_state.code = st.text_area(
        "Paste Python code here:",
        value=st.session_state.code,
        height=380,
        label_visibility="collapsed",
        placeholder="# Paste your Python code here...",
    )

    col_btn1, col_btn2, col_btn3 = st.columns([2, 1, 1])
    with col_btn1:
        analyse_clicked = st.button(
            "🔍 Analyse Code", use_container_width=True, type="primary"
        )
    with col_btn2:
        if st.button("📋 Load Sample", use_container_width=True):
            st.session_state.code = SAMPLE_CODE
            st.rerun()
    with col_btn3:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.code = ""
            st.session_state.analysed = False
            st.rerun()

    # ── Run analysis ──────────────────────────────────────────────────────────
    if analyse_clicked and st.session_state.code.strip():
        with st.spinner("🔄 Running AI analysis pipeline..."):
            code = st.session_state.code

            progress = st.progress(0, text="Parsing code structure…")
            st.session_state.metrics    = parse_code(code)
            progress.progress(15, text="Detecting bugs…")
            st.session_state.bugs       = detect_bugs(code)
            progress.progress(30, text="Scanning security…")
            st.session_state.security   = scan_security(code)
            progress.progress(50, text="Analysing complexity…")
            st.session_state.complexity = analyse_complexity(code)
            progress.progress(65, text="Checking energy efficiency…")
            st.session_state.energy     = analyse_energy(code)
            progress.progress(78, text="Running ML risk model…")
            st.session_state.risk       = predict_risk(st.session_state.metrics)
            progress.progress(90, text="Generating AI explanation…")
            st.session_state.explanation = explain_code(code)
            progress.progress(100, text="Computing health scores…")
            st.session_state.scores     = compute_scores(
                st.session_state.bugs,
                st.session_state.security,
                st.session_state.energy,
                st.session_state.complexity,
            )
            st.session_state.analysed   = True
            progress.empty()

        st.success("✅ Analysis complete! Navigate the tabs to explore results.")

    elif analyse_clicked:
        st.warning("⚠️ Please paste some code before analysing.")

    # ── Quick stats after analysis ────────────────────────────────────────────
    if st.session_state.analysed:
        st.divider()
        st.markdown("#### 📊 Quick Overview")
        m = st.session_state.metrics
        s = st.session_state.scores

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Lines", m.get("number_of_lines", 0))
        c2.metric("🐞 Bugs",     len(st.session_state.bugs))
        c3.metric("🔐 Security", len(st.session_state.security))
        c4.metric("🌱 Energy",   len(st.session_state.energy))
        c5.metric("⭐ Score",    f"{s.get('overall_score',0)}/100")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Bug Detection
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[1]:
    st.markdown("### 🐞 Bug Detection Report")

    if not st.session_state.analysed:
        st.info("👆 Paste code and click **Analyse Code** in the Code Input tab first.")
    else:
        bugs = st.session_state.bugs
        if not bugs:
            st.success("✅ No bugs detected — code looks clean!")
        else:
            st.error(f"🚨 {len(bugs)} issue(s) found")

            sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            bugs_sorted = sorted(bugs, key=lambda x: sev_order.get(x.get("severity", "LOW"), 3))

            sev_colors = {
                "HIGH":   ("#ff6b35", "high"),
                "MEDIUM": ("#ffd60a", "medium"),
                "LOW":    ("#30d158", "low"),
            }

            for bug in bugs_sorted:
                sev = bug.get("severity", "LOW")
                color, css_class = sev_colors.get(sev, ("#888", "low"))

                st.markdown(
                    f"""
                    <div class="finding-card {css_class}">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong style="color:#e0f0ff; font-size:15px;">{bug['id']} · {bug['name']}</strong>
                            <span class="score-badge" style="background:{color}22; color:{color}; border:1px solid {color}55;">
                                {sev}
                            </span>
                        </div>
                        <p style="color:#8bb8d4; margin:6px 0 4px;">📍 Line {bug.get('line',0)}</p>
                        <code style="background:#07101d; color:#a8d4ff; padding:4px 8px; border-radius:4px;
                                     font-size:12px; display:block; margin:6px 0;">
                            {bug.get('code_snippet','').replace('<','&lt;').replace('>','&gt;')}
                        </code>
                        <p style="color:#c0d8f0; margin:4px 0;">⚠️ {bug['message']}</p>
                        <p style="color:#4fc3f7; margin:4px 0;">💡 <em>{bug['fix']}</em></p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Severity breakdown chart
            st.divider()
            st.markdown("#### Severity Breakdown")
            df_bugs = pd.DataFrame(bugs)
            sev_counts = df_bugs["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            fig_bugs = px.bar(
                sev_counts,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map={"HIGH": "#ff6b35", "MEDIUM": "#ffd60a", "LOW": "#30d158"},
                template="plotly_dark",
                title="Bug Severity Distribution",
            )
            fig_bugs.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(13,27,42,0.6)",
                font_color="#8bb8d4",
            )
            st.plotly_chart(fig_bugs, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — Security
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[2]:
    st.markdown("### 🔐 Security Vulnerability Report")

    if not st.session_state.analysed:
        st.info("👆 Run analysis first.")
    else:
        sec = st.session_state.security
        sec_score = st.session_state.scores.get("security_score", 100)

        col_s1, col_s2 = st.columns(2)
        col_s1.metric("Security Score", f"{sec_score}/100")
        col_s2.metric("Vulnerabilities Found", len(sec))

        if not sec:
            st.success("✅ No security vulnerabilities detected.")
        else:
            sev_colors = {
                "CRITICAL": ("#ff2d55", "critical"),
                "HIGH":     ("#ff6b35", "high"),
                "MEDIUM":   ("#ffd60a", "medium"),
                "LOW":      ("#30d158", "low"),
            }
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sec_sorted = sorted(sec, key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))

            for item in sec_sorted:
                sev = item.get("severity", "LOW")
                color, css_class = sev_colors.get(sev, ("#888", "low"))
                st.markdown(
                    f"""
                    <div class="finding-card {css_class}">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong style="color:#e0f0ff;">{item['id']} · {item['name']}</strong>
                            <span class="score-badge" style="background:{color}22; color:{color}; border:1px solid {color}55;">
                                {sev} · {item.get('category','General')}
                            </span>
                        </div>
                        <p style="color:#8bb8d4; margin:4px 0;">📍 Line {item.get('line',0)}</p>
                        <code style="background:#07101d; color:#ffa07a; padding:4px 8px;
                                     border-radius:4px; font-size:12px; display:block; margin:6px 0;">
                            {item.get('code_snippet','').replace('<','&lt;').replace('>','&gt;')}
                        </code>
                        <p style="color:#c0d8f0; margin:4px 0;">⚠️ {item['message']}</p>
                        <p style="color:#4fc3f7; margin:4px 0;">💡 <em>{item['fix']}</em></p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Category chart
            st.divider()
            df_sec = pd.DataFrame(sec)
            cat_counts = df_sec["category"].value_counts().reset_index()
            cat_counts.columns = ["Category", "Count"]
            fig_sec = px.pie(
                cat_counts,
                names="Category",
                values="Count",
                hole=0.45,
                template="plotly_dark",
                title="Vulnerability Categories",
                color_discrete_sequence=px.colors.sequential.Blues_r,
            )
            fig_sec.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#8bb8d4",
            )
            st.plotly_chart(fig_sec, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Complexity
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[3]:
    st.markdown("### ⚡ Time Complexity Analysis")

    if not st.session_state.analysed:
        st.info("👆 Run analysis first.")
    else:
        comp = st.session_state.complexity

        c1, c2, c3 = st.columns(3)
        c1.metric("Overall Complexity",    comp.get("overall_complexity", "—"))
        c2.metric("Max Nesting Depth",     comp.get("max_nesting_depth", 0))
        c3.metric("Total Loops",           comp.get("loop_count", 0))

        st.divider()
        recs = get_complexity_recommendations(comp)
        st.markdown("#### 💡 Recommendations")
        for r in recs:
            st.markdown(f"- {r}")

        fn_complexities = comp.get("function_complexities", [])
        if fn_complexities:
            st.divider()
            st.markdown("#### 🔧 Function-Level Complexity")
            df_fn = pd.DataFrame(fn_complexities)
            df_fn_display = df_fn[["name", "line", "complexity", "loop_count", "nesting_depth"]]
            df_fn_display.columns = ["Function", "Line", "Complexity", "Loops", "Nesting Depth"]
            st.dataframe(df_fn_display, use_container_width=True)

        # Complexity details
        st.divider()
        st.markdown("#### 📋 Analysis Details")
        for detail in comp.get("details", []):
            st.markdown(f"- {detail}")

        # Visual: nesting depth chart
        depth = comp.get("max_nesting_depth", 0)
        depths = ["O(1)", "O(n)", "O(n²)", "O(n³)", "O(n⁴)+"]
        values = [100, 80, 55, 30, 10]
        colors = ["#30d158", "#34aadc", "#ffd60a", "#ff6b35", "#ff2d55"]

        fig_comp = go.Figure(
            go.Bar(
                x=depths,
                y=values,
                marker_color=colors,
                text=[f"{'← Your Code' if i == min(depth, 4) else ''}" for i in range(5)],
                textposition="outside",
            )
        )
        # Highlight current complexity
        highlight_idx = min(depth, 4)
        fig_comp.add_shape(
            type="rect",
            x0=highlight_idx - 0.45, x1=highlight_idx + 0.45,
            y0=0, y1=values[highlight_idx] + 8,
            fillcolor="rgba(79,195,247,0.15)",
            line=dict(color="#4fc3f7", width=2),
        )
        fig_comp.update_layout(
            title="Complexity Scale — Your Code Highlighted",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(13,27,42,0.6)",
            font_color="#8bb8d4",
            yaxis_title="Efficiency Score",
        )
        st.plotly_chart(fig_comp, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — Energy
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[4]:
    st.markdown("### 🌱 Energy Efficiency Analysis")

    if not st.session_state.analysed:
        st.info("👆 Run analysis first.")
    else:
        energy = st.session_state.energy
        e_score = st.session_state.scores.get("energy_score", 100)

        col_e1, col_e2 = st.columns(2)
        col_e1.metric("Energy Score", f"{e_score}/100")
        col_e2.metric("Issues Found", len(energy))

        if not energy:
            st.success("✅ No major energy inefficiency patterns detected. Green code! 🌿")
        else:
            sev_colors = {
                "HIGH":   ("#ff6b35", "high"),
                "MEDIUM": ("#ffd60a", "medium"),
                "LOW":    ("#30d158", "low"),
            }
            for item in energy:
                sev = item.get("severity", "LOW")
                color, css_class = sev_colors.get(sev, ("#888", "low"))
                st.markdown(
                    f"""
                    <div class="finding-card {css_class}">
                        <strong style="color:#e0f0ff;">{item['id']} · {item['name']}</strong>
                        <span class="score-badge" style="background:{color}22; color:{color};
                              border:1px solid {color}55; margin-left:8px;">{sev}</span>
                        <p style="color:#8bb8d4; margin:4px 0;">📍 Line {item.get('line',0)}</p>
                        <code style="background:#07101d; color:#a8d4ff; padding:4px 8px;
                                     border-radius:4px; font-size:12px; display:block; margin:6px 0;">
                            {item.get('code_snippet','').replace('<','&lt;').replace('>','&gt;')}
                        </code>
                        <p style="color:#c0d8f0; margin:4px 0;">⚠️ {item['message']}</p>
                        <p style="color:#4fc3f7; margin:4px 0;">💡 <em>{item['fix']}</em></p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Energy meter gauge
        fig_energy = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=e_score,
                title={"text": "Energy Efficiency Score", "font": {"color": "#8bb8d4"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#4a8abf"},
                    "bar":  {"color": "#30d158" if e_score >= 70 else "#ffd60a" if e_score >= 40 else "#ff2d55"},
                    "steps": [
                        {"range": [0, 40],   "color": "rgba(255,45,85,0.15)"},
                        {"range": [40, 70],  "color": "rgba(255,214,10,0.15)"},
                        {"range": [70, 100], "color": "rgba(48,209,88,0.15)"},
                    ],
                    "threshold": {
                        "line": {"color": "#4fc3f7", "width": 3},
                        "thickness": 0.75,
                        "value": e_score,
                    },
                },
                number={"suffix": "/100", "font": {"color": "#e0f0ff"}},
            )
        )
        fig_energy.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#8bb8d4",
            height=300,
        )
        st.plotly_chart(fig_energy, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 6 — ML Risk
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[5]:
    st.markdown("### 🤖 ML Risk Prediction")

    if not st.session_state.analysed:
        st.info("👆 Run analysis first.")
    else:
        risk = st.session_state.risk
        metrics = st.session_state.metrics

        # Risk badge
        label_color = risk.get("color", "#888")
        st.markdown(
            f"""
            <div style="text-align:center; padding:24px; background:linear-gradient(135deg,#0d1b2a,#102035);
                        border:2px solid {label_color}44; border-radius:16px; margin:16px 0;">
                <div style="font-size:3rem; margin-bottom:8px;">🤖</div>
                <div style="font-size:2rem; font-weight:700; color:{label_color}; font-family:'JetBrains Mono',monospace;">
                    {risk.get('label','—')}
                </div>
                <p style="color:#8bb8d4; margin-top:8px;">RandomForest prediction based on code metrics</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Probability bars
        st.markdown("#### Risk Probability Distribution")
        proba_data = {
            "Risk Level": ["🟢 Low Risk", "🟡 Medium Risk", "🔴 High Risk"],
            "Probability (%)": [
                risk.get("probability_low", 0),
                risk.get("probability_medium", 0),
                risk.get("probability_high", 0),
            ],
        }
        df_proba = pd.DataFrame(proba_data)
        fig_proba = px.bar(
            df_proba,
            x="Risk Level",
            y="Probability (%)",
            color="Risk Level",
            color_discrete_map={
                "🟢 Low Risk":    "#30d158",
                "🟡 Medium Risk": "#ffd60a",
                "🔴 High Risk":   "#ff2d55",
            },
            template="plotly_dark",
            title="Model Confidence per Class",
            text="Probability (%)",
        )
        fig_proba.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
        fig_proba.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(13,27,42,0.6)",
            font_color="#8bb8d4",
            showlegend=False,
        )
        st.plotly_chart(fig_proba, use_container_width=True)

        # Feature importances
        st.divider()
        st.markdown("#### 🔍 Feature Importances")
        fi = risk.get("feature_importances", {})
        if fi:
            df_fi = pd.DataFrame(
                {"Feature": list(fi.keys()), "Importance": list(fi.values())}
            ).sort_values("Importance", ascending=True)
            fig_fi = px.bar(
                df_fi,
                x="Importance",
                y="Feature",
                orientation="h",
                template="plotly_dark",
                color="Importance",
                color_continuous_scale="Blues",
                title="What Drives the Risk Score",
            )
            fig_fi.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(13,27,42,0.6)",
                font_color="#8bb8d4",
            )
            st.plotly_chart(fig_fi, use_container_width=True)

        # Code metrics used
        st.divider()
        st.markdown("#### 📏 Code Metrics Used for Prediction")
        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("Lines of Code",   metrics.get("number_of_lines", 0))
        col_m1.metric("Functions",       metrics.get("number_of_functions", 0))
        col_m2.metric("Loops",           metrics.get("number_of_loops", 0))
        col_m2.metric("Conditions",      metrics.get("number_of_conditions", 0))
        col_m3.metric("Variables",       metrics.get("number_of_variables", 0))
        col_m3.metric("Max Nesting",     metrics.get("max_nesting_depth", 0))


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 7 — AI Explain
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[6]:
    st.markdown("### 💡 AI Code Explanation")

    if not st.session_state.analysed:
        st.info("👆 Run analysis first.")
    else:
        exp = st.session_state.explanation

        st.markdown("#### 📖 Summary")
        st.markdown(
            f"""
            <div style="background:linear-gradient(135deg,#0d1b2a,#102035); border:1px solid #1e3a5f;
                        border-radius:12px; padding:20px; font-size:15px; color:#c0d8f0; line-height:1.7;">
                {exp.get('summary','No summary available.')}
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.divider()

        col_exp1, col_exp2 = st.columns(2)

        with col_exp1:
            st.markdown("#### 🏗️ Code Structure")
            for item in exp.get("structure", ["—"]):
                st.markdown(f"- {item}")

        with col_exp2:
            st.markdown("#### ⚙️ What It Does")
            for item in exp.get("what_it_does", ["—"]):
                st.markdown(f"- {item}")

        issues = exp.get("potential_issues", [])
        if issues:
            st.divider()
            st.markdown("#### ⚠️ Potential Issues Highlighted")
            for issue in issues:
                st.warning(issue)
        else:
            st.divider()
            st.success("✅ No major structural issues highlighted.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 8 — Code Health Dashboard
# ═══════════════════════════════════════════════════════════════════════════════
with tabs[7]:
    st.markdown("### 📊 Code Health Dashboard")

    if not st.session_state.analysed:
        st.info("👆 Run analysis first to see the full health dashboard.")
    else:
        scores = st.session_state.scores
        risk   = st.session_state.risk

        # Summary banner
        summary_md = build_summary(scores, risk)
        st.markdown(
            f"""
            <div style="background:linear-gradient(135deg,#0d1b2a,#0a1525);
                        border:1px solid #1e3a5f; border-radius:12px; padding:20px; margin-bottom:16px;">
                {summary_md.replace(chr(10),'<br>')}
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Score metrics row
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🐞 Bug Score",         f"{scores['bug_score']}/100")
        col2.metric("🔐 Security",          f"{scores['security_score']}/100")
        col3.metric("⚡ Performance",        f"{scores['performance_score']}/100")
        col4.metric("🌱 Energy",            f"{scores['energy_score']}/100")
        col5.metric("⭐ Overall",           f"{scores['overall_score']}/100")

        st.divider()

        # ── Row 1: Bar chart + Gauge ──────────────────────────────────────────
        chart_col, gauge_col = st.columns([3, 2])

        with chart_col:
            categories = ["Bug Score", "Security", "Performance", "Energy Efficiency"]
            values = [
                scores["bug_score"],
                scores["security_score"],
                scores["performance_score"],
                scores["energy_score"],
            ]
            bar_colors = [
                "#30d158" if v >= 70 else "#ffd60a" if v >= 40 else "#ff2d55"
                for v in values
            ]

            fig_bar = go.Figure(
                go.Bar(
                    x=categories,
                    y=values,
                    marker_color=bar_colors,
                    text=[f"{v}" for v in values],
                    textposition="outside",
                    marker_line_width=0,
                )
            )
            fig_bar.add_hline(y=70, line_dash="dash", line_color="#4fc3f7",
                              annotation_text="Good threshold", annotation_font_color="#4fc3f7")
            fig_bar.update_layout(
                title="Code Health Metric Scores",
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(13,27,42,0.6)",
                font_color="#8bb8d4",
                yaxis=dict(range=[0, 110]),
                showlegend=False,
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        with gauge_col:
            overall = scores["overall_score"]
            gauge_color = (
                "#30d158" if overall >= 70 else
                "#ffd60a" if overall >= 40 else
                "#ff2d55"
            )
            fig_gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number+delta",
                    value=overall,
                    delta={"reference": 70, "increasing": {"color": "#30d158"},
                           "decreasing": {"color": "#ff2d55"}},
                    title={"text": f"Overall Quality<br><span style='font-size:1.4em;font-weight:700'>"
                                   f"Grade: {scores['grade']}</span>",
                           "font": {"color": "#8bb8d4", "size": 16}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#4a8abf", "dtick": 20},
                        "bar":  {"color": gauge_color, "thickness": 0.3},
                        "bgcolor": "rgba(0,0,0,0)",
                        "borderwidth": 0,
                        "steps": [
                            {"range": [0,  40], "color": "rgba(255,45,85,0.15)"},
                            {"range": [40, 70], "color": "rgba(255,214,10,0.12)"},
                            {"range": [70,100], "color": "rgba(48,209,88,0.12)"},
                        ],
                        "threshold": {
                            "line": {"color": "#4fc3f7", "width": 3},
                            "thickness": 0.8,
                            "value": overall,
                        },
                    },
                    number={"suffix": "/100", "font": {"color": "#e0f0ff", "size": 40}},
                )
            )
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#8bb8d4",
                height=320,
                margin=dict(t=40, b=20),
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        # ── Row 2: Radar chart ────────────────────────────────────────────────
        st.divider()
        st.markdown("#### 🕸️ Code Quality Radar")

        radar_cats = ["Bug Safety", "Security", "Performance", "Energy Efficiency", "Complexity"]
        comp_score = scores.get("performance_score", 100)
        radar_vals = [
            scores["bug_score"],
            scores["security_score"],
            scores["performance_score"],
            scores["energy_score"],
            comp_score,
        ]
        # Close the polygon
        radar_cats_closed = radar_cats + [radar_cats[0]]
        radar_vals_closed = radar_vals + [radar_vals[0]]

        fig_radar = go.Figure()
        fig_radar.add_trace(
            go.Scatterpolar(
                r=radar_vals_closed,
                theta=radar_cats_closed,
                fill="toself",
                fillcolor="rgba(79,195,247,0.15)",
                line=dict(color="#4fc3f7", width=2),
                name="Your Code",
            )
        )
        fig_radar.add_trace(
            go.Scatterpolar(
                r=[70, 70, 70, 70, 70, 70],
                theta=radar_cats_closed,
                fill="toself",
                fillcolor="rgba(48,209,88,0.05)",
                line=dict(color="#30d158", width=1, dash="dash"),
                name="Good Threshold",
            )
        )
        fig_radar.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 100], color="#4a8abf"),
                angularaxis=dict(color="#8bb8d4"),
                bgcolor="rgba(13,27,42,0.6)",
            ),
            showlegend=True,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#8bb8d4",
            height=400,
        )
        st.plotly_chart(fig_radar, use_container_width=True)

        # ── Row 3: Issue summary table ────────────────────────────────────────
        st.divider()
        st.markdown("#### 📋 Issue Summary")
        issue_data = {
            "Category":       ["🐞 Bugs", "🔐 Security", "🌱 Energy", "⚡ Complexity"],
            "Issues Found":   [
                scores["bug_count"],
                scores["sec_count"],
                scores["energy_count"],
                1 if st.session_state.complexity.get("max_nesting_depth", 0) >= 2 else 0,
            ],
            "Score":          [
                f"{scores['bug_score']}/100",
                f"{scores['security_score']}/100",
                f"{scores['energy_score']}/100",
                f"{scores['performance_score']}/100",
            ],
            "Status": [
                "✅ Pass" if scores["bug_score"] >= 70 else "⚠️ Review" if scores["bug_score"] >= 40 else "❌ Fail",
                "✅ Pass" if scores["security_score"] >= 70 else "⚠️ Review" if scores["security_score"] >= 40 else "❌ Fail",
                "✅ Pass" if scores["energy_score"] >= 70 else "⚠️ Review" if scores["energy_score"] >= 40 else "❌ Fail",
                "✅ Pass" if scores["performance_score"] >= 70 else "⚠️ Review" if scores["performance_score"] >= 40 else "❌ Fail",
            ],
        }
        df_issues = pd.DataFrame(issue_data)
        st.dataframe(df_issues, use_container_width=True, hide_index=True)
