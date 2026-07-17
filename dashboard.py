import streamlit as st
import pandas as pd
import json
import io
import datetime
import os
from src.normalization import Normalization

# ════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ════════════════════════════════════════════════════════════════════════════
if "aws_data"     not in st.session_state: st.session_state.aws_data     = None
if "azure_data"   not in st.session_state: st.session_state.azure_data   = None
if "gcp_data"     not in st.session_state: st.session_state.gcp_data     = None
if "results"      not in st.session_state: st.session_state.results      = None
if "logged_in"    not in st.session_state: st.session_state.logged_in    = False

if "scan_history" not in st.session_state:
    if os.path.exists("scan_history.json"):
        try:
            with open("scan_history.json", "r") as f:
                st.session_state.scan_history = json.load(f)
        except Exception:
            st.session_state.scan_history = []
    else:
        st.session_state.scan_history = []

if "last_run"     not in st.session_state: st.session_state.last_run     = None
if "risk_score"   not in st.session_state: st.session_state.risk_score   = None

# ════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG & CSS
# ════════════════════════════════════════════════════════════════════════════
st.set_page_config(page_title="Harmonization Engine", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.top-header { background: linear-gradient(135deg, #0f172a, #1e293b); border-bottom: 2px solid #334155; padding: 18px 24px 14px 24px; border-radius: 8px; margin-bottom: 30px; }
.top-header h1 { color: #f1f5f9; font-size: 1.6rem; font-weight: 700; margin: 0; }
.top-header p  { color: #94a3b8; font-size: 0.84rem; margin: 4px 0 0 0; }
.section-title { font-size: 0.78rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.08em; border-left: 3px solid #3b82f6; padding-left: 9px; margin: 28px 0 12px 0; }
.metric-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 22px 16px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
.metric-value { font-size: 2.4rem; font-weight: 700; }
.metric-label { font-size: 0.73rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.07em; margin-top: 5px; }
.c-red { color: #ef4444; } .c-orange { color: #f97316; } .c-green { color: #22c55e; } .c-blue { color: #60a5fa; }
hr.divider { border: none; border-top: 1px solid #334155; margin: 24px 0; }
.info-card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 22px 24px; margin-bottom: 18px; }
.info-card h3 { color: #f1f5f9; font-size: 1rem; font-weight: 600; margin: 0 0 10px 0; }
.info-card p, .info-card li { color: #cbd5e1; font-size: 0.9rem; line-height: 1.7; }
.info-card ul, .info-card ol { padding-left: 20px; margin: 0; }
.step-card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; text-align: center; }
.step-icon { font-size: 2rem; margin-bottom: 10px; }
.step-num { font-size: 0.7rem; font-weight: 700; color: #3b82f6; text-transform: uppercase; letter-spacing: 0.1em; }
.step-title { font-size: 0.95rem; font-weight: 600; color: #f1f5f9; margin: 6px 0; }
.step-desc { font-size: 0.82rem; color: #94a3b8; line-height: 1.5; }
.badge { display: inline-block; background: #0f172a; border: 1px solid #334155; border-radius: 20px; padding: 4px 14px; font-size: 0.78rem; color: #60a5fa; font-weight: 600; margin: 4px 4px 4px 0; }
.dev-card { background: linear-gradient(135deg,#0f172a,#1e293b); border: 1px solid #3b82f6; border-radius: 10px; padding: 20px 24px; }
.matrix-cell-high { background: rgba(239,68,68,0.18); color: #ef4444; font-weight: 700; border-radius: 4px; padding: 2px 8px; }
.matrix-cell-med  { background: rgba(249,115,22,0.18); color: #f97316; font-weight: 700; border-radius: 4px; padding: 2px 8px; }
.matrix-cell-low  { background: rgba(34,197,94,0.18);  color: #22c55e; font-weight: 700; border-radius: 4px; padding: 2px 8px; }
.matrix-cell-none { background: rgba(100,116,139,0.18); color: #64748b; font-weight: 600; border-radius: 4px; padding: 2px 8px; }
</style>
""", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# LOGIN LOGIC
# ════════════════════════════════════════════════════════════════════════════
if not st.session_state.logged_in:
    st.markdown("<div style='text-align: center; margin-top: 50px;'><h1>🛡️ Multi-Cloud Harmonization Engine</h1><p style='color: #94a3b8;'>Air Force Institute of Technology Kaduna</p></div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.markdown("<div style='background: #1e293b; padding: 30px; border-radius: 10px; border: 1px solid #334155;'>", unsafe_allow_html=True)
        st.markdown("### 🔒 LOGIN")
        user = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        if st.button("Login", type="primary", use_container_width=True):
            if user == "admin" and pwd == "password123":
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("Invalid credentials")
        st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# ════════════════════════════════════════════════════════════════════════════
# PRIVILEGE MAPPING & ANALYSIS ENGINE
# ════════════════════════════════════════════════════════════════════════════
AWS_LEVEL = {
    "administratoraccess": "HIGH", "poweruseraccess": "HIGH",
    "s3fullaccess": "MEDIUM", "iamfullaccess": "MEDIUM", "ec2fullaccess": "MEDIUM",
    "readonlyaccess": "LOW", "viewonlyaccess": "LOW", "s3readonlyaccess": "LOW",
    "ec2readonlyaccess": "LOW", "readonly": "LOW",
}

AZURE_LEVEL = {
    "owner": "HIGH",
    "contributor": "MEDIUM", "storage blob data owner": "MEDIUM",
    "storage blob data contributor": "MEDIUM", "virtual machine contributor": "MEDIUM",
    "reader": "LOW", "securityreader": "LOW", "security reader": "LOW",
    "storage blob data reader": "LOW", "virtual machine reader": "LOW",
}

GCP_LEVEL = {
    "owner": "HIGH", "roles/owner": "HIGH",
    "iam.securityadmin": "HIGH", "roles/iam.securityadmin": "HIGH",
    "editor": "MEDIUM", "roles/editor": "MEDIUM",
    "storage.objectadmin": "MEDIUM", "roles/storage.objectadmin": "MEDIUM",
    "viewer": "LOW", "roles/viewer": "LOW",
    "storage.objectviewer": "LOW", "roles/storage.objectviewer": "LOW",
}

LEVEL_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "NONE": 0}

def get_aws_level(policy_name: str) -> str:
    if not policy_name: return "UNKNOWN"
    key = policy_name.strip().lower()
    if key in AWS_LEVEL: return AWS_LEVEL[key]
    if any(x in key for x in ("admin", "fullaccess", "poweruser")): return "HIGH"
    if any(x in key for x in ("read", "readonly", "viewonly", "list")): return "LOW"
    if any(x in key for x in ("write", "contributor", "access", "full")): return "MEDIUM"
    return "UNKNOWN"

def get_azure_level(role_name: str) -> str:
    if not role_name: return "UNKNOWN"
    key = role_name.strip().lower()
    if key in AZURE_LEVEL: return AZURE_LEVEL[key]
    if "owner" in key: return "HIGH"
    if "contributor" in key: return "MEDIUM"
    if "reader" in key: return "LOW"
    return "UNKNOWN"

def get_gcp_level(role_name: str) -> str:
    if not role_name: return "UNKNOWN"
    key = role_name.strip().lower()
    if key in GCP_LEVEL: return GCP_LEVEL[key]
    short = key.split("/")[-1]
    if short in GCP_LEVEL: return GCP_LEVEL[short]
    if any(x in short for x in ("owner", "admin")): return "HIGH"
    if any(x in short for x in ("editor", "write", "full")): return "MEDIUM"
    if any(x in short for x in ("viewer", "reader", "readonly")): return "LOW"
    return "UNKNOWN"

def _extract_aws_users_dash(aws_data: dict) -> dict:
    """Handles all 3 AWS formats and returns {lower_name: (display_name, best_policy_name)}."""
    user_list = (
        aws_data.get("users") or
        aws_data.get("Users") or
        aws_data.get("UserDetailList") or []
    )
    aws_users = {}
    for user in user_list:
        if not isinstance(user, dict): continue
        name = (user.get("UserName") or user.get("userName") or user.get("UserId") or "unknown").strip()
        policies = (
            user.get("AttachedPolicies") or
            user.get("AttachedManagedPolicies") or
            user.get("Policies") or []
        )
        if not isinstance(policies, list): policies = [policies]
        if policies:
            best = max(policies, key=lambda p: LEVEL_ORDER.get(get_aws_level(p.get("PolicyName") or p.get("PolicyArn", "")), 0))
            policy_name = best.get("PolicyName") or best.get("PolicyArn") or "Unknown"
        else:
            policy_name = "No Policy"
        key = name.lower()
        if key not in aws_users or LEVEL_ORDER.get(get_aws_level(policy_name), 0) > LEVEL_ORDER.get(get_aws_level(aws_users[key][1]), 0):
            aws_users[key] = (name, policy_name)
    return aws_users

def _extract_azure_users_dash(azure_data: dict) -> dict:
    """Handles all 3 Azure formats and returns {lower_name: (display_name, best_role_name)}."""
    # Format 1: roleAssignments flat list
    if "roleAssignments" in azure_data:
        items = azure_data["roleAssignments"]
        azure_users = {}
        for a in items:
            if not isinstance(a, dict): continue
            name = (a.get("PrincipalName") or a.get("PrincipalId") or "unknown").strip()
            role = a.get("RoleDefinitionName") or a.get("RoleName") or "Unknown"
            key = name.lower()
            if key not in azure_users or LEVEL_ORDER.get(get_azure_level(role), 0) > LEVEL_ORDER.get(get_azure_level(azure_users[key][1]), 0):
                azure_users[key] = (name, role)
        return azure_users
    # Format 2: Users with RoleAssignments array
    if "Users" in azure_data:
        azure_users = {}
        for u in azure_data["Users"]:
            if not isinstance(u, dict): continue
            name = (u.get("PrincipalName") or u.get("name") or "unknown").strip()
            for ra in (u.get("RoleAssignments") or []):
                role = ra.get("RoleName") or ra.get("RoleDefinitionName") or "Unknown"
                key = name.lower()
                if key not in azure_users or LEVEL_ORDER.get(get_azure_level(role), 0) > LEVEL_ORDER.get(get_azure_level(azure_users[key][1]), 0):
                    azure_users[key] = (name, role)
        return azure_users
    # Format 3: value array with properties nesting
    if "value" in azure_data:
        azure_users = {}
        for item in azure_data["value"]:
            if not isinstance(item, dict): continue
            src = item.get("properties", item) if isinstance(item.get("properties"), dict) else item
            name = (src.get("principalName") or src.get("PrincipalName") or src.get("principalId") or "unknown").strip()
            role = src.get("roleDefinitionName") or src.get("RoleDefinitionName") or "Unknown"
            key = name.lower()
            if key not in azure_users or LEVEL_ORDER.get(get_azure_level(role), 0) > LEVEL_ORDER.get(get_azure_level(azure_users[key][1]), 0):
                azure_users[key] = (name, role)
        return azure_users
    return {}

def _extract_gcp_users_dash(gcp_data: dict) -> dict:
    """Extracts GCP bindings and returns {lower_name: (display_name, role_name)}."""
    bindings = (
        gcp_data.get("bindings") or
        (gcp_data.get("policy") or {}).get("bindings") or
        gcp_data.get("roleBindings") or []
    )
    gcp_users = {}
    for binding in bindings:
        if not isinstance(binding, dict): continue
        role = binding.get("role") or binding.get("Role") or binding.get("roleName") or "Unknown"
        members = binding.get("members") or binding.get("Members") or binding.get("principals") or []
        if isinstance(members, str): members = [members]
        for member in members:
            if not isinstance(member, str): continue
            name = member.split(":", 1)[1] if ":" in member else member
            key = name.lower()
            if key not in gcp_users or LEVEL_ORDER.get(get_gcp_level(role), 0) > LEVEL_ORDER.get(get_gcp_level(gcp_users[key][1]), 0):
                gcp_users[key] = (name, role)
    return gcp_users

def run_analysis(aws_data: dict, azure_data: dict, gcp_data: dict = None) -> list:
    aws_users   = _extract_aws_users_dash(aws_data)
    azure_users = _extract_azure_users_dash(azure_data)
    gcp_users   = _extract_gcp_users_dash(gcp_data) if gcp_data else {}

    all_keys = set(aws_users) | set(azure_users) | set(gcp_users)
    results = []

    for key in sorted(all_keys):
        aws_name,   aws_policy  = aws_users.get(key,   (key, None))
        azure_name, azure_role  = azure_users.get(key, (key, None))
        gcp_name,   gcp_role    = gcp_users.get(key,   (key, None))

        display_name = aws_name if key in aws_users else (azure_name if key in azure_users else gcp_name)
        aws_level   = get_aws_level(aws_policy)   if aws_policy  else "NONE"
        azure_level = get_azure_level(azure_role) if azure_role  else "NONE"
        gcp_level   = get_gcp_level(gcp_role)     if gcp_role    else "NONE"

        active = {p: lvl for p, lvl in [("AWS", aws_level), ("Azure", azure_level), ("GCP", gcp_level)] if lvl != "NONE"}
        active_values = list(active.values())

        if len(set(active_values)) <= 1:
            issue_type = "✅ Consistent"
            severity   = "None"
            recommendation = "Privilege levels match across all active platforms. No action required."
        else:
            max_lvl = max(active_values, key=lambda l: LEVEL_ORDER.get(l, 0))
            min_lvl = min(active_values, key=lambda l: LEVEL_ORDER.get(l, 0))
            diff = LEVEL_ORDER.get(max_lvl, 0) - LEVEL_ORDER.get(min_lvl, 0)
            severity = "Critical" if diff >= 3 else "High" if diff == 2 else "Medium" if diff == 1 else "Low"
            max_p = next(p for p, l in active.items() if l == max_lvl)
            issue_type = "🔴 Excess Privilege" if diff >= 2 else "🟠 Inconsistency"
            platforms_str = ", ".join(f"{p}={l}" for p, l in active.items())
            recommendation = (f"Privilege mismatch ({platforms_str}). Highest on {max_p}. "
                              "Apply Principle of Least Privilege and align all platforms.")

        results.append({
            "Username":      display_name,
            "AWS Policy":    aws_policy  or "N/A",
            "AWS Level":     aws_level,
            "Azure Role":    azure_role  or "N/A",
            "Azure Level":   azure_level,
            "GCP Role":      gcp_role    or "N/A",
            "GCP Level":     gcp_level,
            "Issue Type":    issue_type,
            "Severity":      severity,
            "Recommendation": recommendation,
        })
    return results


# ════════════════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ════════════════════════════════════════════════════════════════════════════
st.sidebar.markdown("""<div style="font-size:0.7rem; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.1em; padding: 0 4px 10px 4px; border-bottom:1px solid #1e293b; margin-bottom:10px;">Navigation</div>""", unsafe_allow_html=True)
page = st.sidebar.radio("Navigation", ["Overview", "Upload & Analysis", "Live Analysis", "Reports & Export"], label_visibility="collapsed")

if st.sidebar.button("🚪 Logout", use_container_width=True):
    st.session_state.logged_in = False
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**System Status**")
if st.session_state.results is not None:
    st.sidebar.success(f"✔ {len(st.session_state.results)} record(s) analysed")
else:
    st.sidebar.warning("Upload files to begin")

st.sidebar.markdown("---")
st.sidebar.markdown("**Scan History**")
if not st.session_state.scan_history:
    st.sidebar.info("No recent scans.")
else:
    for scan in reversed(st.session_state.scan_history[-5:]):
        color = "#ef4444" if scan['score'] <= 40 else "#f97316" if scan['score'] <= 70 else "#22c55e"
        
        sev_html = ""
        if "critical" in scan:
            sev_html = f"<div style='font-size:0.7rem; color:#94a3b8; margin-top:4px;'>🔴 {scan.get('critical',0)} &nbsp; 🟠 {scan.get('high',0)} &nbsp; 🟡 {scan.get('medium',0)} &nbsp; 🟢 {scan.get('low',0)}</div>"
            
        st.sidebar.markdown(f"""
        <div style='font-size:0.8rem; background:#1e293b; padding:8px; border-radius:4px; margin-bottom:6px; border-left: 3px solid {color};'>
            <b>{scan['time']}</b><br>
            Score: <span style='color:{color}; font-weight:bold;'>{scan['score']}</span> | Issues: {scan['issues']}
            {sev_html}
        </div>
        """, unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# HEADER
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""<div class="top-header"><h1>🛡️ Harmonization Engine</h1><p>Air Force Institute of Technology Kaduna &nbsp;|&nbsp; Harmonization of User Privileges on Multi-Cloud Platforms Using Python</p></div>""", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ════════════════════════════════════════════════════════════════════════════
if page == "Overview":
    if st.session_state.results is not None:
        st.success(f"✅ Analysis complete — {len(st.session_state.results)} user record(s) processed. Navigate to Live Analysis or Reports & Export.")

    # ── About ──────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">About the System</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        <h3>🛡️ Sentinel Harmonization Engine</h3>
        <p>The <b>Sentinel Harmonization Engine</b> is developed as a final-year BSc Cyber Security project at the
        <b>Air Force Institute of Technology (AFIT), Kaduna</b>. It addresses the growing challenge of managing user
        privileges across multiple cloud platforms simultaneously — automatically ingesting IAM data from
        <b>AWS, Azure and GCP</b>, normalising privilege levels into a unified scale, detecting inconsistencies
        through intelligent comparison, and generating actionable recommendations to harmonise privileges across
        all platforms.</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Problem & Solution ─────────────────────────────────────────────────
    ps1, ps2 = st.columns(2)
    with ps1:
        st.markdown("""
        <div class="info-card">
            <h3>⚠️ Problem Statement</h3>
            <p>Organisations today use <b>multiple cloud platforms</b> (AWS, Azure, GCP) simultaneously.
            Managing user privileges manually across these platforms is <b>time-consuming, error-prone and creates
            serious security risks</b>. Users may hold excessive privileges on one platform and insufficient
            privileges on another, violating the <i>Principle of Least Privilege</i> and creating potential
            security vulnerabilities.</p>
        </div>
        """, unsafe_allow_html=True)
    with ps2:
        st.markdown("""
        <div class="info-card">
            <h3>✅ Solution</h3>
            <p>The Sentinel Harmonization Engine <b>automatically ingests</b> IAM data from AWS, Azure and GCP,
            <b>normalises</b> privilege levels into a unified HIGH / MEDIUM / LOW scale,
            <b>detects inconsistencies</b> through intelligent cross-platform comparison, and
            <b>generates actionable recommendations</b> to harmonise privileges — reducing manual effort,
            eliminating blind spots and enforcing consistent security policy.</p>
        </div>
        """, unsafe_allow_html=True)

    # ── Requirements ──────────────────────────────────────────────────────
    req1, req2 = st.columns(2)
    with req1:
        st.markdown("""
        <div class="info-card">
            <h3>📋 Functional Requirements</h3>
            <ol>
                <li>Ingest AWS IAM JSON configuration files</li>
                <li>Ingest Azure RBAC JSON configuration files</li>
                <li>Ingest GCP IAM JSON policy files</li>
                <li>Parse and normalise all three formats into a unified schema</li>
                <li>Map policy/role names to HIGH, MEDIUM or LOW privilege tiers</li>
                <li>Detect privilege mismatches across all active platforms per user</li>
                <li>Classify issues by severity (Critical, High, Medium, Low)</li>
                <li>Generate actionable remediation recommendations per user</li>
                <li>Produce a quantitative security health score (0–100)</li>
                <li>Export results as CSV and Excel reports for audit purposes</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)
    with req2:
        st.markdown("""
        <div class="info-card">
            <h3>⚙️ Non-Functional Requirements</h3>
            <ol>
                <li><b>Usability</b> — Intuitive single-page interface requiring no specialist training</li>
                <li><b>Performance</b> — Analysis of 1,000+ user records completes in under 5 seconds</li>
                <li><b>Reliability</b> — Graceful error handling for malformed or unexpected JSON formats</li>
                <li><b>Scalability</b> — Modular architecture allows additional cloud platforms to be added</li>
                <li><b>Security</b> — Authentication gate prevents unauthorised dashboard access</li>
                <li><b>Portability</b> — Runs on any OS with Python 3.9+ and a standard browser</li>
                <li><b>Maintainability</b> — Clear separation of concerns across data, analysis and UI layers</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)

    # ── How It Works ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">How It Works</div>', unsafe_allow_html=True)
    hw1, hw2, hw3, hw4 = st.columns(4)
    steps = [
        ("📥", "Step 1", "Data Ingestion",
         "Upload AWS IAM, Azure RBAC and GCP IAM JSON files. The engine supports three different format variants per platform automatically."),
        ("🔄", "Step 2", "Normalisation",
         "All policy and role names are mapped to a unified HIGH / MEDIUM / LOW privilege scale, stripping platform-specific terminology."),
        ("🔍", "Step 3", "Comparison & Analysis",
         "Users are matched by name across all three platforms. Mismatches are classified by severity and flagged with root-cause descriptions."),
        ("📄", "Step 4", "Report Generation",
         "A security health score is computed, recommendations are generated, and results are exportable as CSV or Excel for audit trails."),
    ]
    for col, (icon, num, title, desc) in zip([hw1, hw2, hw3, hw4], steps):
        with col:
            st.markdown(f"""
            <div class="step-card">
                <div class="step-icon">{icon}</div>
                <div class="step-num">{num}</div>
                <div class="step-title">{title}</div>
                <div class="step-desc">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    # ── Technology Stack ───────────────────────────────────────────────────
    st.markdown('<div class="section-title">Technology Stack</div>', unsafe_allow_html=True)
    techs = ["🐍 Python 3.11", "⚡ Streamlit", "📊 Pandas", "☁️ AWS IAM", "🔷 Azure RBAC", "🟡 Google Cloud IAM", "📄 JSON", "📑 OpenPyXL"]
    badges_html = "".join(f'<span class="badge">{t}</span>' for t in techs)
    st.markdown(f'<div class="info-card" style="padding:16px 20px;">{badges_html}</div>', unsafe_allow_html=True)

    # ── Developer Info ─────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Developer Information</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="dev-card">
        <table style="width:100%; border-collapse:collapse; color:#cbd5e1; font-size:0.9rem;">
            <tr><td style="padding:6px 0; width:180px; color:#64748b; font-weight:600;">👤 Developer</td><td><b style="color:#f1f5f9;">Udeagwu Chinedu</b></td></tr>
            <tr><td style="padding:6px 0; color:#64748b; font-weight:600;">🏛️ Institution</td><td>Air Force Institute of Technology (AFIT), Kaduna</td></tr>
            <tr><td style="padding:6px 0; color:#64748b; font-weight:600;">🎓 Department</td><td>Cyber Security</td></tr>
            <tr><td style="padding:6px 0; color:#64748b; font-weight:600;">📅 Academic Year</td><td>2025 / 2026</td></tr>
            <tr><td style="padding:6px 0; color:#64748b; font-weight:600;">📌 Project Title</td><td>Harmonisation of User Privileges on Multi-Cloud Platforms Using Python</td></tr>
        </table>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.info("➡️ Use the sidebar to navigate to **Upload & Analysis** to begin processing your cloud IAM data.")

# ════════════════════════════════════════════════════════════════════════════
# PAGE: UPLOAD & ANALYSIS
# ════════════════════════════════════════════════════════════════════════════
elif page == "Upload & Analysis":
    # ── validation helpers ───────────────────────────────────────────────
    AWS_KEYS   = {"users", "Users", "UserDetailList"}
    AZURE_KEYS = {"roleAssignments", "Users", "value"}
    GCP_KEYS   = {"bindings", "policy", "roleBindings"}

    def _validate_upload(raw_bytes, filename, expected_platform):
        """Returns (parsed_dict, error_string). error_string is None on success."""
        # 1. JSON syntax check
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return None, (
                f"❌ **Invalid JSON file.** `{filename}` could not be parsed.\n\n"
                f"**Error:** `{e}`\n\n"
                "**Expected format:** A valid JSON object `{{...}}` containing IAM/RBAC user data."
            )
        if not isinstance(data, dict):
            return None, (
                f"❌ **Wrong format.** `{filename}` must be a JSON *object* (dictionary), "
                "not a list or primitive value."
            )
        top_keys = set(data.keys())
        # 2. Wrong-slot detection
        if expected_platform == "AWS":
            if top_keys & AZURE_KEYS and not top_keys & AWS_KEYS:
                return None, (
                    f"❌ **Wrong file slot.** `{filename}` looks like an **Azure RBAC** file "
                    f"(contains key(s): `{', '.join(top_keys & AZURE_KEYS)}`). "
                    "Please upload it in the **Azure RBAC** slot.\n\n"
                    "**AWS IAM files** should contain one of: `users`, `Users`, or `UserDetailList`."
                )
            if top_keys & GCP_KEYS and not top_keys & AWS_KEYS:
                return None, (
                    f"❌ **Wrong file slot.** `{filename}` looks like a **GCP IAM** file. "
                    "Please upload it in the **GCP IAM** slot.\n\n"
                    "**AWS IAM files** should contain one of: `users`, `Users`, or `UserDetailList`."
                )
            if not top_keys & AWS_KEYS:
                return None, (
                    f"❌ **Unrecognised AWS format.** `{filename}` does not contain any expected "
                    "AWS IAM keys (`users`, `Users`, `UserDetailList`).\n\n"
                    "Please verify this is a valid AWS IAM export file."
                )
        elif expected_platform == "Azure":
            if top_keys & AWS_KEYS and not top_keys & AZURE_KEYS:
                return None, (
                    f"❌ **Wrong file slot.** `{filename}` looks like an **AWS IAM** file. "
                    "Please upload it in the **AWS IAM** slot.\n\n"
                    "**Azure RBAC files** should contain one of: `roleAssignments`, `Users`, or `value`."
                )
            if top_keys & GCP_KEYS and not top_keys & AZURE_KEYS:
                return None, (
                    f"❌ **Wrong file slot.** `{filename}` looks like a **GCP IAM** file. "
                    "Please upload it in the **GCP IAM** slot."
                )
            if not top_keys & AZURE_KEYS:
                return None, (
                    f"❌ **Unrecognised Azure format.** `{filename}` does not contain any expected "
                    "Azure RBAC keys (`roleAssignments`, `Users`, `value`).\n\n"
                    "Please verify this is a valid Azure RBAC export file."
                )
        elif expected_platform == "GCP":
            if top_keys & AWS_KEYS and not top_keys & GCP_KEYS:
                return None, (
                    f"❌ **Wrong file slot.** `{filename}` looks like an **AWS IAM** file. "
                    "Please upload it in the **AWS IAM** slot."
                )
            if top_keys & AZURE_KEYS and not top_keys & GCP_KEYS:
                return None, (
                    f"❌ **Wrong file slot.** `{filename}` looks like an **Azure RBAC** file. "
                    "Please upload it in the **Azure RBAC** slot."
                )
            if not top_keys & GCP_KEYS:
                return None, (
                    f"❌ **Unrecognised GCP format.** `{filename}` does not contain any expected "
                    "GCP IAM keys (`bindings`, `policy`, `roleBindings`).\n\n"
                    "Please verify this is a valid GCP IAM policy export file."
                )
        return data, None

    st.markdown('<div class="section-title">1 · Upload JSON Files</div>', unsafe_allow_html=True)
    col_aws, col_az, col_gcp = st.columns(3)

    with col_aws:
        st.markdown("**☁️ AWS IAM Configuration**")
        st.caption("Formats: `users`, `Users`, or `UserDetailList`")
        aws_upload = st.file_uploader("aws", type=["json"], label_visibility="collapsed", key="aws_file_widget")
        if aws_upload is not None:
            parsed, err = _validate_upload(aws_upload.getvalue(), aws_upload.name, "AWS")
            if err:
                st.error(err)
                st.session_state.aws_data = None
            else:
                st.session_state.aws_data = parsed
                st.success(f"✔ `{aws_upload.name}` — valid AWS IAM file loaded ({len(_extract_aws_users_dash(parsed))} user(s) found)")
        if st.session_state.aws_data is not None and aws_upload is None:
            st.info(f"AWS data already loaded.")

    with col_az:
        st.markdown("**🔷 Azure RBAC Configuration**")
        st.caption("Formats: `roleAssignments`, `Users`, or `value`")
        az_upload = st.file_uploader("azure", type=["json"], label_visibility="collapsed", key="az_file_widget")
        if az_upload is not None:
            parsed, err = _validate_upload(az_upload.getvalue(), az_upload.name, "Azure")
            if err:
                st.error(err)
                st.session_state.azure_data = None
            else:
                st.session_state.azure_data = parsed
                st.success(f"✔ `{az_upload.name}` — valid Azure RBAC file loaded ({len(_extract_azure_users_dash(parsed))} role assignment(s) found)")
        if st.session_state.azure_data is not None and az_upload is None:
            st.info("Azure data already loaded.")

    with col_gcp:
        st.markdown("**🟡 GCP IAM Configuration**")
        st.caption("Formats: `bindings`, `policy`, or `roleBindings` — optional")
        gcp_upload = st.file_uploader("gcp", type=["json"], label_visibility="collapsed", key="gcp_file_widget")
        if gcp_upload is not None:
            parsed, err = _validate_upload(gcp_upload.getvalue(), gcp_upload.name, "GCP")
            if err:
                st.error(err)
                st.session_state.gcp_data = None
            else:
                st.session_state.gcp_data = parsed
                st.success(f"✔ `{gcp_upload.name}` — valid GCP IAM file loaded ({len(_extract_gcp_users_dash(parsed))} member(s) found)")
        if st.session_state.gcp_data is not None and gcp_upload is None:
            st.info("GCP data already loaded.")

    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">2 · Run Harmonization Engine</div>', unsafe_allow_html=True)

    if st.button("▶  Run Harmonization Engine", type="primary", use_container_width=True):
        if st.session_state.aws_data is None or st.session_state.azure_data is None:
            st.error("❌ Please upload both AWS and Azure JSON files before running.")
        else:
            with st.spinner("Analysing privilege levels across all platforms…"):
                result_list = run_analysis(st.session_state.aws_data, st.session_state.azure_data, st.session_state.gcp_data)
                
                points_deducted = 0
                for r in result_list:
                    if r["Severity"] == "Critical": points_deducted += 15
                    elif r["Severity"] == "High": points_deducted += 10
                    elif r["Severity"] == "Medium": points_deducted += 5
                    elif r["Severity"] == "Low": points_deducted += 2
                
                final_score = max(0, 100 - points_deducted)
                st.session_state.risk_score = final_score
                st.session_state.last_run = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.session_state.results = result_list
                
                new_scan = {
                    "time": st.session_state.last_run,
                    "score": final_score,
                    "issues": sum(1 for r in result_list if r["Severity"] != "None"),
                    "critical": sum(1 for r in result_list if r["Severity"] == "Critical"),
                    "high": sum(1 for r in result_list if r["Severity"] == "High"),
                    "medium": sum(1 for r in result_list if r["Severity"] == "Medium"),
                    "low": sum(1 for r in result_list if r["Severity"] == "Low")
                }
                st.session_state.scan_history.append(new_scan)
                st.session_state.scan_history = st.session_state.scan_history[-50:]
                
                try:
                    with open("scan_history.json", "w") as f:
                        json.dump(st.session_state.scan_history, f, indent=4)
                except Exception as e:
                    st.error(f"❌ Could not save scan history to file: {e}")
            st.success(f"✅ Analysis complete — {len(result_list)} user record(s) processed. Please navigate to Live Analysis.")

# ════════════════════════════════════════════════════════════════════════════
# PAGE: LIVE ANALYSIS
# ════════════════════════════════════════════════════════════════════════════
elif page == "Live Analysis":
    if st.session_state.results is None:
        st.info("No data analysed yet. Please go to Upload & Analysis to run the engine.")
    else:
        df = pd.DataFrame(st.session_state.results)
        issues_df = df[df["Severity"] != "None"]
        crit = len(df[df["Severity"] == "Critical"])
        high = len(df[df["Severity"] == "High"])
        med = len(df[df["Severity"] == "Medium"])
        low = len(df[df["Severity"] == "Low"])
        score = st.session_state.risk_score
        
        # Simulated Email Alert
        if crit > 0 or high > 0:
            st.markdown(f"""
            <div style="background-color: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); padding: 16px; border-radius: 8px; margin-bottom: 20px;">
                <h4 style="color: #ef4444; margin-top: 0; margin-bottom: 8px;">🚨 SIMULATED EMAIL ALERT</h4>
                <div style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.6;">
                    <b>To:</b> admin@afit.edu.ng<br>
                    <b>Subject:</b> CRITICAL PRIVILEGE MISMATCH DETECTED<br>
                    <b>Body:</b> Automated scan detected {crit} Critical and {high} High severity privilege mismatches across AWS and Azure environments. Please review the dashboard immediately.
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-title">3 · Risk Score & Executive Summary</div>', unsafe_allow_html=True)
        
        col_gauge, col_sum = st.columns([1, 2])
        with col_gauge:
            color_hex = "#ef4444" if score <= 40 else "#f97316" if score <= 70 else "#22c55e"
            st.markdown(f"""
            <div style="background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; text-align: center; height: 100%;">
                <h4 style="margin-top:0; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.8rem;">Security Health Score</h4>
                <div style="font-size: 4.5rem; font-weight: 700; color: {color_hex}; line-height: 1.2; margin: 10px 0;">{score}</div>
                <div style="width: 100%; background-color: rgba(255,255,255,0.05); border-radius: 6px; height: 14px; margin-top: 15px; border: 1px solid #334155;">
                    <div style="width: {score}%; background-color: {color_hex}; height: 100%; border-radius: 5px;"></div>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #64748b; margin-top: 6px; font-weight: 600;">
                    <span>0</span><span>100</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
        with col_sum:
            st.markdown(f"""
            <div style="background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; height: 100%;">
                <h4 style="margin-top:0;">Executive Summary</h4>
                <p style="color: #cbd5e1; font-size: 0.95rem; line-height: 1.6;">
                    Analysis ran on <b>{st.session_state.last_run}</b>. The engine scanned <b>{len(df)}</b> users across AWS and Azure environments. 
                    A total of <b>{len(issues_df)}</b> inconsistencies were detected, comprising:
                    <br><br>
                    <span style="color:#ef4444; font-weight:bold;">{crit} Critical</span> &nbsp;|&nbsp; 
                    <span style="color:#f97316; font-weight:bold;">{high} High</span> &nbsp;|&nbsp; 
                    <span style="color:#eab308; font-weight:bold;">{med} Medium</span> &nbsp;|&nbsp; 
                    <span style="color:#22c55e; font-weight:bold;">{low} Low</span>
                    <br><br>
                    The overall security health risk score stands at <b>{score}/100</b>. Immediate action is recommended for Critical and High severity issues.
                </p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<hr class="divider">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">4 · Visual Analysis</div>', unsafe_allow_html=True)
        ch1, ch2, ch3 = st.columns(3)
        with ch1:
            st.markdown("**Issues by Severity**")
            sev_counts = issues_df["Severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0).reset_index()
            sev_counts.columns = ["Severity", "Count"]
            st.bar_chart(sev_counts, x="Severity", y="Count", color="#f97316")
        with ch2:
            st.markdown("**AWS Privilege Level Distribution**")
            aws_dist = df["AWS Level"].value_counts().reset_index()
            aws_dist.columns = ["Level", "Count"]
            st.bar_chart(aws_dist, x="Level", y="Count", color="#3b82f6")
        with ch3:
            st.markdown("**Azure & GCP Level Distribution**")
            az_dist = df["Azure Level"].value_counts().rename("Azure")
            gcp_dist = df["GCP Level"].value_counts().rename("GCP") if "GCP Level" in df.columns else pd.Series(dtype=int)
            combined = pd.concat([az_dist, gcp_dist], axis=1).fillna(0).reset_index()
            combined.rename(columns={"index": "Level"}, inplace=True)
            st.bar_chart(combined, x="Level", color=["#22c55e", "#facc15"])

        # ── Privilege Comparison Matrix ───────────────────────────────────
        st.markdown('<hr class="divider">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">5 · Privilege Comparison Matrix</div>', unsafe_allow_html=True)

        def _level_badge(lvl):
            css = {"HIGH": "matrix-cell-high", "MEDIUM": "matrix-cell-med",
                   "LOW": "matrix-cell-low"}.get(lvl, "matrix-cell-none")
            return f'<span class="{css}">{lvl}</span>'

        matrix_rows = []
        for r in st.session_state.results:
            aws_b   = _level_badge(r.get("AWS Level",   "NONE"))
            az_b    = _level_badge(r.get("Azure Level", "NONE"))
            gcp_b   = _level_badge(r.get("GCP Level",  "NONE"))
            sev     = r.get("Severity", "None")
            sev_col = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e"}.get(sev,"#64748b")
            sev_html = f'<span style="color:{sev_col};font-weight:700;">{sev}</span>'
            rec = r.get("Recommendation","")[:80] + ("…" if len(r.get("Recommendation","")) > 80 else "")
            matrix_rows.append(
                f"<tr>"
                f"<td style='padding:8px 10px;color:#f1f5f9;font-weight:600;'>{r.get('Username','')}</td>"
                f"<td style='padding:8px 10px;color:#94a3b8;font-size:0.8rem;'>{r.get('AWS Policy','N/A')}</td>"
                f"<td style='padding:8px 10px;text-align:center;'>{aws_b}</td>"
                f"<td style='padding:8px 10px;text-align:center;'>{az_b}</td>"
                f"<td style='padding:8px 10px;text-align:center;'>{gcp_b}</td>"
                f"<td style='padding:8px 10px;text-align:center;'>{sev_html}</td>"
                f"<td style='padding:8px 10px;color:#94a3b8;font-size:0.78rem;'>{rec}</td>"
                f"</tr>"
            )
        matrix_html = (
            "<div style='overflow-x:auto;'>"
            "<table style='width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;'>"
            "<thead><tr style='background:#0f172a;'>"
            "<th style='padding:10px;text-align:left;color:#64748b;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.07em;'>Username</th>"
            "<th style='padding:10px;text-align:left;color:#64748b;font-size:0.75rem;text-transform:uppercase;'>Policy / Role</th>"
            "<th style='padding:10px;text-align:center;color:#60a5fa;font-size:0.75rem;'>AWS</th>"
            "<th style='padding:10px;text-align:center;color:#818cf8;font-size:0.75rem;'>Azure</th>"
            "<th style='padding:10px;text-align:center;color:#facc15;font-size:0.75rem;'>GCP</th>"
            "<th style='padding:10px;text-align:center;color:#64748b;font-size:0.75rem;'>Severity</th>"
            "<th style='padding:10px;text-align:left;color:#64748b;font-size:0.75rem;'>Recommendation</th>"
            "</tr></thead><tbody>"
            + "".join(matrix_rows)
            + "</tbody></table></div>"
        )
        st.markdown(matrix_html, unsafe_allow_html=True)

        # ── Harmonization Preview ─────────────────────────────────────────
        st.markdown('<hr class="divider">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">6 · Harmonization Preview — Before & After</div>', unsafe_allow_html=True)

        inconsistent = [r for r in st.session_state.results if r.get("Severity","None") != "None"]
        changes = len(inconsistent)
        st.markdown(f"""
        <div style="background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.3);
             border-radius:8px;padding:14px 18px;margin-bottom:18px;">
            <span style="color:#60a5fa;font-weight:700;font-size:1rem;">
                🔧 {changes} privilege change(s) would be applied to reach a fully harmonised state.
            </span>
            <span style="color:#94a3b8;font-size:0.85rem;margin-left:10px;">
                All users would be aligned to their lowest active privilege level.
            </span>
        </div>
        """, unsafe_allow_html=True)

        col_before, col_after = st.columns(2)

        def _preview_table(rows, mode):
            """mode = 'before' (highlight issues red) or 'after' (all green)."""
            hdr_color = "#ef4444" if mode == "before" else "#22c55e"
            title = "⚠️ Current State (Before)" if mode == "before" else "✅ Harmonised State (After)"
            html = (
                f"<div style='background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;'>"
                f"<h4 style='color:{hdr_color};margin:0 0 12px 0;font-size:0.9rem;'>{title}</h4>"
                "<table style='width:100%;border-collapse:collapse;font-size:0.82rem;'>"
                "<tr style='color:#64748b;font-size:0.72rem;text-transform:uppercase;'>"
                "<th style='padding:6px;text-align:left;'>User</th>"
                "<th style='padding:6px;text-align:center;'>AWS</th>"
                "<th style='padding:6px;text-align:center;'>Azure</th>"
                "<th style='padding:6px;text-align:center;'>GCP</th></tr>"
            )
            lo = {"HIGH":3,"MEDIUM":2,"LOW":1,"NONE":0,"UNKNOWN":0}
            for r in rows:
                aws_l  = r.get("AWS Level","NONE")
                az_l   = r.get("Azure Level","NONE")
                gcp_l  = r.get("GCP Level","NONE")
                active = [l for l in [aws_l, az_l, gcp_l] if l not in ("NONE","UNKNOWN")]
                if mode == "after" and active:
                    target = min(active, key=lambda l: lo.get(l,0))
                    aws_l = target if aws_l != "NONE" else "NONE"
                    az_l  = target if az_l  != "NONE" else "NONE"
                    gcp_l = target if gcp_l != "NONE" else "NONE"
                is_inc = r.get("Severity","None") != "None"
                row_bg = "rgba(239,68,68,0.07)" if (mode=="before" and is_inc) else "rgba(34,197,94,0.05)" if mode=="after" else "transparent"
                html += (
                    f"<tr style='background:{row_bg};border-bottom:1px solid #1e293b;'>"
                    f"<td style='padding:7px 6px;color:#f1f5f9;font-weight:500;'>{r.get('Username','')}</td>"
                    f"<td style='padding:7px 6px;text-align:center;'>{_level_badge(aws_l)}</td>"
                    f"<td style='padding:7px 6px;text-align:center;'>{_level_badge(az_l)}</td>"
                    f"<td style='padding:7px 6px;text-align:center;'>{_level_badge(gcp_l)}</td>"
                    f"</tr>"
                )
            html += "</table></div>"
            return html

        preview_rows = inconsistent if inconsistent else st.session_state.results
        with col_before:
            st.markdown(_preview_table(preview_rows, "before"), unsafe_allow_html=True)
        with col_after:
            st.markdown(_preview_table(preview_rows, "after"), unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS & EXPORT
# ════════════════════════════════════════════════════════════════════════════
elif page == "Reports & Export":
    if st.session_state.results is None:
        st.info("No data analysed yet. Please go to Upload & Analysis to run the engine.")
    else:
        df = pd.DataFrame(st.session_state.results)
        
        st.markdown('<div class="section-title">5 · Detailed Inconsistencies Report</div>', unsafe_allow_html=True)

        def style_severity(val):
            if val == "Critical": return "background-color: rgba(239,68,68,0.2); color: #ef4444; font-weight: bold;"
            if val == "High": return "background-color: rgba(249,115,22,0.2); color: #f97316; font-weight: bold;"
            if val == "Medium": return "background-color: rgba(234,179,8,0.2); color: #eab308; font-weight: bold;"
            if val == "Low": return "background-color: rgba(34,197,94,0.2); color: #22c55e; font-weight: bold;"
            return "color: #94a3b8;"

        def style_level(val):
            if val == "HIGH": return "color:#ef4444;font-weight:600;"
            if val == "MEDIUM": return "color:#f97316;font-weight:600;"
            if val == "LOW": return "color:#22c55e;font-weight:600;"
            return ""

        gcp_col_list = ["GCP Level"] if "GCP Level" in df.columns else []
        styled = (df.style
            .map(style_severity, subset=["Severity"])
            .map(style_level, subset=["AWS Level", "Azure Level"] + gcp_col_list)
        )

        st.dataframe(styled, use_container_width=True, hide_index=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">6 · Export Report</div>', unsafe_allow_html=True)

        ex1, ex2 = st.columns(2)

        csv_bytes = df.to_csv(index=False).encode("utf-8")
        with ex1:
            st.download_button("⬇  Download CSV", data=csv_bytes, file_name="harmonization_report.csv", mime="text/csv", use_container_width=True)

        excel_buf = io.BytesIO()
        with pd.ExcelWriter(excel_buf, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Harmonization Report")
        with ex2:
            st.download_button("⬇  Download Excel", data=excel_buf.getvalue(), file_name="harmonization_report.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
