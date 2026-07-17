# Sentinel Harmonization Engine

A Python-based system that detects and harmonizes Identity and Access Management (IAM) privilege inconsistencies across **AWS**, **Azure**, and **GCP** — built to solve a real problem in multi-cloud environments: the same user can end up with wildly different access levels on different cloud platforms, with no easy way to spot it.

📄 **Published research:** [Harmonization of User Privileges on Multi-Cloud Platforms Using Python: The Sentinel Harmonization Engine](https://ideasuniuyojournal.com/wp-content/uploads/2026/07/Ideas-V1-N6-25.pdf) — *IDEAS: Uniuyo Journal of Philosophy and Multi-Disciplinary Studies*, Vol. 1, No. 6 (2026), pp. 329–339.

---

## The Problem

Organizations running multi-cloud infrastructure inherit three separate identity systems with no native way to compare them:

- **AWS** — JSON-based policies attached to users, groups, and roles
- **Azure** — Role-Based Access Control (RBAC) tied to Azure Active Directory
- **GCP** — A hierarchical resource model (organization → folder → project)

A user can hold administrative access on one platform and read-only access on another for the exact same job function — and without a unified view, that inconsistency goes unnoticed until it becomes a security incident.

## What It Does

- **Ingests** IAM data from AWS, Azure, and GCP
- **Normalizes** each platform's privilege model into a unified **HIGH / MEDIUM / LOW** scale
- **Detects** cross-platform inconsistencies via an automated harmonization algorithm
- **Scores risk** with a Security Health Score (0–100) and severity-classified findings (CRITICAL / HIGH / MEDIUM)
- **Recommends remediation** for each inconsistency found

## Key Features

- 🔐 Authenticated Streamlit dashboard
- 📊 Gauge-based Security Health Score visualization
- 🔍 Privilege comparison matrix (side-by-side view across all three platforms)
- 🕒 Scan history with JSON persistence
- 📤 CSV / Excel report export
- 📧 Simulated email alerting for critical findings

## Tech Stack

| Layer | Tools |
|---|---|
| Language | Python |
| Interface | Streamlit |
| Cloud SDKs | `boto3` (AWS), `azure-identity` (Azure), `google-cloud-iam` (GCP) |
| Data Persistence | JSON |
| Export | CSV, Excel |

## Architecture

1. **Data Ingestion Module** — accepts CSV-formatted IAM data from all three platforms and auto-detects format
2. **Normalization Engine** — maps native privilege representations onto the unified HIGH/MEDIUM/LOW scale
3. **Harmonization Algorithm** — compares normalized privileges across platforms, flags inconsistencies, calculates risk
4. **Report Generation Module** — produces the Security Health Score, inconsistency reports, and comparison matrix
5. **Interactive Dashboard** — presents everything through an authenticated Streamlit interface

## Results

Tested on a simulated 12-user multi-cloud dataset with deliberately introduced inconsistencies:

- **7** distinct privilege inconsistencies identified
- **Security Health Score: 50/100** — correctly classified as a critical-risk environment
- Findings included privilege escalation, privilege gaps, and cross-platform role misalignment, each with a severity rating and remediation recommendation

## Why It Matters

Framed within Nigerian regulatory context — NITDA, the Nigeria Data Protection Regulation (NDPR), and the CBN Risk-Based Cybersecurity Framework — this project demonstrates that practical, deployable multi-cloud IAM governance tooling can be built from within a Nigerian academic institution, with direct relevance to government agencies, financial institutions, and higher education running multi-cloud workloads.

## Getting Started

```bash
git clone https://github.com/Kel-veen/sentinel-harmonization-engine.git
cd sentinel-harmonization-engine
pip install -r requirements.txt
streamlit run app.pyUdeagwu, C. K. (2026). Harmonization of User Privileges on Multi-Cloud Platforms
Using Python: The Sentinel Harmonization Engine. IDEAS: Uniuyo Journal of
Philosophy and Multi-Disciplinary Studies, 1(6), 329–339.
