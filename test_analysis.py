import pytest
from src.analysis import PrivilegeAnalysis

# ── Helpers ────────────────────────────────────────────────────────────────
def make_record(username, platform, policy):
    return {
        "UserName":   username,
        "User_ID":    username,
        "Platform":   platform,
        "PolicyName": policy,
        "Permission": policy,
        "Resource":   "*",
    }

# ── Basic tests ────────────────────────────────────────────────────────────
def test_empty_input():
    assert PrivilegeAnalysis([]).detect_inconsistencies() == []


def test_no_inconsistency_when_levels_match():
    data = [
        make_record("alice", "AWS",   "AdministratorAccess"),
        make_record("alice", "Azure", "Owner"),
    ]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    assert issues == [], f"Expected no issues but got: {issues}"


def test_excess_privilege_aws_high_azure_low():
    """john_doe: AWS AdministratorAccess (HIGH) vs Azure Reader (LOW) → Excess Privilege."""
    data = [
        make_record("john_doe", "AWS",   "AdministratorAccess"),
        make_record("john_doe", "Azure", "Reader"),
    ]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    assert len(issues) == 1
    assert issues[0]["Type"] == "Excess Privilege"
    assert issues[0]["AWS_Level"]   == "HIGH"
    assert issues[0]["Azure_Level"] == "LOW"


def test_inconsistency_aws_low_azure_high():
    """david_brown: AWS ReadOnlyAccess (LOW) vs Azure Owner (HIGH) → Inconsistency."""
    data = [
        make_record("david_brown", "AWS",   "ReadOnlyAccess"),
        make_record("david_brown", "Azure", "Owner"),
    ]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    assert len(issues) == 1
    assert issues[0]["Type"] == "Inconsistency"
    assert issues[0]["AWS_Level"]   == "LOW"
    assert issues[0]["Azure_Level"] == "HIGH"


def test_poweruser_aws_vs_reader_azure():
    """mike_johnson: PowerUserAccess (HIGH) vs Reader (LOW) → Excess Privilege."""
    data = [
        make_record("mike_johnson", "AWS",   "PowerUserAccess"),
        make_record("mike_johnson", "Azure", "Reader"),
    ]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    assert len(issues) == 1
    assert issues[0]["Type"] == "Excess Privilege"
    assert issues[0]["AWS_Level"]   == "HIGH"
    assert issues[0]["Azure_Level"] == "LOW"


def test_missing_azure_account():
    data = [make_record("only_aws_user", "AWS", "ReadOnlyAccess")]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    assert len(issues) == 1
    assert issues[0]["Type"] == "Missing Account/Role"


def test_missing_aws_account():
    data = [make_record("only_azure_user", "Azure", "Owner")]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    assert len(issues) == 1
    assert issues[0]["Type"] == "Missing Account/Role"


def test_multiple_users_mixed():
    """Three users — one clean match, two issues."""
    data = [
        make_record("alice",    "AWS",   "AdministratorAccess"),  # HIGH
        make_record("alice",    "Azure", "Owner"),                 # HIGH  → clean
        make_record("bob",      "AWS",   "AdministratorAccess"),  # HIGH
        make_record("bob",      "Azure", "Reader"),                # LOW   → Excess Privilege
        make_record("carol",    "AWS",   "ReadOnlyAccess"),       # LOW
        make_record("carol",    "Azure", "Owner"),                 # HIGH  → Inconsistency
    ]
    issues = PrivilegeAnalysis(data).detect_inconsistencies()
    types  = {i["UserName"]: i["Type"] for i in issues}
    assert "alice"  not in types
    assert types["bob"]   == "Excess Privilege"
    assert types["carol"] == "Inconsistency"
