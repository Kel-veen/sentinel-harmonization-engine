import pytest
from src.normalization import Normalization

# ── AWS normalisation ──────────────────────────────────────────────────────
def test_normalize_aws_uses_username():
    aws = {"users": [{"UserId": "U1", "UserName": "alice",
                       "AttachedPolicies": [{"PolicyName": "AdministratorAccess",
                                             "PolicyDocument": {"Statement": [{"Action": "*", "Resource": "*"}]}}]}]}
    recs = Normalization().normalize_aws_data(aws)
    assert len(recs) == 1
    assert recs[0]["UserName"]   == "alice"
    assert recs[0]["PolicyName"] == "AdministratorAccess"
    assert recs[0]["Platform"]   == "AWS"


def test_normalize_aws_falls_back_to_userid():
    """If UserName is absent the UserId should be used as the UserName."""
    aws = {"users": [{"UserId": "U99",
                       "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess",
                                             "PolicyDocument": {"Statement": [{"Action": "s3:Get*", "Resource": "*"}]}}]}]}
    recs = Normalization().normalize_aws_data(aws)
    assert recs[0]["UserName"] == "U99"


def test_normalize_azure_uses_principalname():
    azure = {"roleAssignments": [{"PrincipalId": "P1", "PrincipalName": "john_doe",
                                   "RoleDefinitionName": "Owner", "Scope": "*"}]}
    recs = Normalization().normalize_azure_data(azure)
    assert len(recs) == 1
    assert recs[0]["UserName"]   == "john_doe"
    assert recs[0]["PolicyName"] == "Owner"
    assert recs[0]["Platform"]   == "Azure"


def test_get_unified_data_combines_both():
    aws   = {"users": [{"UserId": "U1", "UserName": "alice",
                         "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess",
                                               "PolicyDocument": {"Statement": [{"Action": "s3:Get*", "Resource": "*"}]}}]}]}
    azure = {"roleAssignments": [{"PrincipalId": "P1", "PrincipalName": "alice",
                                   "RoleDefinitionName": "Reader", "Scope": "*"}]}
    unified = Normalization().get_unified_data(aws, azure)
    platforms = {r["Platform"] for r in unified}
    assert "AWS"   in platforms
    assert "Azure" in platforms
