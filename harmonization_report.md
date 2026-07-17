# Multi-Cloud Privilege Harmonization Report

## Identified Issues and Recommendations

### User: alice (Excess Privilege)
- **Observation**: 'alice' has MEDIUM privilege on AWS ('S3FullAccess') but LOW privilege on Azure ('Storage Blob Data Reader').
- **Recommendation**: Align privilege levels for alice: AWS is MEDIUM ('S3FullAccess') but Azure is LOW ('Storage Blob Data Reader'). Standardise access to the lower of the two levels.

### User: charlie (Inconsistency)
- **Observation**: 'charlie' has LOW privilege on AWS ('EC2ReadOnlyAccess') but MEDIUM privilege on Azure ('Virtual Machine Contributor').
- **Recommendation**: Align privilege levels for charlie: AWS is LOW ('EC2ReadOnlyAccess') but Azure is MEDIUM ('Virtual Machine Contributor'). Standardise access to the lower of the two levels.

### User: dave (Excess Privilege)
- **Observation**: 'dave' has HIGH privilege on AWS ('AdministratorAccess') but LOW privilege on Azure ('Reader').
- **Recommendation**: DOWNGRADE AWS permissions for dave: 'AdministratorAccess' is HIGH privilege but Azure only grants LOW ('Reader'). Apply the Principle of Least Privilege and align both platforms.

## Summary Table

| UserName   | AWS_Policy          | AWS_Level   | Azure_Role                  | Azure_Level   | Issue_Type       | Observation                                                                                                             | Recommendation                                                                                                                                                                     |
|:-----------|:--------------------|:------------|:----------------------------|:--------------|:-----------------|:------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| alice      | S3FullAccess        | MEDIUM      | Storage Blob Data Reader    | LOW           | Excess Privilege | 'alice' has MEDIUM privilege on AWS ('S3FullAccess') but LOW privilege on Azure ('Storage Blob Data Reader').           | Align privilege levels for alice: AWS is MEDIUM ('S3FullAccess') but Azure is LOW ('Storage Blob Data Reader'). Standardise access to the lower of the two levels.                 |
| charlie    | EC2ReadOnlyAccess   | LOW         | Virtual Machine Contributor | MEDIUM        | Inconsistency    | 'charlie' has LOW privilege on AWS ('EC2ReadOnlyAccess') but MEDIUM privilege on Azure ('Virtual Machine Contributor'). | Align privilege levels for charlie: AWS is LOW ('EC2ReadOnlyAccess') but Azure is MEDIUM ('Virtual Machine Contributor'). Standardise access to the lower of the two levels.       |
| dave       | AdministratorAccess | HIGH        | Reader                      | LOW           | Excess Privilege | 'dave' has HIGH privilege on AWS ('AdministratorAccess') but LOW privilege on Azure ('Reader').                         | DOWNGRADE AWS permissions for dave: 'AdministratorAccess' is HIGH privilege but Azure only grants LOW ('Reader'). Apply the Principle of Least Privilege and align both platforms. |