import json
import os

def generate_datasets():
    # AWS IAM Simulated Data (Policy-based)
    aws_data = {
        "users": [
            {
                "UserId": "U001",
                "UserName": "alice",
                "AttachedPolicies": [
                    {
                        "PolicyName": "S3FullAccess",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:*",
                                    "Resource": "arn:aws:s3:::*"
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "UserId": "U002",
                "UserName": "bob",
                "AttachedPolicies": [
                    {
                        "PolicyName": "S3ReadOnlyAccess",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:Get*", "s3:List*"],
                                    "Resource": "arn:aws:s3:::*"
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "UserId": "U003",
                "UserName": "charlie",
                "AttachedPolicies": [
                    {
                        "PolicyName": "EC2ReadOnlyAccess",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["ec2:Describe*"],
                                    "Resource": "*"
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "UserId": "U004",
                "UserName": "dave",
                "AttachedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*"
                                }
                            ]
                        }
                    }
                ]
            }
        ]
    }

    # Azure RBAC Simulated Data (Role-based)
    azure_data = {
        "roleAssignments": [
            {
                "PrincipalId": "U001",
                "PrincipalName": "alice",
                "RoleDefinitionName": "Storage Blob Data Reader", # Inconsistency: AWS is S3FullAccess
                "Scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1"
            },
            {
                "PrincipalId": "U002",
                "PrincipalName": "bob",
                "RoleDefinitionName": "Storage Blob Data Reader", # Consistent with AWS S3ReadOnlyAccess
                "Scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1"
            },
            {
                "PrincipalId": "U003",
                "PrincipalName": "charlie",
                "RoleDefinitionName": "Virtual Machine Contributor", # Inconsistency: AWS is EC2ReadOnlyAccess
                "Scope": "/subscriptions/sub1/resourceGroups/rg1"
            },
            {
                "PrincipalId": "U004",
                "PrincipalName": "dave",
                "RoleDefinitionName": "Reader", # Inconsistency: AWS is AdministratorAccess (Excess Privilege risk)
                "Scope": "/subscriptions/sub1"
            }
        ]
    }

    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    with open(os.path.join(script_dir, 'aws_iam_simulated.json'), 'w') as f:
        json.dump(aws_data, f, indent=4)
        
    with open(os.path.join(script_dir, 'azure_rbac_simulated.json'), 'w') as f:
        json.dump(azure_data, f, indent=4)
        
    print("Simulated datasets generated successfully.")

if __name__ == "__main__":
    generate_datasets()
