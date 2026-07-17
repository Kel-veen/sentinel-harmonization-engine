class Normalization:
    def __init__(self):
        pass

    def _extract_aws_users(self, aws_data):
        if not isinstance(aws_data, dict):
            return []
        for key in ("users", "Users", "UserDetailList"):
            if key in aws_data and isinstance(aws_data[key], list):
                return aws_data[key]
        return []

    def _extract_azure_items(self, azure_data):
        if not isinstance(azure_data, dict):
            return []
        if "roleAssignments" in azure_data and isinstance(azure_data["roleAssignments"], list):
            return azure_data["roleAssignments"]
        if "Users" in azure_data and isinstance(azure_data["Users"], list):
            return azure_data["Users"]
        if "value" in azure_data and isinstance(azure_data["value"], list):
            return azure_data["value"]
        return []

    def _extract_gcp_bindings(self, gcp_data):
        if not isinstance(gcp_data, dict):
            return []
        if "bindings" in gcp_data and isinstance(gcp_data["bindings"], list):
            return gcp_data["bindings"]
        if "policy" in gcp_data and isinstance(gcp_data["policy"], dict):
            policy = gcp_data["policy"]
            if "bindings" in policy and isinstance(policy["bindings"], list):
                return policy["bindings"]
        if "roleBindings" in gcp_data and isinstance(gcp_data["roleBindings"], list):
            return gcp_data["roleBindings"]
        return []

    def normalize_aws_data(self, aws_data):
        normalized_records = []
        for user in self._extract_aws_users(aws_data):
            if not isinstance(user, dict):
                continue

            user_name = user.get("UserName") or user.get("userName") or user.get("UserId") or user.get("Id") or "unknown"
            user_id = user.get("UserId", user_name)

            policies = []
            if "AttachedPolicies" in user:
                policies = user.get("AttachedPolicies", [])
            elif "AttachedManagedPolicies" in user:
                policies = user.get("AttachedManagedPolicies", [])
            elif "Policies" in user:
                policies = user.get("Policies", [])

            if not isinstance(policies, list):
                policies = [policies]

            if not policies:
                normalized_records.append({
                    "UserName": user_name,
                    "User_ID": user_id,
                    "Platform": "AWS",
                    "PolicyName": None,
                    "Permission": None,
                    "Resource": "*"
                })
                continue

            for policy in policies:
                if not isinstance(policy, dict):
                    continue
                policy_name = policy.get("PolicyName") or policy.get("Policy") or policy.get("PolicyArn") or "Unknown"
                policy_doc = policy.get("PolicyDocument", {})
                if "Actions" in policy and not policy_doc:
                    action = policy.get("Actions")
                    if isinstance(action, list):
                        action = ", ".join(action)
                    permission = action or policy_name
                    normalized_records.append({
                        "UserName": user_name,
                        "User_ID": user_id,
                        "Platform": "AWS",
                        "PolicyName": policy_name,
                        "Permission": permission,
                        "Resource": "*"
                    })
                    continue

                statements = []
                if isinstance(policy_doc, dict):
                    statements = policy_doc.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]

                if not statements:
                    normalized_records.append({
                        "UserName": user_name,
                        "User_ID": user_id,
                        "Platform": "AWS",
                        "PolicyName": policy_name,
                        "Permission": policy_name,
                        "Resource": "*"
                    })
                    continue

                for statement in statements:
                    if not isinstance(statement, dict):
                        continue
                    action = statement.get("Action")
                    if isinstance(action, list):
                        permission = ", ".join(action)
                    else:
                        permission = action or policy_name

                    resource = statement.get("Resource", "*")
                    if isinstance(resource, list):
                        resource = ", ".join(resource)

                    normalized_records.append({
                        "UserName": user_name,
                        "User_ID": user_id,
                        "Platform": "AWS",
                        "PolicyName": policy_name,
                        "Permission": permission,
                        "Resource": resource
                    })

        return normalized_records

    def normalize_azure_data(self, azure_data):
        normalized_records = []
        for item in self._extract_azure_items(azure_data):
            if not isinstance(item, dict):
                continue

            source = item.get("properties", item) if isinstance(item.get("properties"), dict) else item
            user_name = (
                source.get("PrincipalName") or source.get("principalName") or source.get("userPrincipalName") or
                source.get("name") or source.get("displayName") or source.get("PrincipalId") or "unknown"
            )
            user_id = source.get("PrincipalId") or source.get("principalId") or user_name

            if "RoleAssignments" in source and isinstance(source["RoleAssignments"], list):
                for assignment in source["RoleAssignments"]:
                    if not isinstance(assignment, dict):
                        continue
                    role_name = (
                        assignment.get("RoleName") or assignment.get("roleName") or
                        assignment.get("RoleDefinitionName") or assignment.get("roleDefinitionName") or "Unknown"
                    )
                    normalized_records.append({
                        "UserName": user_name,
                        "User_ID": user_id,
                        "Platform": "Azure",
                        "PolicyName": role_name,
                        "Permission": role_name,
                        "Resource": source.get("Scope", source.get("scope", "*"))
                    })
                continue

            role_name = (
                source.get("RoleDefinitionName") or source.get("roleDefinitionName") or
                source.get("RoleName") or source.get("roleName") or "Unknown"
            )
            normalized_records.append({
                "UserName": user_name,
                "User_ID": user_id,
                "Platform": "Azure",
                "PolicyName": role_name,
                "Permission": role_name,
                "Resource": source.get("Scope", source.get("scope", "*"))
            })

        return normalized_records

    def normalize_gcp_data(self, gcp_data):
        normalized_records = []
        for binding in self._extract_gcp_bindings(gcp_data):
            if not isinstance(binding, dict):
                continue

            role_value = binding.get("role") or binding.get("Role") or binding.get("roleName") or binding.get("RoleName") or "Unknown"
            role_name = role_value.split("/")[-1] if isinstance(role_value, str) else str(role_value)
            members = binding.get("members") or binding.get("Members") or binding.get("principals") or []
            if isinstance(members, str):
                members = [members]
            if not isinstance(members, list):
                members = [members]

            for member in members:
                if not isinstance(member, str):
                    continue
                normalized_name = member.split(":", 1)[1] if ":" in member else member
                normalized_name = normalized_name.strip() or member
                normalized_records.append({
                    "UserName": normalized_name,
                    "User_ID": normalized_name,
                    "Platform": "GCP",
                    "PolicyName": role_name,
                    "Permission": role_value,
                    "Resource": binding.get("resource", "*")
                })

        return normalized_records

    def get_unified_data(self, aws_data, azure_data, gcp_data=None):
        """Returns a combined list of normalized records from all supported platforms."""
        aws_norm = self.normalize_aws_data(aws_data)
        azure_norm = self.normalize_azure_data(azure_data)
        gcp_norm = self.normalize_gcp_data(gcp_data) if gcp_data is not None else []
        return aws_norm + azure_norm + gcp_norm
