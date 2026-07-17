import pandas as pd

class PrivilegeAnalysis:
    """
    Compares AWS, Azure, and GCP privilege levels per user (matched by UserName)
    using a three-tier privilege model: HIGH / MEDIUM / LOW.

    AWS Policy → Privilege Level
    ─────────────────────────────
    AdministratorAccess, PowerUserAccess, FullAccess, *     → HIGH
    S3FullAccess, IAMFullAccess, EC2FullAccess,
    Contributor, StorageBlobDataOwner, *Contributor*         → MEDIUM
    ReadOnlyAccess, ReadOnly, ViewOnlyAccess,
    S3ReadOnlyAccess, EC2ReadOnlyAccess                     → LOW

    Azure Role → Privilege Level
    ─────────────────────────────
    Owner                                                    → HIGH
    Contributor, *Contributor*, Storage Blob Data Owner      → MEDIUM
    Reader, SecurityReader, Storage Blob Data Reader,
    Virtual Machine Reader, *Reader*                        → LOW

    GCP Role → Privilege Level
    ─────────────────────────────
    roles/owner, owner                                       → HIGH
    roles/editor, editor, *Admin*, *objectAdmin*             → MEDIUM
    roles/viewer, viewer, *Reader*, *read*                   → LOW
    """

    # ── Privilege maps ──────────────────────────────────────────────────────
    AWS_LEVEL_MAP = {
        # HIGH
        "administratoraccess":  "HIGH",
        "poweruseraccess":      "HIGH",
        "fullaccess":           "HIGH",
        "*":                    "HIGH",

        # MEDIUM
        "s3fullaccess":         "MEDIUM",
        "iamfullaccess":        "MEDIUM",
        "ec2fullaccess":        "MEDIUM",

        # LOW
        "readonlyaccess":       "LOW",
        "readonly":             "LOW",
        "viewonlyaccess":       "LOW",
        "s3readonlyaccess":     "LOW",
        "ec2readonlyaccess":    "LOW",
    }

    AZURE_LEVEL_MAP = {
        # HIGH
        "owner":                "HIGH",

        # MEDIUM
        "contributor":          "MEDIUM",
        "storage blob data owner": "MEDIUM",

        # LOW
        "reader":               "LOW",
        "securityreader":       "LOW",
        "security reader":      "LOW",
        "storage blob data reader":     "LOW",
        "storage blob data contributor":"MEDIUM",
        "virtual machine contributor":  "MEDIUM",
        "virtual machine reader":       "LOW",
    }

    GCP_LEVEL_MAP = {
        # HIGH
        "owner":                    "HIGH",
        "roles/owner":              "HIGH",
        "iam.securityadmin":        "HIGH",
        "roles/iam.securityadmin":  "HIGH",

        # MEDIUM
        "editor":                   "MEDIUM",
        "roles/editor":             "MEDIUM",
        "storage.objectadmin":      "MEDIUM",
        "roles/storage.objectadmin":"MEDIUM",

        # LOW
        "viewer":                   "LOW",
        "roles/viewer":             "LOW",
        "storage.objectviewer":     "LOW",
        "roles/storage.objectviewer":"LOW",
    }

    def __init__(self, normalized_data):
        self.df = pd.DataFrame(normalized_data) if normalized_data else pd.DataFrame()

    # ── Internal helpers ─────────────────────────────────────────────────────
    def _aws_level(self, policy_name: str) -> str:
        """Return HIGH/MEDIUM/LOW for an AWS policy name."""
        if not policy_name:
            return "UNKNOWN"
        key = policy_name.strip().lower()

        # Exact match first
        if key in self.AWS_LEVEL_MAP:
            return self.AWS_LEVEL_MAP[key]

        # Substring heuristics
        if any(x in key for x in ("admin", "fullaccess", "poweruser", "full")):
            return "HIGH"
        if any(x in key for x in ("read", "readonly", "viewonly", "list")):
            return "LOW"
        if any(x in key for x in ("write", "contributor", "access")):
            return "MEDIUM"

        return "UNKNOWN"

    def _azure_level(self, role_name: str) -> str:
        """Return HIGH/MEDIUM/LOW for an Azure role name."""
        if not role_name:
            return "UNKNOWN"
        key = role_name.strip().lower()

        # Exact match first
        if key in self.AZURE_LEVEL_MAP:
            return self.AZURE_LEVEL_MAP[key]

        # Substring heuristics
        if "owner" in key:
            return "HIGH"
        if "contributor" in key:
            return "MEDIUM"
        if "reader" in key:
            return "LOW"

        return "UNKNOWN"

    def _gcp_level(self, role_name: str) -> str:
        """Return HIGH/MEDIUM/LOW for a GCP role name.

        Handles both full paths (roles/owner) and short names (owner),
        as well as common admin/editor/viewer heuristics.
        """
        if not role_name:
            return "UNKNOWN"
        key = role_name.strip().lower()

        # Exact match (handles roles/owner, roles/editor, etc.)
        if key in self.GCP_LEVEL_MAP:
            return self.GCP_LEVEL_MAP[key]

        # Strip roles/ prefix and try again
        short_key = key.split("/")[-1]
        if short_key in self.GCP_LEVEL_MAP:
            return self.GCP_LEVEL_MAP[short_key]

        # Substring heuristics
        if any(x in short_key for x in ("owner", "admin", "securityadmin")):
            return "HIGH"
        if any(x in short_key for x in ("editor", "objectadmin", "write", "full")):
            return "MEDIUM"
        if any(x in short_key for x in ("viewer", "reader", "readonly", "list")):
            return "LOW"

        return "UNKNOWN"

    def _recommendation(self, user: str, aws_level: str, azure_level: str,
                        aws_policy: str, azure_role: str,
                        gcp_level: str = "NONE", gcp_role: str = "N/A") -> str:
        """Generate a concise, actionable recommendation across all three platforms."""
        level_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}

        levels = {
            "AWS":   (aws_level,   aws_policy),
            "Azure": (azure_level, azure_role),
        }
        if gcp_level not in ("NONE", "UNKNOWN"):
            levels["GCP"] = (gcp_level, gcp_role)

        active = {p: (lvl, pol) for p, (lvl, pol) in levels.items() if lvl not in ("NONE", "UNKNOWN")}

        if len(active) < 2:
            return "Insufficient cross-platform data to generate a recommendation."

        max_platform = max(active, key=lambda p: level_order.get(active[p][0], 0))
        min_platform = min(active, key=lambda p: level_order.get(active[p][0], 0))
        max_lvl, max_pol = active[max_platform]
        min_lvl, _ = active[min_platform]

        if max_lvl == min_lvl:
            return "Levels match across all active platforms — no action required."

        platforms_str = " / ".join(f"{p} ({lvl})" for p, (lvl, _) in active.items())
        return (
            f"Privilege mismatch detected for '{user}': {platforms_str}. "
            f"Highest privilege on {max_platform} ('{max_pol}' = {max_lvl}). "
            "Apply the Principle of Least Privilege and align all platforms to the lowest required level."
        )

    # ── Main detection method ─────────────────────────────────────────────────
    def detect_inconsistencies(self):
        """
        Matches users by UserName across AWS, Azure, and GCP records.
        Returns a list of issue dicts, each containing:
          UserName, AWS_Policy, AWS_Level, Azure_Role, Azure_Level,
          GCP_Role, GCP_Level, Type, Description, Recommendation
        """
        issues = []

        if self.df.empty:
            return issues

        # Resolve the column to use for user identity (UserName preferred)
        name_col = "UserName" if "UserName" in self.df.columns else "User_ID"

        aws_df   = self.df[self.df["Platform"] == "AWS"].copy()
        azure_df = self.df[self.df["Platform"] == "Azure"].copy()
        gcp_df   = self.df[self.df["Platform"] == "GCP"].copy()

        # Compute privilege levels
        aws_df["Level"]   = aws_df["PolicyName"].apply(self._aws_level)
        azure_df["Level"] = azure_df["PolicyName"].apply(self._azure_level)
        gcp_df["Level"]   = gcp_df["PolicyName"].apply(self._gcp_level)

        # Collect all known usernames across all three platforms
        all_users = (
            set(aws_df[name_col].dropna()) |
            set(azure_df[name_col].dropna()) |
            set(gcp_df[name_col].dropna())
        )

        level_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "NONE": 0}

        for user in sorted(all_users):
            user_aws   = aws_df[aws_df[name_col].str.lower()   == user.lower()]
            user_azure = azure_df[azure_df[name_col].str.lower() == user.lower()]
            user_gcp   = gcp_df[gcp_df[name_col].str.lower()   == user.lower()]

            # ── Resolve best row per platform ────────────────────────────────
            def best_row(platform_df):
                if platform_df.empty:
                    return None
                return platform_df.loc[platform_df["Level"].map(level_order).idxmax()]

            aws_row   = best_row(user_aws)
            azure_row = best_row(user_azure)
            gcp_row   = best_row(user_gcp)

            aws_level   = aws_row["Level"]   if aws_row   is not None else "NONE"
            azure_level = azure_row["Level"] if azure_row is not None else "NONE"
            gcp_level   = gcp_row["Level"]   if gcp_row   is not None else "NONE"

            aws_policy  = (aws_row["PolicyName"]   if aws_row   is not None else None) or "N/A"
            azure_role  = (azure_row["PolicyName"] if azure_row is not None else None) or "N/A"
            gcp_role    = (gcp_row["PolicyName"]   if gcp_row   is not None else None) or "N/A"

            # ── Determine active platforms and check for inconsistency ───────
            active_levels = {
                lvl for platform, lvl in [("AWS", aws_level), ("Azure", azure_level), ("GCP", gcp_level)]
                if lvl not in ("NONE",)
            }

            # Count platforms present
            present = sum(1 for lvl in (aws_level, azure_level, gcp_level) if lvl != "NONE")

            # If all present platforms agree → skip (no issue)
            if present >= 2 and len(active_levels - {"UNKNOWN"}) <= 1 and "UNKNOWN" not in active_levels:
                continue

            # Determine issue type
            if present == 1:
                # Only on one platform — still flag as missing
                if aws_level != "NONE":
                    issue_type = "Missing Account/Role"
                    description = (
                        f"'{user}' has AWS policy '{aws_policy}' ({aws_level}) "
                        "but no corresponding Azure or GCP role. "
                        "Provision roles on other platforms or revoke unused access."
                    )
                elif azure_level != "NONE":
                    issue_type = "Missing Account/Role"
                    description = (
                        f"'{user}' has Azure role '{azure_role}' ({azure_level}) "
                        "but no corresponding AWS policy or GCP role."
                    )
                else:
                    issue_type = "Missing Account/Role"
                    description = (
                        f"'{user}' has GCP role '{gcp_role}' ({gcp_level}) "
                        "but no corresponding AWS policy or Azure role."
                    )
            else:
                # Check for excess privilege across any active pair
                active_pairs = {
                    "AWS": aws_level, "Azure": azure_level, "GCP": gcp_level
                }
                max_lvl = max(
                    (lvl for lvl in active_pairs.values() if lvl != "NONE"),
                    key=lambda l: level_order.get(l, 0),
                    default="UNKNOWN"
                )
                min_lvl = min(
                    (lvl for lvl in active_pairs.values() if lvl != "NONE"),
                    key=lambda l: level_order.get(l, 0),
                    default="UNKNOWN"
                )

                if max_lvl == min_lvl:
                    # All active platforms match — no issue
                    continue

                if level_order.get(max_lvl, 0) - level_order.get(min_lvl, 0) >= 2:
                    issue_type = "Excess Privilege"
                else:
                    issue_type = "Inconsistency"

                description = (
                    f"'{user}' has mismatched privilege levels: "
                    f"AWS={aws_level} ('{aws_policy}'), "
                    f"Azure={azure_level} ('{azure_role}'), "
                    f"GCP={gcp_level} ('{gcp_role}')."
                )

            issues.append({
                "UserName":    user,
                "AWS_Policy":  aws_policy,
                "AWS_Level":   aws_level,
                "Azure_Role":  azure_role,
                "Azure_Level": azure_level,
                "GCP_Role":    gcp_role,
                "GCP_Level":   gcp_level,
                "Type":        issue_type,
                "Description": description,
                "Recommendation": self._recommendation(
                    user, aws_level, azure_level, aws_policy, azure_role,
                    gcp_level, gcp_role
                ),
            })

        return issues
