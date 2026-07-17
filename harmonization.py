class Harmonization:
    def __init__(self, issues):
        self.issues = issues

    def generate_recommendations(self):
        """
        Converts raw issue dicts from PrivilegeAnalysis into the final
        recommendation records displayed in the dashboard.

        The new analysis engine already pre-computes a Recommendation string
        per issue. This layer ensures backward compatibility and fills in
        any missing recommendations.

        Supports two-platform (AWS + Azure) and three-platform
        (AWS + Azure + GCP) issue dicts.
        """
        recommendations = []

        for issue in self.issues:
            # Build a flat record the dashboard and reporter can consume.
            # GCP fields default to "N/A" / "NONE" for backward compatibility
            # with two-platform issue dicts that predate GCP support.
            rec = {
                "UserName":    issue.get("UserName") or issue.get("User_ID", "N/A"),
                "AWS_Policy":  issue.get("AWS_Policy", "N/A"),
                "AWS_Level":   issue.get("AWS_Level", "N/A"),
                "Azure_Role":  issue.get("Azure_Role", "N/A"),
                "Azure_Level": issue.get("Azure_Level", "N/A"),
                "GCP_Role":    issue.get("GCP_Role", "N/A"),
                "GCP_Level":   issue.get("GCP_Level", "NONE"),
                "Issue_Type":  issue.get("Type", "N/A"),
                "Observation": issue.get("Description", ""),
                "Recommendation": issue.get("Recommendation", ""),
            }

            # Fallback recommendation if the analysis layer didn't supply one
            if not rec["Recommendation"]:
                level_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
                aws_l  = rec["AWS_Level"]
                az_l   = rec["Azure_Level"]
                gcp_l  = rec["GCP_Level"]
                itype  = rec["Issue_Type"]

                if itype == "Excess Privilege":
                    rec["Recommendation"] = (
                        f"DOWNGRADE the highest privilege assignment to match the lowest "
                        f"active level across platforms (AWS={aws_l}, Azure={az_l}, GCP={gcp_l}). "
                        "Apply the Principle of Least Privilege."
                    )
                elif itype == "Inconsistency":
                    rec["Recommendation"] = (
                        f"Privilege mismatch detected (AWS={aws_l}, Azure={az_l}, GCP={gcp_l}). "
                        "Standardise access to the lowest required level across all active platforms."
                    )
                elif itype == "Missing Account/Role":
                    rec["Recommendation"] = (
                        "Provision the missing role/policy on the other platform(s), "
                        "or revoke unused access if the account is not needed cross-platform."
                    )

            recommendations.append(rec)

        return recommendations
