import pandas as pd
import os

class Reporting:
    def __init__(self, recommendations):
        self.recommendations = recommendations

    def generate_markdown_report(self, output_path):
        """
        Generates a user-friendly Markdown report of the recommendations.
        """
        if not self.recommendations:
            content = "# Multi-Cloud Privilege Harmonization Report\n\nNo issues detected. User privileges are synchronized across AWS and Azure."
        else:
            df = pd.DataFrame(self.recommendations)
            
            content = "# Multi-Cloud Privilege Harmonization Report\n\n"
            content += "## Identified Issues and Recommendations\n\n"
            
            for index, row in df.iterrows():
                user = row.get('UserName') or row.get('User_ID', 'N/A')
                content += f"### User: {user} ({row['Issue_Type']})\n"
                content += f"- **Observation**: {row['Observation']}\n"
                content += f"- **Recommendation**: {row['Recommendation']}\n\n"
                
            content += "## Summary Table\n\n"
            content += df.to_markdown(index=False)
            
        with open(output_path, 'w') as f:
            f.write(content)
            
        print(f"Report successfully generated at: {output_path}")

    def print_summary(self):
        """Prints a quick summary to the console."""
        print("\n--- Harmonization Summary ---")
        if not self.recommendations:
            print("All clear! No issues found.")
            return
            
        for rec in self.recommendations:
            user = rec.get('UserName') or rec.get('User_ID', 'N/A')
            print(f"[{user} - {rec['Issue_Type']}] {rec['Recommendation']}")
        print("-----------------------------\n")
