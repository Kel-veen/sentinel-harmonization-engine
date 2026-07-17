import json
import os

class DataLoader:
    def __init__(self, aws_file_path, azure_file_path, gcp_file_path=None):
        self.aws_file_path = aws_file_path
        self.azure_file_path = azure_file_path
        self.gcp_file_path = gcp_file_path

    def load_aws_data(self):
        """Loads the AWS IAM JSON dataset."""
        if not os.path.exists(self.aws_file_path):
            raise FileNotFoundError(f"AWS data file not found: {self.aws_file_path}")
        with open(self.aws_file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_azure_data(self):
        """Loads the Azure RBAC JSON dataset."""
        if not os.path.exists(self.azure_file_path):
            raise FileNotFoundError(f"Azure data file not found: {self.azure_file_path}")
        with open(self.azure_file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_gcp_data(self):
        """Loads the GCP IAM JSON dataset."""
        if self.gcp_file_path is None:
            return None
        if not os.path.exists(self.gcp_file_path):
            raise FileNotFoundError(f"GCP data file not found: {self.gcp_file_path}")
        with open(self.gcp_file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_all(self):
        """Loads available datasets and returns them as a tuple."""
        aws_data = self.load_aws_data()
        azure_data = self.load_azure_data()
        gcp_data = self.load_gcp_data() if self.gcp_file_path else None
        return aws_data, azure_data, gcp_data
