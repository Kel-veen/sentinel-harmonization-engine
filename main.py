import os
from src.data_loader import DataLoader
from src.normalization import Normalization
from src.analysis import PrivilegeAnalysis
from src.harmonization import Harmonization
from src.reporting import Reporting

def main():
    print("Starting Multi-Cloud Privilege Harmonization System...")
    
    # 1. Setup paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    aws_file = os.path.join(base_dir, 'data', 'aws_iam_simulated.json')
    azure_file = os.path.join(base_dir, 'data', 'azure_rbac_simulated.json')
    report_file = os.path.join(base_dir, 'harmonization_report.md')

    # 2. Data Loading
    print("Loading datasets...")
    loader = DataLoader(aws_file, azure_file)
    aws_data, azure_data = loader.load_all()

    # 3. Normalization
    print("Normalizing data into unified format...")
    normalizer = Normalization()
    unified_data = normalizer.get_unified_data(aws_data, azure_data)

    # 4. Privilege Analysis
    print("Analyzing privileges across platforms...")
    analyzer = PrivilegeAnalysis(unified_data)
    issues = analyzer.detect_inconsistencies()

    # 5. Harmonization
    print("Generating harmonized recommendations...")
    harmonizer = Harmonization(issues)
    recommendations = harmonizer.generate_recommendations()

    # 6. Reporting
    print("Compiling final report...")
    reporter = Reporting(recommendations)
    reporter.print_summary()
    reporter.generate_markdown_report(report_file)
    
    print("Workflow completed successfully.")

if __name__ == "__main__":
    main()
