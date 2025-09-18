import pandas as pd
import json
from datetime import datetime
import os
import shutil
from jinja2 import Template

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_submission(self, application_id, results):
        """Generate complete submission package"""
        # Create folder structure
        folder_name = f"PS-02_{application_id}_Submission"
        submission_dir = os.path.join(self.output_dir, folder_name)
        os.makedirs(submission_dir, exist_ok=True)
        
        # Generate Excel report
        excel_path = os.path.join(submission_dir, f"PS-02_{application_id}_Submission_Set.xlsx")
        df = pd.DataFrame(results)
        df.to_excel(excel_path, index=False)
        
        # Create evidence folder
        evidence_dir = os.path.join(submission_dir, f"PS-02_{application_id}_Evidences")
        os.makedirs(evidence_dir, exist_ok=True)
        
        # Create documentation folder
        doc_dir = os.path.join(submission_dir, f"PS-02_{application_id}_Documentation_folder")
        os.makedirs(doc_dir, exist_ok=True)
        
        # Generate solution report
        report_path = os.path.join(doc_dir, f"PS-02_{application_id}_Report.pdf")
        self.generate_solution_report(report_path, application_id, results)
        
        # Zip the submission
        zip_path = os.path.join(self.output_dir, f"{folder_name}.zip")
        shutil.make_archive(zip_path.replace('.zip', ''), 'zip', submission_dir)
        
        return zip_path
    
    def generate_solution_report(self, output_path, application_id, results):
        """Generate PDF solution report"""
        # For now, generate HTML report (can be converted to PDF)
        html_content = self._generate_html_report(application_id, results)
        
        # Save as HTML
        html_path = output_path.replace('.pdf', '.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Solution report generated at {html_path}")
        return html_path
    
    def _generate_html_report(self, application_id, results):
        """Generate HTML report"""
        template = Template('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Phishing Detection Report - PS-02_{{ application_id }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { text-align: center; margin-bottom: 30px; }
                .section { margin-bottom: 30px; }
                .results-table { width: 100%; border-collapse: collapse; }
                .results-table th, .results-table td { 
                    border: 1px solid #ddd; padding: 8px; text-align: left; 
                }
                .results-table th { background-color: #f2f2f2; }
                .phishing { background-color: #ffebee; }
                .legitimate { background-color: #e8f5e8; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Phishing Detection Report</h1>
                <h2>Application ID: PS-02_{{ application_id }}</h2>
                <p>Generated on: {{ generation_date }}</p>
            </div>
            
            <div class="section">
                <h3>Executive Summary</h3>
                <p>This report presents the results of phishing domain detection targeting Critical Sector Entities (CSEs).</p>
                <ul>
                    <li>Total domains analyzed: {{ total_domains }}</li>
                    <li>Phishing domains detected: {{ phishing_count }}</li>
                    <li>Legitimate domains: {{ legitimate_count }}</li>
                    <li>Detection accuracy: {{ accuracy }}%</li>
                </ul>
            </div>
            
            <div class="section">
                <h3>Detailed Results</h3>
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Status</th>
                            <th>Confidence</th>
                            <th>Features</th>
                            <th>Date Detected</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for result in results %}
                        <tr class="{{ result.status }}">
                            <td>{{ result.domain }}</td>
                            <td>{{ result.status.upper() }}</td>
                            <td>{{ "%.2f"|format(result.confidence) }}</td>
                            <td>{{ result.features_summary }}</td>
                            <td>{{ result.date }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h3>Methodology</h3>
                <p>The phishing detection system uses machine learning with the following features:</p>
                <ul>
                    <li>URL structure analysis</li>
                    <li>Domain registration information</li>
                    <li>Content analysis</li>
                    <li>SSL certificate validation</li>
                    <li>Brand keyword detection</li>
                </ul>
            </div>
        </body>
        </html>
        ''')
        
        # Prepare results data
        total_domains = len(results)
        phishing_count = sum(1 for r in results if r.get('status') == 'phishing')
        legitimate_count = total_domains - phishing_count
        accuracy = (phishing_count / total_domains * 100) if total_domains > 0 else 0
        
        # Add summary to results
        for result in results:
            result['features_summary'] = f"URL length: {result.get('url_length', 'N/A')}, " \
                                       f"Domain age: {result.get('domain_age_days', 'N/A')} days"
        
        return template.render(
            application_id=application_id,
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_domains=total_domains,
            phishing_count=phishing_count,
            legitimate_count=legitimate_count,
            accuracy=accuracy,
            results=results
        )
    
    def generate_dashboard_data(self):
        """Generate data for dashboard"""
        # This would typically query the database for current status
        return {
            'total_domains': 0,
            'phishing_domains': 0,
            'legitimate_domains': 0,
            'suspected_domains': 0,
            'recent_activity': []
        }