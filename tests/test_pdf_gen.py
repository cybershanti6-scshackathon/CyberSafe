"""Test PDF generation with realistic scan results."""
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Ensure we're in the right directory
os.chdir(project_root)

from msme_auditor.pdf_generator import generate_pdf

results = [
    {
        'control_id': 'RPP',
        'sub_control': 'RPP.1',
        'sub_control_name': 'Password Complexity & Expiry',
        'status': 'Failed',
        'score': 35,
        'severity': 'Critical',
        'summary': 'Password Complexity & Expiry issues: Minimum Password Length, Password Expiry, Password History',
        'finding_details': 'Found 3 issue(s)',
        'business_impact': 'CRITICAL RISK: Password Complexity & Expiry gaps create significant breach risk and regulatory exposure.',
        'ai_remediation': 'Fix all failed checks.',
        'remediation_script': '# Fix script',
        'checks': [
            {
                'check_id': 'min_length',
                'check_name': 'Minimum Password Length',
                'passed': False,
                'expected_value': 'At least 8 characters',
                'actual_value': '6 characters',
                'severity': 'High',
                'remediation_command': 'conf t\nsecurity passwords min-length 8\nend'
            },
            {
                'check_id': 'uppercase',
                'check_name': 'Uppercase Letters Required',
                'passed': True,
                'expected_value': 'Required',
                'actual_value': 'Enabled',
                'severity': 'High',
                'remediation_command': None
            },
            {
                'check_id': 'expiry',
                'check_name': 'Password Expiry',
                'passed': False,
                'expected_value': 'At most 90 days',
                'actual_value': '365 days',
                'severity': 'High',
                'remediation_command': 'conf t\nsecurity passwords aging 90\nend'
            },
            {
                'check_id': 'history',
                'check_name': 'Password History',
                'passed': False,
                'expected_value': 'At least 5 remembered',
                'actual_value': '0',
                'severity': 'Medium',
                'remediation_command': 'conf t\nsecurity passwords history 5\nend'
            }
        ],
        'target_system': '192.168.1.1',
        'scan_method': 'web',
        'scan_timestamp': '2026-08-24T10:30:00Z'
    },
    {
        'control_id': 'NES',
        'sub_control': 'NES.4',
        'sub_control_name': 'Email Security (SPF/DKIM/DMARC)',
        'status': 'Warning',
        'score': 67,
        'severity': 'High',
        'summary': 'Email Security issues: DMARC Policy',
        'finding_details': 'Found 1 issue(s)',
        'business_impact': 'HIGH RISK: Partial email security coverage leaves vulnerabilities.',
        'ai_remediation': 'Fix all failed checks.',
        'remediation_script': '# Fix script',
        'checks': [
            {
                'check_id': 'spf',
                'check_name': 'SPF Configured',
                'passed': True,
                'expected_value': 'SPF record present',
                'actual_value': 'v=spf1 include:_spf.google.com -all',
                'severity': 'High',
                'remediation_command': None
            },
            {
                'check_id': 'dmarc',
                'check_name': 'DMARC Policy',
                'passed': False,
                'expected_value': 'p=reject or p=quarantine',
                'actual_value': 'p=none',
                'severity': 'High',
                'remediation_command': 'Add DMARC DNS record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'
            }
        ],
        'target_system': 'example.com',
        'scan_method': 'dns_lookup',
        'scan_timestamp': '2026-08-24T10:31:00Z'
    }
]

print("Generating PDF with generate_pdf()...")
try:
    pdf_bytes = generate_pdf(
        results,
        title='CyberSure Security Report',
        target='192.168.1.1',
        scan_type='RPP - Password & Access Policy'
    )
    with open('test_report.pdf', 'wb') as f:
        f.write(pdf_bytes)
    print(f"SUCCESS! PDF generated: {len(pdf_bytes)} bytes")
    print(f"Saved to: test_report.pdf")
    
    # Verify PDF is not empty and starts with PDF header
    assert len(pdf_bytes) > 1000, f"PDF too small: {len(pdf_bytes)} bytes"
    assert pdf_bytes[:5] == b'%PDF-', f"Invalid PDF header: {pdf_bytes[:10]}"
    print("PDF validation passed!")
except Exception as e:
    import traceback
    print(f"ERROR: {e}")
    traceback.print_exc()
