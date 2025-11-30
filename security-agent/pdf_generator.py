from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import sys

def generate_pdf_report(report_text, filename="soc_incident_report.pdf"):
    """
    Generates a PDF report from the provided text.
    Parses simple markdown-like syntax (# Headers, - Bullets).
    """
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = styles['Title']
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        spaceBefore=12,
        spaceAfter=6,
        textColor=colors.darkblue
    )
    normal_style = styles['BodyText']
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['BodyText'],
        leftIndent=20,
        spaceBefore=2,
        spaceAfter=2
    )

    story = []
    
    # Add Title
    story.append(Paragraph("SOC Incident Report", title_style))
    story.append(Spacer(1, 12))

    # Parse text line by line
    lines = report_text.split('\n')
    
    current_list = []

    def flush_list():
        if current_list:
            story.append(ListFlowable(
                current_list,
                bulletType='bullet',
                start='circle',
                leftIndent=20
            ))
            current_list.clear()
            story.append(Spacer(1, 6))

    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.startswith('#'):
            flush_list()
            # Remove # and whitespace
            header_text = line.lstrip('#').strip()
            story.append(Paragraph(header_text, heading_style))
            story.append(Spacer(1, 6))
            
        elif line.startswith('- ') or line.startswith('* '):
            bullet_text = line[2:].strip()
            current_list.append(ListItem(Paragraph(bullet_text, bullet_style)))
            
        else:
            flush_list()
            story.append(Paragraph(line, normal_style))
            story.append(Spacer(1, 6))

    flush_list()
    
    try:
        doc.build(story)
        print(f"PDF generated successfully: {filename}")
        return True
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return False

if __name__ == "__main__":
    # Test Data
    sample_report = """
    # Executive Summary
    Ransomware detected on FileServer01. Immediate action required.

    # Key Facts
    - Source: Unknown
    - Target: FileServer01
    - Type: Ransomware
    - Severity: High

    # Mitigation Plan
    - Isolate the infected server immediately.
    - Activate Incident Response Plan.
    - Preserve forensic evidence.
    
    # Threat Intelligence
    - IP 45.12.34.7 is flagged as Malicious.
    - Risk Score: 85/100.
    """
    generate_pdf_report(sample_report, "test_report.pdf")
