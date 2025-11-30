import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
import graphviz
from gtts import gTTS
import time

def generate_pdf_report(report_text, filename="soc_report.pdf"):
    """
    Generates a PDF report from the given text.
    """
    try:
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = styles['Title']
        title_style.textColor = colors.darkblue
        story.append(Paragraph("SOC Incident Report", title_style))
        story.append(Spacer(1, 12))

        # Body
        body_style = styles['BodyText']
        for line in report_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line, body_style))
                story.append(Spacer(1, 6))

        doc.build(story)
        return filename
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None

def create_threat_graph(source_ip, target, attack_type):
    """
    Creates a simple threat graph using Graphviz.
    Returns the graph object.
    """
    try:
        dot = graphviz.Digraph(comment='Threat Graph')
        dot.attr(rankdir='LR', bgcolor='#0E1117') # Dark background
        
        # Node styles
        dot.attr('node', shape='box', style='filled', color='white', fontname='Courier')
        
        # Nodes
        dot.node('A', f'Attacker\n{source_ip}', fillcolor='#FF4B4B', fontcolor='white') # Red
        dot.node('B', 'Firewall/IPS', fillcolor='#FFA500', fontcolor='black') # Orange
        dot.node('C', f'Target\n{target}', fillcolor='#00CC96', fontcolor='black') # Green
        
        # Edges
        dot.edge('A', 'B', label=attack_type, color='white', fontcolor='white')
        dot.edge('B', 'C', label='Allowed/Blocked', color='white', fontcolor='white')
        
        return dot
    except Exception as e:
        print(f"Error creating graph: {e}")
        return None

def generate_audio_summary(text, filename="summary.mp3"):
    """
    Generates an audio file from text using gTTS.
    """
    try:
        tts = gTTS(text=text, lang='en')
        tts.save(filename)
        return filename
    except Exception as e:
        print(f"Error generating audio: {e}")
        return None

def tail_log_file(filepath):
    """
    Generator that yields new lines from a log file.
    """
    try:
        with open(filepath, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except Exception as e:
        print(f"Error reading log file: {e}")
