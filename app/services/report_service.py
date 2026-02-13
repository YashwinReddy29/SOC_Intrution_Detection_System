from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from app.models.database import get_logs

def generate_report():
    doc = SimpleDocTemplate("soc_report.pdf")
    styles = getSampleStyleSheet()
    elements = []

    logs = get_logs()

    for log in logs:
        elements.append(Paragraph(f"{log[1]} | Risk: {log[2]} | Threat: {log[3]}",
                                  styles["Normal"]))

    doc.build(elements)
