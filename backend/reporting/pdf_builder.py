from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def save_pdf(result, ledger, path):
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SecureMailScope — Cryptographic Security Forensic Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph(f"<b>Source:</b> {result.get('source','')}", styles["BodyText"]),
        Paragraph(f"<b>Posture:</b> {result.get('overall_score',0)}/100 — {result.get('overall_posture','')}", styles["Heading2"]),
        Spacer(1, 10),
        Paragraph("AI Summary", styles["Heading2"]),
        Paragraph(result.get("ai_summary",""), styles["BodyText"]),
        Spacer(1, 10),
        Paragraph("Findings", styles["Heading2"]),
    ]
    data = [["Severity","Finding","Evidence"]]
    for f in result.get("findings", []):
        data.append([f.get("severity",""), f.get("title",""), f.get("evidence","")])
    table = Table(data, colWidths=[65,190,260], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),
        ("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTSIZE",(0,0),(-1,-1),8),
    ]))
    story += [table, Spacer(1,12), Paragraph("Evidence Integrity Ledger", styles["Heading2"]),
              Paragraph(f"Block: {ledger.get('block_number','')}<br/>Current Hash: {ledger.get('current_hash','')}<br/>Evidence Hash: {ledger.get('evidence_hash','')}<br/>Report Hash: {ledger.get('report_hash','')}", styles["BodyText"])]
    doc.build(story)
