import os
import json
import datetime
import logging
from typing import Dict, Any, List
from app.core.config import settings

logger = logging.getLogger(__name__)

# Try importing ReportLab
REPORTLAB_AVAILABLE = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    logger.warning("ReportLab is not available. PDF export will use JSON/HTML export fallback.")

def generate_report_summary(
    dataset_name: str,
    model_name: str,
    algorithm: str,
    accuracy: float,
    detection_summary: Dict[str, Any],
    threats: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Synthesizes security findings into structured report metadata.
    """
    total = detection_summary["total_records"]
    malicious = detection_summary["malicious_count"]
    benign = detection_summary["benign_count"]
    critical = detection_summary["critical_count"]
    
    # Calculate attack distribution
    attack_counts = {}
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    recs_by_attack = {}
    
    for t in threats:
        attack = t["attack_type"]
        sev = t["severity"]
        
        attack_counts[attack] = attack_counts.get(attack, 0) + 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Accumulate recommendations
        if sev != "Low" and attack not in recs_by_attack:
            recs_by_attack[attack] = t["recommended_actions"][:3]
            
    # Auto-generate key findings (bullets)
    findings = []
    if malicious > 0:
        mal_pct = (malicious / total) * 100
        findings.append(f"Intrusion activity detected: {malicious} of {total} records ({mal_pct:.1f}%) classified as malicious.")
        
        # Get highest risk attack
        sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        top_attacks = [a for a, c in sorted_attacks if a.lower() not in ["benign", "normal"]]
        
        if top_attacks:
            findings.append(f"Primary attack vector: {top_attacks[0]} was the most frequent incident category.")
            
        if critical > 0:
            findings.append(f"Immediate action required: {critical} security events classified as CRITICAL severity.")
    else:
        findings.append("No active network threats or anomalies were identified in the analyzed dataset sample.")
        
    findings.append(f"Model verification: Threat evaluation completed with a {accuracy*100:.1f}% test accuracy rating using the '{algorithm}' classifier.")
    
    summary = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_name": dataset_name,
        "model_name": model_name,
        "model_algorithm": algorithm,
        "model_accuracy": accuracy,
        "total_records": total,
        "benign_records": benign,
        "malicious_records": malicious,
        "critical_records": critical,
        "attack_distribution": attack_counts,
        "severity_distribution": severity_counts,
        "key_findings": findings,
        "recommendations": recs_by_attack
    }
    return summary

def export_pdf_report(summary: Dict[str, Any], filepath: str) -> str:
    """
    Creates a professional PDF report on the disk.
    If ReportLab is unavailable, serializes the report to a formatted JSON instead.
    """
    if not REPORTLAB_AVAILABLE:
        # Fallback to JSON file
        json_path = filepath.replace(".pdf", ".json")
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=4)
        return json_path
        
    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    styles = getSampleStyleSheet()
    
    # Custom Palette - SOC Dashboard styling
    COLOR_PRIMARY = colors.HexColor("#0f172a") # Slate-900
    COLOR_SECONDARY = colors.HexColor("#475569") # Slate-600
    COLOR_ACCENT = colors.HexColor("#0284c7") # Cyan-600
    COLOR_ALERT = colors.HexColor("#e11d48") # Rose-600
    COLOR_BORDER = colors.HexColor("#cbd5e1") # Slate-300
    
    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=COLOR_PRIMARY,
        spaceAfter=15,
        leading=28
    )
    
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_SECONDARY,
        spaceAfter=25,
        leading=14
    )
    
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=COLOR_PRIMARY,
        spaceBefore=15,
        spaceAfter=10,
        leading=18
    )
    
    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8,
        leading=14
    )
    
    finding_style = ParagraphStyle(
        "FindingText",
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=6
    )

    # Document Header
    story.append(Paragraph("IoT Sentinel - Security Assessment Report", title_style))
    story.append(Paragraph(f"Generated: {summary['generated_at']} | Source: {summary['dataset_name']} | Model: {summary['model_name']} ({summary['model_algorithm']})", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Executive Summary Metrics
    story.append(Paragraph("1. Executive Summary", h2_style))
    
    kpi_data = [
        [
            Paragraph("<b>Total Records Analyzed:</b>", body_style),
            Paragraph(str(summary["total_records"]), body_style),
            Paragraph("<b>Threats Detected:</b>", body_style),
            Paragraph(f"<font color='{COLOR_ALERT}'><b>{summary['malicious_records']}</b></font>", body_style)
        ],
        [
            Paragraph("<b>Benign Traffic:</b>", body_style),
            Paragraph(str(summary["benign_records"]), body_style),
            Paragraph("<b>Critical Threat Events:</b>", body_style),
            Paragraph(f"<b>{summary['critical_records']}</b>", body_style)
        ],
        [
            Paragraph("<b>Analysis Model:</b>", body_style),
            Paragraph(summary["model_name"], body_style),
            Paragraph("<b>Detection Accuracy:</b>", body_style),
            Paragraph(f"{summary['model_accuracy']*100:.2f}%", body_style)
        ]
    ]
    
    kpi_table = Table(kpi_data, colWidths=[140, 120, 140, 120])
    kpi_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('PADDING', (0,0), (-1,-1), 8),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 15))
    
    # Key Findings
    story.append(Paragraph("2. Critical Security Findings", h2_style))
    for f in summary["key_findings"]:
        story.append(Paragraph(f"• {f}", finding_style))
    story.append(Spacer(1, 15))
    
    # Threat Distribution
    story.append(Paragraph("3. Threat Profile Breakdown", h2_style))
    
    threat_headers = ["Attack Category", "Record Count", "Percentage"]
    threat_rows = [threat_headers]
    for attack, count in summary["attack_distribution"].items():
        pct = (count / summary["total_records"]) * 100
        threat_rows.append([
            attack, 
            str(count), 
            f"{pct:.2f}%"
        ])
        
    threat_table = Table(threat_rows, colWidths=[200, 160, 160])
    threat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLOR_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    story.append(threat_table)
    story.append(Spacer(1, 15))
    
    # Recommended Response Actions
    if summary["recommendations"]:
        story.append(Paragraph("4. Recommended Mitigation Strategies", h2_style))
        for attack, recs in summary["recommendations"].items():
            story.append(Paragraph(f"<b>For {attack} Traffic:</b>", body_style))
            for r in recs:
                story.append(Paragraph(f"  - {r}", finding_style))
            story.append(Spacer(1, 5))
            
    doc.build(story)
    return filepath
