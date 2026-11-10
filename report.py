"""Branded RansomwareShield-SA PDF report."""
import math
from io import BytesIO
from pathlib import Path

from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, String, Wedge
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

NAVY = colors.HexColor("#07051B")
PURPLE = colors.HexColor("#6F2CFF")
BLUE = colors.HexColor("#1677FF")
CYAN = colors.HexColor("#31C8FF")
SOFT = colors.HexColor("#F3F5FB")
LINE = colors.HexColor("#DFE3EF")
MUTED = colors.HexColor("#6B7090")
LEVEL_COLOURS = {"Strong": "#16A34A", "Good": "#6F2CFF", "Developing": "#D97706", "Weak": "#EA580C",
                 "Critical": "#DC2626", "Not assessable": "#6B7090"}


def level(s):
    if s is None:
        return "Not assessable"
    return "Critical" if s < 40 else "Weak" if s < 60 else "Developing" if s < 75 else "Good" if s < 90 else "Strong"


def radar(scores, size=78 * mm):
    d = Drawing(size, size)
    cx = cy = size / 2
    r = size * 0.33
    labels = list(scores.keys())
    n = len(labels)

    def pt(i, v):
        a = math.pi / 2 - i * 2 * math.pi / n
        return cx + math.cos(a) * r * v, cy + math.sin(a) * r * v

    for ring in range(1, 6):
        pts = []
        for i in range(n):
            pts += pt(i, ring / 5)
        d.add(Polygon(pts, strokeColor=LINE, fillColor=None, strokeWidth=0.6))
    for i, lab in enumerate(labels):
        x, y = pt(i, 1)
        d.add(Line(cx, cy, x, y, strokeColor=LINE, strokeWidth=0.6))
        lx, ly = pt(i, 1.22)
        d.add(String(lx, ly - 3, lab, fontName="Helvetica-Bold", fontSize=7.5, fillColor=NAVY, textAnchor="middle"))
    pts = []
    for i, lab in enumerate(labels):
        pts += pt(i, (scores[lab] or 0) / 100)
    d.add(Polygon(pts, strokeColor=PURPLE, strokeWidth=1.8, fillColor=colors.Color(0.435, 0.173, 1, alpha=0.22)))
    for i, lab in enumerate(labels):
        x, y = pt(i, (scores[lab] or 0) / 100)
        d.add(Circle(x, y, 2.4, fillColor=CYAN, strokeColor=colors.white, strokeWidth=0.8))
    return d


def seal(score, readiness, size=50 * mm):
    d = Drawing(size, size)
    c = size / 2
    col = colors.HexColor(LEVEL_COLOURS.get(readiness, "#6F2CFF"))
    d.add(Circle(c, c, size * 0.46, fillColor=SOFT, strokeColor=None))
    d.add(Wedge(c, c, size * 0.42, 90 - 360 * (score or 0) / 100, 90, fillColor=col, strokeColor=None))
    d.add(Circle(c, c, size * 0.33, fillColor=NAVY, strokeColor=None))
    d.add(String(c, c + 4, f"{score}%", fontName="Helvetica-Bold", fontSize=17, fillColor=colors.white, textAnchor="middle"))
    d.add(String(c, c - 10, readiness.upper(), fontName="Helvetica-Bold", fontSize=7.5, fillColor=CYAN, textAnchor="middle"))
    d.add(String(c, c - 19, "READINESS", fontName="Helvetica", fontSize=5.5, fillColor=colors.HexColor("#B8C0DF"), textAnchor="middle"))
    return d


def build(a, scores, weak, recs, summary, version, base_dir):
    buf = BytesIO()
    styles = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=9.2, leading=13)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=NAVY, fontSize=13, spaceBefore=10, spaceAfter=6, keepWithNext=1)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, textColor=MUTED, alignment=TA_CENTER)

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(PURPLE)
        canvas.rect(0, A4[1] - 4, A4[0], 4, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(17 * mm, 10 * mm, f"RansomwareShield-SA v{version}  |  RSA-{a.id:04d}  |  Confidential demonstration report - fictional academic data")
        canvas.drawRightString(A4[0] - 17 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=17 * mm, rightMargin=17 * mm, topMargin=14 * mm,
                            bottomMargin=18 * mm, title=f"RansomwareShield-SA Readiness Report RSA-{a.id:04d}",
                            author="RansomwareShield-SA")
    story = []
    logo_path = Path(base_dir) / "static" / "logo.jpg"
    logo = Image(str(logo_path), width=26 * mm, height=26 * mm) if logo_path.exists() else ""
    eyebrow = ParagraphStyle("ey", parent=body, fontSize=7.5, leading=10, textColor=CYAN, fontName="Helvetica-Bold")
    big = ParagraphStyle("big", parent=body, fontSize=19, leading=23, textColor=colors.white, fontName="Helvetica-Bold")
    sub = ParagraphStyle("sub", parent=body, fontSize=9, leading=12, textColor=colors.HexColor("#D9DEF2"))
    ref = ParagraphStyle("ref", parent=body, fontSize=7.5, leading=10, textColor=colors.HexColor("#9CA6C9"))
    title = [Paragraph("CYBERSECURITY READINESS ASSESSMENT", eyebrow), Paragraph("RansomwareShield-SA", big),
             Paragraph("Ransomware Readiness Report", sub), Paragraph(f"Reference RSA-{a.id:04d}", ref)]
    readiness = a.readiness or "Not assessable"
    score_p = [Paragraph(f"{a.overall_score}%", ParagraphStyle("sc", parent=big, fontSize=24, leading=28, alignment=TA_CENTER)),
               Paragraph(readiness.upper(), ParagraphStyle("lv", parent=eyebrow, fontSize=9.5, leading=12, alignment=TA_CENTER)),
               Paragraph("OVERALL READINESS", ParagraphStyle("ov", parent=ref, fontSize=6.5, alignment=TA_CENTER))]
    header = Table([[logo, title, score_p]], colWidths=[33 * mm, 90 * mm, 43 * mm], rowHeights=[38 * mm])
    header.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("ALIGN", (0, 0), (0, 0), "CENTER"), ("LEFTPADDING", (0, 0), (-1, -1), 9),
                                ("LINEBEFORE", (2, 0), (2, 0), 0.8, colors.HexColor("#3A3270"))]))
    story += [header, Spacer(1, 7 * mm)]

    details = Table([["Organisation", a.organisation], ["Prepared for", f"{a.user.fullname} ({a.user.role})"],
                     ["Completed", a.submitted_at.strftime("%d %B %Y, %H:%M UTC") if a.submitted_at else "Not recorded"],
                     ["Framework", "NIST CSF 2.0 (project-defined scoring)"],
                     ["Platform", f"RansomwareShield-SA v{version}"]], colWidths=[33 * mm, 72 * mm])
    details.setStyle(TableStyle([("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.3),
                                 ("TEXTCOLOR", (0, 0), (0, -1), NAVY), ("BACKGROUND", (0, 0), (0, -1), SOFT),
                                 ("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                 ("PADDING", (0, 0), (-1, -1), 5)]))
    top = Table([[details, seal(a.overall_score, readiness)]], colWidths=[108 * mm, 58 * mm])
    top.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "CENTER")]))
    story += [top, Spacer(1, 4 * mm)]

    badge_col = LEVEL_COLOURS.get(readiness, "#6F2CFF")
    badge_text = {"Strong": "STRONG PREPAREDNESS", "Good": "GOOD PREPAREDNESS", "Developing": "DEVELOPING READINESS",
                  "Weak": "IMPROVEMENT REQUIRED"}.get(readiness, "PRIORITY IMPROVEMENT REQUIRED")
    cen = lambda **k: ParagraphStyle("c" + str(len(k)) + str(k.get("fontSize")), parent=body, alignment=TA_CENTER, **k)
    badge = Table([[[Paragraph("READINESS BADGE", cen(fontSize=7, leading=10, textColor=colors.HexColor(badge_col), fontName="Helvetica-Bold")),
                     Paragraph(badge_text, cen(fontSize=15, leading=20, textColor=NAVY, fontName="Helvetica-Bold")),
                     Paragraph("Project-defined result. Not certification and not a guarantee of protection against ransomware.",
                               cen(fontSize=7.5, leading=10, textColor=MUTED))]]],
                  colWidths=[166 * mm])
    badge.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(badge_col)),
                               ("BACKGROUND", (0, 0), (-1, -1), SOFT), ("PADDING", (0, 0), (-1, -1), 8)]))
    story += [badge, Spacer(1, 4 * mm), Paragraph("Executive Summary", h2), Paragraph(summary, body)]

    rows = [["NIST CSF Function", "Score", "Level"]]
    for fn, s in scores.items():
        rows.append([fn, "N/A" if s is None else f"{s:.1f}%", level(s)])
    sc = Table(rows, colWidths=[38 * mm, 18 * mm, 26 * mm])
    style = [("BACKGROUND", (0, 0), (-1, 0), PURPLE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.3),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
             ("PADDING", (0, 0), (-1, -1), 5)]
    for i, (fn, s) in enumerate(scores.items(), start=1):
        style.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor(LEVEL_COLOURS[level(s)])))
        style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    sc.setStyle(TableStyle(style))
    profile = Table([[radar(scores), sc]], colWidths=[82 * mm, 84 * mm])
    profile.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story += [Paragraph("Readiness Profile", h2), profile]

    story.append(Paragraph("Priority Findings and Recommended Actions", h2))
    if weak:
        rr = [["Code", "Priority", "Finding and recommended action"]]
        for w in weak:
            rr.append([w.question.code, "Critical" if w.value == 1 else "High",
                       Paragraph(f"<b>{w.question.text}</b><br/><font color='#6B7090'>{recs[w.question.function]}</font>", body)])
        rt = Table(rr, colWidths=[16 * mm, 20 * mm, 130 * mm], repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
              ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.3),
              ("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]
        for i, w in enumerate(weak, start=1):
            st.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor("#DC2626" if w.value == 1 else "#EA580C")))
            st.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        rt.setStyle(TableStyle(st))
        story.append(rt)
    else:
        story.append(Paragraph("No score-triggered priority findings were generated.", body))

    story += [Spacer(1, 6 * mm), KeepTogether([
        Paragraph("Method and Limitations", h2),
        Paragraph("Answers on a 1-5 scale are converted to percentages and averaged per Function. The overall score "
                  "weights Govern and Protect at 20% and the remaining Functions at 15%. Readiness levels and risk "
                  "priorities are project-defined for this academic prototype and are not official NIST ratings. "
                  "This report reflects self-assessed responses and does not certify compliance or guarantee "
                  "protection against ransomware.", body),
        Spacer(1, 4 * mm),
        Paragraph("Generated by RansomwareShield-SA - Group 7, Project: Cyber Security", small)])]
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf
