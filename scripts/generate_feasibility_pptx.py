"""
CyberSure — Feasibility & Viability Presentation Generator
===========================================================
Run:  python generate_feasibility_pptx.py
Output: CyberSure_Feasibility_Viability.pptx
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ── Colors ──────────────────────────────────────────────────────
PRIMARY    = RGBColor(0x0E, 0xA5, 0xC6)   # #0ea5c6  Cyan
ACCENT     = RGBColor(0x6C, 0x63, 0xFF)   # #6c63ff  Purple
DARK       = RGBColor(0x0F, 0x27, 0x40)   # #0f2740  Navy
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_BG   = RGBColor(0xF7, 0xFB, 0xFF)
MUTED      = RGBColor(0x5C, 0x72, 0x87)
SUCCESS    = RGBColor(0x16, 0xA3, 0x4A)
WARNING    = RGBColor(0xD9, 0x77, 0x06)
DANGER     = RGBColor(0xDC, 0x26, 0x26)
SURFACE    = RGBColor(0xEE, 0xF8, 0xFF)


def set_slide_bg(slide, color):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_shape_box(slide, left, top, width, height, fill_color, border_color=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def add_text_box(slide, left, top, width, height, text, font_size=14, bold=False,
                 color=DARK, alignment=PP_ALIGN.LEFT, font_name="Calibri"):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.color.rgb = color
    p.font.name = font_name
    p.alignment = alignment
    return txBox


def add_bullet_slide(slide, items, left, top, width, height,
                     font_size=16, color=DARK, spacing=Pt(8), icon="▸"):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = f"{icon}  {item}"
        p.font.size = Pt(font_size)
        p.font.color.rgb = color
        p.font.name = "Calibri"
        p.space_after = spacing
        p.space_before = Pt(2)
    return txBox


def add_section_header(slide, title, subtitle, emoji=""):
    """Add a styled section header to a content slide."""
    # Title
    full_title = f"{emoji}  {title}" if emoji else title
    add_text_box(slide, Inches(0.8), Inches(0.4), Inches(8.4), Inches(0.6),
                 full_title, font_size=28, bold=True, color=PRIMARY)
    # Subtitle
    add_text_box(slide, Inches(0.8), Inches(1.05), Inches(8.4), Inches(0.4),
                 subtitle, font_size=14, color=MUTED)
    # Divider line
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                  Inches(0.8), Inches(1.5), Inches(8.4), Pt(2))
    line.fill.solid()
    line.fill.fore_color.rgb = PRIMARY
    line.line.fill.background()


# ════════════════════════════════════════════════════════════════
#  BUILD PRESENTATION
# ════════════════════════════════════════════════════════════════

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# ── SLIDE 1: Title Slide ───────────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
set_slide_bg(slide, DARK)

# Gradient accent bar at top
bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                             Inches(0), Inches(0), Inches(13.333), Pt(6))
bar.fill.solid()
bar.fill.fore_color.rgb = PRIMARY
bar.line.fill.background()

add_text_box(slide, Inches(1.5), Inches(1.5), Inches(10), Inches(0.6),
             "🛡️  CYBERSURE", font_size=20, bold=True, color=PRIMARY,
             alignment=PP_ALIGN.CENTER)

add_text_box(slide, Inches(1.5), Inches(2.2), Inches(10), Inches(1.2),
             "Feasibility & Viability Analysis", font_size=44, bold=True,
             color=WHITE, alignment=PP_ALIGN.CENTER)

add_text_box(slide, Inches(1.5), Inches(3.5), Inches(10), Inches(0.8),
             "CERT-In Compliance Security Platform for MSMEs",
             font_size=22, color=PRIMARY, alignment=PP_ALIGN.CENTER)

add_text_box(slide, Inches(1.5), Inches(4.5), Inches(10), Inches(0.6),
             "Automated Cybersecurity Assessment  •  63M+ Indian MSMEs  •  Regulatory Compliance",
             font_size=14, color=MUTED, alignment=PP_ALIGN.CENTER)

# Bottom badge
badge = add_shape_box(slide, Inches(4.5), Inches(5.8), Inches(4.3), Inches(0.55),
                       SURFACE, PRIMARY)
tf = badge.text_frame
tf.paragraphs[0].text = "Technical • Market • Revenue • Scalability"
tf.paragraphs[0].font.size = Pt(14)
tf.paragraphs[0].font.bold = True
tf.paragraphs[0].font.color.rgb = PRIMARY
tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SLIDE 2: What is CyberSure? ────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "What is CyberSure?",
                   "One-click CERT-In compliance for every Indian MSME", "🛡️")

modules = [
    ("RPP", "Password Policy\n4 scanners — complexity, lockout, MFA, hash"),
    ("NES", "Network & Email\n4 scanners — ports, Wi-Fi, TLS, SPF/DKIM"),
    ("Web Security", "Website Checks\nSSL, headers, DNS configuration"),
    ("Devices", "Multi-Vendor\nCisco / Fortinet / Juniper config parsing"),
    ("AI Assistant", "Smart Guidance\nGemini-powered remediation advice"),
]

for i, (title, desc) in enumerate(modules):
    x = Inches(0.8 + i * 2.45)
    box = add_shape_box(slide, x, Inches(2.0), Inches(2.2), Inches(2.4),
                         WHITE, RGBColor(0xD7, 0xE8, 0xF2))
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(18)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = PRIMARY
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    p2 = tf.add_paragraph()
    p2.text = ""
    p3 = tf.add_paragraph()
    p3.text = desc
    p3.font.size = Pt(12)
    p3.font.color.rgb = MUTED
    p3.alignment = PP_ALIGN.CENTER

add_text_box(slide, Inches(0.8), Inches(4.8), Inches(11.7), Inches(0.8),
             "Architecture: Python FastAPI backend  •  Plugin-based scanner registry  •  "
             "Responsive HTML/CSS/JS frontend  •  PDF reporting  •  Knowledge base training",
             font_size=13, color=MUTED, alignment=PP_ALIGN.CENTER)

# Key stat boxes
stats = [("9", "Scanners"), ("5", "Modules"), ("20+", "API Endpoints"), ("3", "Vendor Parsers")]
for i, (num, label) in enumerate(stats):
    x = Inches(0.8 + i * 3.1)
    box = add_shape_box(slide, x, Inches(5.7), Inches(2.8), Inches(1.1), WHITE, PRIMARY)
    tf = box.text_frame
    tf.paragraphs[0].text = num
    tf.paragraphs[0].font.size = Pt(32)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = PRIMARY
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    p2 = tf.add_paragraph()
    p2.text = label
    p2.font.size = Pt(13)
    p2.font.color.rgb = MUTED
    p2.alignment = PP_ALIGN.CENTER


# ── SLIDE 3: Technical Feasibility ─────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Technical Feasibility",
                   "Is it possible to build? YES — and it's already built.", "⚙️")

tech_points = [
    ("✅  Fully Functional MVP",
     "9 scanners, FastAPI backend, polished responsive frontend — working end-to-end today"),
    ("✅  Extensible Plugin Architecture",
     "New CERT-In controls added by dropping a single file — zero changes to core code"),
    ("✅  Vendor Config Intelligence",
     "Upload Cisco/Fortinet config → auto-normalize → CERT-In audit → remediation"),
    ("✅  AI-Powered Remediation",
     "Gemini integration with deterministic fallback — every failed check gets actionable fixes"),
]

for i, (title, desc) in enumerate(tech_points):
    y = Inches(1.8 + i * 1.3)
    box = add_shape_box(slide, Inches(0.8), y, Inches(11.7), Inches(1.1), WHITE,
                         RGBColor(0xD7, 0xE8, 0xF2))
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(17)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = DARK
    p2 = tf.add_paragraph()
    p2.text = desc
    p2.font.size = Pt(13)
    p2.font.color.rgb = MUTED
    p2.space_before = Pt(4)

# Rating badge
rating_box = add_shape_box(slide, Inches(4), Inches(6.4), Inches(5.3), Inches(0.6),
                            SUCCESS)
tf = rating_box.text_frame
tf.paragraphs[0].text = "⭐⭐⭐⭐⭐  Overall Technical Rating: HIGH"
tf.paragraphs[0].font.size = Pt(16)
tf.paragraphs[0].font.bold = True
tf.paragraphs[0].font.color.rgb = WHITE
tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SLIDE 4: Market Viability ──────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Market Viability",
                   "Is there demand? 63M+ MSMEs + mandatory CERT-In compliance = massive need.", "💰")

market_points = [
    ("63M+ MSMEs in India",
     "80%+ lack any cybersecurity tooling — massive untapped market"),
    ("CERT-In Mandate (April 2022)",
     "Compliance is now mandatory, not optional — creating urgent regulatory demand"),
    ("Price Gap in Competition",
     "Enterprise tools cost ₹10-50 Lakh/yr; CyberSure serves MSMEs at ₹5K-50K/yr"),
    ("No Direct Competitor",
     "No existing product automates CERT-In compliance checks for Indian MSMEs"),
]

for i, (title, desc) in enumerate(market_points):
    y = Inches(1.8 + i * 1.3)
    box = add_shape_box(slide, Inches(0.8), y, Inches(11.7), Inches(1.1), WHITE,
                         RGBColor(0xD7, 0xE8, 0xF2))
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(17)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = DARK
    p2 = tf.add_paragraph()
    p2.text = desc
    p2.font.size = Pt(13)
    p2.font.color.rgb = MUTED
    p2.space_before = Pt(4)

rating_box = add_shape_box(slide, Inches(4), Inches(6.4), Inches(5.3), Inches(0.6),
                            SUCCESS)
tf = rating_box.text_frame
tf.paragraphs[0].text = "⭐⭐⭐⭐⭐  Overall Market Rating: HIGH"
tf.paragraphs[0].font.size = Pt(16)
tf.paragraphs[0].font.bold = True
tf.paragraphs[0].font.color.rgb = WHITE
tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SLIDE 5: Revenue Viability ─────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Revenue Viability",
                   "Can it make money? YES — multiple proven SaaS monetization models.", "💵")

revenue_models = [
    ("Freemium SaaS", "Free basic scans drive adoption;\npaid full audits + PDF reports\nconvert to paying customers", "⭐⭐⭐⭐⭐"),
    ("Per-Scan Pricing", "₹50-500 per audit run;\nlow barrier to entry;\npay-as-you-go model", "⭐⭐⭐⭐"),
    ("Annual Subscription", "₹5,000-50,000/yr per company;\npredictable recurring revenue;\ncontinuous monitoring", "⭐⭐⭐⭐"),
    ("White-Label License", "License to CAs & auditors;\nB2B channel distribution;\nenterprise revenue stream", "⭐⭐⭐⭐"),
]

for i, (title, desc, stars) in enumerate(revenue_models):
    x = Inches(0.8 + i * 3.1)
    box = add_shape_box(slide, x, Inches(1.8), Inches(2.8), Inches(3.2), WHITE,
                         RGBColor(0xD7, 0xE8, 0xF2))
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(18)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = PRIMARY
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    p2 = tf.add_paragraph()
    p2.text = ""
    p3 = tf.add_paragraph()
    p3.text = desc
    p3.font.size = Pt(12)
    p3.font.color.rgb = MUTED
    p3.alignment = PP_ALIGN.CENTER

    p4 = tf.add_paragraph()
    p4.text = ""
    p5 = tf.add_paragraph()
    p5.text = stars
    p5.font.size = Pt(14)
    p5.font.color.rgb = WARNING
    p5.alignment = PP_ALIGN.CENTER

# Bottom note
add_text_box(slide, Inches(0.8), Inches(5.3), Inches(11.7), Inches(0.5),
             "Low marginal cost  •  Software scales without per-audit human cost  •  High profit margins",
             font_size=14, color=MUTED, alignment=PP_ALIGN.CENTER)

rating_box = add_shape_box(slide, Inches(4), Inches(5.9), Inches(5.3), Inches(0.6),
                            SUCCESS)
tf = rating_box.text_frame
tf.paragraphs[0].text = "⭐⭐⭐⭐  Overall Revenue Rating: HIGH"
tf.paragraphs[0].font.size = Pt(16)
tf.paragraphs[0].font.bold = True
tf.paragraphs[0].font.color.rgb = WHITE
tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SLIDE 6: Growth & Scalability ──────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Growth & Scalability",
                   "Can it grow? YES — architecture and market support rapid scaling.", "🚀")

growth_points = [
    ("Cloud-Ready Architecture",
     "FastAPI + stateless design → Docker deployment + horizontal scaling is straightforward"),
    ("Regulatory Expansion",
     "As CERT-In updates controls, new scanners added rapidly via the plugin system"),
    ("AI Knowledge Base",
     "Human-in-the-loop training improves parser accuracy over time — product gets smarter"),
    ("Multi-Channel Distribution",
     "SaaS portal, embedded for auditors, government MSME schemes, API marketplace"),
]

for i, (title, desc) in enumerate(growth_points):
    y = Inches(1.8 + i * 1.3)
    box = add_shape_box(slide, Inches(0.8), y, Inches(11.7), Inches(1.1), WHITE,
                         RGBColor(0xD7, 0xE8, 0xF2))
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(17)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = DARK
    p2 = tf.add_paragraph()
    p2.text = desc
    p2.font.size = Pt(13)
    p2.font.color.rgb = MUTED
    p2.space_before = Pt(4)

rating_box = add_shape_box(slide, Inches(4), Inches(6.4), Inches(5.3), Inches(0.6),
                            PRIMARY)
tf = rating_box.text_frame
tf.paragraphs[0].text = "⭐⭐⭐⭐  Overall Scalability Rating: HIGH"
tf.paragraphs[0].font.size = Pt(16)
tf.paragraphs[0].font.bold = True
tf.paragraphs[0].font.color.rgb = WHITE
tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SLIDE 7: Risk Assessment ───────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Risk Assessment",
                   "What could go wrong — and how we mitigate each risk.", "⚠️")

risks = [
    ("Legal Liability", "HIGH", "Scanning without authorization",
     "Authorization notices + consent flow + target ownership verification built in"),
    ("Regulation Changes", "MED", "CERT-In updates compliance controls",
     "Plugin architecture allows adding new controls within days, not months"),
    ("False Positives", "MED", "Config parsers may misclassify commands",
     "Knowledge base with human approval loop + confidence scoring"),
    ("Scale Limitations", "MED", "Currently single-user local server",
     "Stateless FastAPI design supports Docker + cloud deployment easily"),
]

# Header row
for j, header in enumerate(["Risk", "Level", "Description", "Mitigation"]):
    widths = [Inches(2), Inches(1), Inches(3.5), Inches(5.2)]
    x = Inches(0.8 + sum(widths[:j]))
    add_text_box(slide, x, Inches(1.8), widths[j], Inches(0.4),
                 header, font_size=13, bold=True, color=PRIMARY)

for i, (risk, level, desc, mitigation) in enumerate(risks):
    y = Inches(2.3 + i * 1.1)
    bg_color = WHITE
    box = add_shape_box(slide, Inches(0.8), y, Inches(11.7), Inches(0.95),
                         bg_color, RGBColor(0xD7, 0xE8, 0xF2))

    # Risk name
    add_text_box(slide, Inches(1.0), y + Pt(6), Inches(1.8), Inches(0.8),
                 risk, font_size=14, bold=True, color=DARK)

    # Level badge
    level_color = DANGER if level == "HIGH" else WARNING
    badge = add_shape_box(slide, Inches(3.0), y + Pt(8), Inches(0.8), Inches(0.35),
                           level_color)
    tf = badge.text_frame
    tf.paragraphs[0].text = level
    tf.paragraphs[0].font.size = Pt(10)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = WHITE
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    # Description
    add_text_box(slide, Inches(4.0), y + Pt(6), Inches(3.3), Inches(0.8),
                 desc, font_size=12, color=MUTED)

    # Mitigation
    add_text_box(slide, Inches(7.5), y + Pt(6), Inches(4.8), Inches(0.8),
                 mitigation, font_size=12, color=SUCCESS)


# ── SLIDE 8: Product Roadmap ───────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Product Roadmap",
                   "From MVP to market-leading SaaS platform.", "🗺️")

phases = [
    ("Phase 1", "Productionize", "Docker, auth, database,\nrate limiting", "2-4 weeks"),
    ("Phase 2", "Cloud Deploy", "AWS/Vercel + managed DB\n+ CI/CD", "1-2 weeks"),
    ("Phase 3", "More Scanners", "Full CERT-In framework:\nbackup, access, physical", "4-6 weeks"),
    ("Phase 4", "Monitoring", "Scheduled scans, alerts,\ntrend tracking", "2-3 weeks"),
    ("Phase 5", "Multi-Tenant", "Company accounts, team\naccess, billing", "4-6 weeks"),
    ("Phase 6", "Mobile App", "React Native / PWA for\non-site auditors", "4-6 weeks"),
]

for i, (phase, title, desc, timeline) in enumerate(phases):
    x = Inches(0.8 + i * 2.05)
    # Phase number circle
    circle = slide.shapes.add_shape(MSO_SHAPE.OVAL, x + Inches(0.7), Inches(2.0),
                                     Inches(0.5), Inches(0.5))
    circle.fill.solid()
    circle.fill.fore_color.rgb = PRIMARY
    circle.line.fill.background()
    tf = circle.text_frame
    tf.paragraphs[0].text = str(i + 1)
    tf.paragraphs[0].font.size = Pt(14)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = WHITE
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    # Connector line
    if i < len(phases) - 1:
        line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                       x + Inches(1.2), Inches(2.2),
                                       Inches(1.55), Pt(2))
        line.fill.solid()
        line.fill.fore_color.rgb = PRIMARY
        line.line.fill.background()

    # Card
    box = add_shape_box(slide, x, Inches(2.7), Inches(1.85), Inches(2.8), WHITE,
                         RGBColor(0xD7, 0xE8, 0xF2))
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = phase
    tf.paragraphs[0].font.size = Pt(11)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = ACCENT
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    p2 = tf.add_paragraph()
    p2.text = title
    p2.font.size = Pt(15)
    p2.font.bold = True
    p2.font.color.rgb = DARK
    p2.alignment = PP_ALIGN.CENTER

    p3 = tf.add_paragraph()
    p3.text = ""
    p4 = tf.add_paragraph()
    p4.text = desc
    p4.font.size = Pt(11)
    p4.font.color.rgb = MUTED
    p4.alignment = PP_ALIGN.CENTER

    p5 = tf.add_paragraph()
    p5.text = ""
    p6 = tf.add_paragraph()
    p6.text = f"⏱️  {timeline}"
    p6.font.size = Pt(11)
    p6.font.bold = True
    p6.font.color.rgb = PRIMARY
    p6.alignment = PP_ALIGN.CENTER


# ── SLIDE 9: Competitive Landscape ─────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, LIGHT_BG)
add_section_header(slide, "Competitive Landscape",
                   "CyberSure vs. existing alternatives.", "🏆")

competitors = [
    ("Feature", "CyberSure", "Qualys / Nessus", "Manual Audits", "CERT-In Docs"),
    ("Price", "₹5K-50K/yr ✅", "₹10-50 Lakh/yr ❌", "₹2-10 Lakh ❌", "Free ✅"),
    ("CERT-In Specific", "Yes ✅", "Generic ❌", "Partial ⚠️", "Yes (text) ⚠️"),
    ("Automated", "Fully ✅", "Fully ✅", "No ❌", "No ❌"),
    ("MSME Friendly", "Yes ✅", "No ❌", "No ❌", "No ❌"),
    ("Vendor Config", "Yes ✅", "Limited ⚠️", "No ❌", "No ❌"),
    ("AI Remediation", "Yes ✅", "No ❌", "Expert Only ⚠️", "No ❌"),
    ("Setup Time", "5 minutes ✅", "Days/Weeks ❌", "Weeks ❌", "N/A"),
]

for row_idx, row in enumerate(competitors):
    y = Inches(1.7 + row_idx * 0.65)
    is_header = row_idx == 0
    bg = PRIMARY if is_header else (WHITE if row_idx % 2 == 1 else SURFACE)
    txt_color = WHITE if is_header else DARK

    col_widths = [Inches(2.5), Inches(2.3), Inches(2.3), Inches(2.3), Inches(2.3)]
    x_start = Inches(0.8)

    for j, cell in enumerate(row):
        x = x_start + sum(col_widths[:j])
        box = add_shape_box(slide, x, y, col_widths[j], Inches(0.55), bg,
                             RGBColor(0xD7, 0xE8, 0xF2) if not is_header else PRIMARY)
        tf = box.text_frame
        tf.word_wrap = True
        tf.paragraphs[0].text = cell
        tf.paragraphs[0].font.size = Pt(12)
        tf.paragraphs[0].font.bold = is_header or j == 0
        tf.paragraphs[0].font.color.rgb = txt_color if is_header else (PRIMARY if j == 1 else DARK)
        tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SLIDE 10: Overall Verdict ──────────────────────────────────
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, DARK)

# Top accent bar
bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                             Inches(0), Inches(0), Inches(13.333), Pt(6))
bar.fill.solid()
bar.fill.fore_color.rgb = PRIMARY
bar.line.fill.background()

add_text_box(slide, Inches(1.5), Inches(0.8), Inches(10), Inches(0.8),
             "🎯  Overall Verdict", font_size=36, bold=True,
             color=WHITE, alignment=PP_ALIGN.CENTER)

add_text_box(slide, Inches(1.5), Inches(1.6), Inches(10), Inches(0.6),
             "HIGHLY FEASIBLE & VIABLE ✅",
             font_size=28, bold=True, color=PRIMARY, alignment=PP_ALIGN.CENTER)

# Rating cards
ratings = [
    ("Technical\nFeasibility", "⭐⭐⭐⭐⭐", "Already built\nand functional"),
    ("Market\nDemand", "⭐⭐⭐⭐⭐", "63M MSMEs +\nCERT-In mandate"),
    ("Competitive\nAdvantage", "⭐⭐⭐⭐", "Only CERT-In\nspecific tool"),
    ("Revenue\nPotential", "⭐⭐⭐⭐", "SaaS + per-scan\n+ white-label"),
    ("Scalability", "⭐⭐⭐", "Needs auth & DB\nfor production"),
    ("Risk Level", "⭐⭐⭐", "Manageable with\nbuilt-in mitigations"),
]

for i, (dim, stars, note) in enumerate(ratings):
    x = Inches(0.8 + i * 2.05)
    box = add_shape_box(slide, x, Inches(2.5), Inches(1.85), Inches(2.8),
                         RGBColor(0x0D, 0x20, 0x2D), PRIMARY)
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].text = dim
    tf.paragraphs[0].font.size = Pt(15)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = WHITE
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    p2 = tf.add_paragraph()
    p2.text = ""
    p3 = tf.add_paragraph()
    p3.text = stars
    p3.font.size = Pt(16)
    p3.font.color.rgb = WARNING
    p3.alignment = PP_ALIGN.CENTER

    p4 = tf.add_paragraph()
    p4.text = ""
    p5 = tf.add_paragraph()
    p5.text = note
    p5.font.size = Pt(12)
    p5.font.color.rgb = MUTED
    p5.alignment = PP_ALIGN.CENTER

# Bottom message
add_text_box(slide, Inches(1), Inches(5.8), Inches(11.3), Inches(0.8),
             "The main gap between now and revenue is productionization\n"
             "(auth, database, deployment) — not product development.",
             font_size=16, color=MUTED, alignment=PP_ALIGN.CENTER)

# Final badge
final_box = add_shape_box(slide, Inches(4), Inches(6.6), Inches(5.3), Inches(0.55),
                            PRIMARY)
tf = final_box.text_frame
tf.paragraphs[0].text = "Build it. Deploy it. Sell it. 🚀"
tf.paragraphs[0].font.size = Pt(18)
tf.paragraphs[0].font.bold = True
tf.paragraphs[0].font.color.rgb = WHITE
tf.paragraphs[0].alignment = PP_ALIGN.CENTER


# ── SAVE ────────────────────────────────────────────────────────
output = "CyberSure_Feasibility_Viability.pptx"
prs.save(output)
print(f"\n✅ Presentation saved: {output}")
print(f"   Slides: {len(prs.slides)}")
print(f"   Size:   {prs.slide_width / 914400:.1f}\" × {prs.slide_height / 914400:.1f}\"")
