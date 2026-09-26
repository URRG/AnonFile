"""Rebuild the two fictional, deterministic PDF/image demo fixtures.

Run from the repository root with the API development requirements installed.
These are public static assets; never put supplier or customer data here.
"""
from pathlib import Path
from io import BytesIO

from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
import reportlab


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "apps" / "web" / "public" / "demo-media"
OUTPUT.mkdir(parents=True, exist_ok=True)


pdf_data = BytesIO()
pdf = canvas.Canvas(pdf_data, pagesize=(700, 340), invariant=1)
pdf.setFillColorRGB(0.07, 0.18, 0.30)
pdf.rect(0, 292, 700, 48, fill=1, stroke=0)
pdf.setFillColorRGB(1, 1, 1)
pdf.setFont("Helvetica-Bold", 18)
pdf.drawString(40, 308, "NORTHSTAR TRAVEL / CUSTOMER EMAIL")
pdf.setFillColorRGB(0.08, 0.16, 0.26)
pdf.setFont("Helvetica", 16)
for y, line in (
    (257, "From: Riya <riya@example.test>"),
    (225, "To: Sita <sita@example.test>"),
    (193, "Subject: Fictional travel update"),
    (145, "Hi Sita, Riya can review the itinerary."),
    (113, "Please confirm the revised schedule."),
):
    pdf.drawString(40, y, line)
pdf.setStrokeColorRGB(0.75, 0.82, 0.86)
pdf.line(40, 177, 660, 177)
pdf.setFillColorRGB(0.38, 0.46, 0.52)
pdf.setFont("Helvetica", 10)
pdf.drawString(40, 35, "FICTIONAL DATA ONLY - NOT A REAL CUSTOMER MESSAGE")
pdf.showPage()
pdf.save()
(OUTPUT / "01-email-thread.pdf").write_bytes(pdf_data.getvalue())


image = Image.new("RGB", (900, 310), "white")
draw = ImageDraw.Draw(image)
draw.rectangle((0, 0, 899, 68), fill=(18, 54, 80))
draw.rounded_rectangle((22, 85, 878, 284), radius=12, outline=(185, 203, 215), width=2)
font_path = Path(reportlab.__file__).parent / "fonts" / "Vera.ttf"
bold_path = Path(reportlab.__file__).parent / "fonts" / "VeraBd.ttf"
draw.text((32, 19), "NORTHSTAR TRAVEL / SERVICE NOTE", font=ImageFont.truetype(str(bold_path), 25), fill="white")
body = ImageFont.truetype(str(font_path), 26)
for y, line in (
    (103, "Passenger: Sita"),
    (148, "Email: sita@example.test"),
    (193, "Booking: DEMO-4822"),
    (238, "Agent: Riya"),
):
    draw.text((47, y), line, font=body, fill=(20, 44, 60))
image.save(OUTPUT / "02-service-note.png", format="PNG", optimize=True)

print("Generated fictional PDF and PNG fixtures in", OUTPUT)
