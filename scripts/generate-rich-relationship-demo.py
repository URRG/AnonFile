"""Generate deterministic, fictional relationship-graph demo assets.

Run from the repository root:
    .venv\\Scripts\\python.exe scripts/generate-rich-relationship-demo.py

The output is intentionally separate from the small media sample.  All source
values are fictional, and the labelled relationship statements are deliberately
bounded so the demo graph never infers a role from nearby prose.
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "apps" / "web" / "public" / "demo-media"
PAGE_W, PAGE_H = A4
LEFT, RIGHT = 46, PAGE_W - 46
INK = colors.HexColor("#203047")
MUTED = colors.HexColor("#52657B")
TEAL = colors.HexColor("#087F82")
LINE = colors.HexColor("#DCE5EB")
PALE = colors.HexColor("#F5F9FA")


def wrapped(text: str, font: str, size: float, width: float) -> list[str]:
    lines, current = [], ""
    for word in text.split():
        candidate = f"{current} {word}" if current else word
        if current and pdfmetrics.stringWidth(candidate, font, size) > width:
            lines.append(current)
            current = word
        else:
            current = candidate
    return [*lines, current] if current else lines


def header(pdf: canvas.Canvas, eyebrow: str, title: str, subtitle: str) -> float:
    pdf.setFont("Helvetica-Bold", 8.5)
    pdf.setFillColor(TEAL)
    pdf.drawString(LEFT, PAGE_H - 45, eyebrow.upper())
    pdf.setFillColor(INK)
    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(LEFT, PAGE_H - 81, title)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 9.5)
    pdf.drawString(LEFT, PAGE_H - 99, subtitle)
    pdf.setStrokeColor(LINE)
    pdf.line(LEFT, PAGE_H - 112, RIGHT, PAGE_H - 112)
    return PAGE_H - 126


def footer(pdf: canvas.Canvas) -> None:
    pdf.setStrokeColor(LINE)
    pdf.line(LEFT, 44, RIGHT, 44)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(LEFT, 30, "SYNTHETIC TEST DATA ONLY  |  Do not treat as a real incident or contact list")


EMAILS = (
    ("01  /  01 OCT 2026  08:42 UTC  /  CLIENT REPORT",
     "From: Isha Rao <isha.rao@bluebird-air.test>",
     "To: Maya Patel <maya.patel@harborline.test>",
     "Subject: P0 - booking confirmations not reaching travellers",
     "43 synthetic bookings lack confirmation, including BB-TEST-6732. Urgent P0-7421; bridge +1 415 555 0148.",
     ("Best regards, Isha Rao | BA-EMP-2041", "Bluebird Air, 100 Example Quay, Example City, CA 90000"), ()),
    ("02  /  01 OCT 2026  08:49 UTC  /  ACKNOWLEDGED",
     "From: Maya Patel <maya.patel@harborline.test>",
     "To: Isha Rao <isha.rao@bluebird-air.test>",
     "Subject: Re: P0-7421 - incident bridge opened",
     "Duplicate dispatch is paused. Arjun Mehta (HS-EMP-1042) and Neha Kapoor (HS-EMP-1057) trace retries.",
     ("Name: Maya Patel", "Title: Incident Lead", "Company: Harborline Systems"), ()),
    ("03  /  01 OCT 2026  09:17 UTC  /  MITIGATION",
     "From: Kabir Sen <kabir.sen@harborline.test>",
     "To: Isha Rao <isha.rao@bluebird-air.test>",
     "Subject: Re: P0-7421 - queued mail is draining",
     "Expired cache route rolled back; queue drains. Bridge +1 415 555 0173.",
     ("Regards, Kabir Sen | HS-EMP-1089",), ()),
    ("04  /  01 OCT 2026  09:41 UTC  /  CLIENT VALIDATION",
     "From: Isha Rao <isha.rao@bluebird-air.test>",
     "To: Maya Patel <maya.patel@harborline.test>",
     "Subject: Re: P0-7421 - confirmation tests passing",
     "BB-TEST-6732, 6733 and 6734 arrived once. Keep bridge open until guard passes.",
     ("Thanks, Isha Rao | Client Operations",), ("Isha Rao is a client of Harborline Systems.",)),
    ("05  /  01 OCT 2026  10:06 UTC  /  RESOLVED",
     "From: Maya Patel <maya.patel@harborline.test>",
     "To: Isha Rao <isha.rao@bluebird-air.test>",
     "Subject: Re: P0-7421 - resolved and follow-up scheduled",
     "Queue steady for 25 minutes. Synthetic P0-7421 resolved; client 1:1 and guard review remain scheduled.",
     ("Best regards, Maya Patel | Incident Lead", "Harborline Systems, 25 Sample Street, Example City, CA 90000"), ()),
)


def email_pdf(path: Path) -> None:
    pdf = canvas.Canvas(str(path), pagesize=A4, pageCompression=1, invariant=1)
    pdf.setTitle("Synthetic P0 client escalation email thread")
    y = header(pdf, "Client incident correspondence  /  5 messages", "P0 escalation to resolution",
               "Harborline Systems + Bluebird Air  |  Fictional ticket P0-7421")
    for meta, sender, recipient, subject, body, signature, evidence in EMAILS:
            body_lines = wrapped(body, "Helvetica", 10, RIGHT - LEFT - 28)
            if len(body_lines) > 2:
                raise ValueError("Email body exceeds two OCR-friendly lines")
            # 16pt baselines keep padded OCR repaint boxes clear of adjacent ink.
            height = 22 + 2 * 18 + len(body_lines) * 18 + (len(signature) + len(evidence)) * 16 + 7
            if y - height < 60:
                raise ValueError("Email thread no longer fits a single demo PDF page")
            pdf.setFillColor(PALE)
            pdf.setStrokeColor(LINE)
            pdf.roundRect(LEFT, y - height, RIGHT - LEFT, height, 7, fill=1, stroke=1)
            pdf.setFillColor(TEAL)
            pdf.setFont("Helvetica-Bold", 8.1)
            pdf.drawString(LEFT + 14, y - 16, f"{meta}  /  P0-7421")
            line_y = y - 35
            pdf.setFillColor(INK)
            pdf.setFont("Helvetica", 9.5)
            for field in (sender, recipient):
                pdf.drawString(LEFT + 14, line_y, field)
                line_y -= 18
            pdf.setFont("Helvetica", 10)
            for line in body_lines:
                pdf.drawString(LEFT + 14, line_y - 1, line)
                line_y -= 18
            pdf.setFillColor(MUTED)
            pdf.setFont("Helvetica", 8.9)
            for line in signature:
                pdf.drawString(LEFT + 14, line_y - 1, line)
                line_y -= 16
            pdf.setFont("Helvetica-Oblique", 8.4)
            for line in evidence:
                pdf.drawString(LEFT + 14, line_y - 1, line)
                line_y -= 16
            y -= height + 5
    footer(pdf)
    pdf.showPage()
    pdf.save()


PARTICIPANTS = (
    "Arjun Mehta | arjun.mehta@harborline.test | ID HS-EMP-1042",
    "Neha Kapoor | neha.kapoor@harborline.test | ID HS-EMP-1057",
    "Owen Blake | owen.blake@harborline.test | ID HS-EMP-1134",
    "Lina Chen | lina.chen@harborline.test | ID HS-EMP-1176",
    "Dev Shah | dev.shah@harborline.test | ID HS-EMP-1210",
)
MESSAGES = (
    ("09:03", "Arjun Mehta", "P0-7421 reproduces a second confirmation for BB-TEST-6732."),
    ("09:07", "Neha Kapoor", "Expired route trace: https://confluence.example.test/x/P0-7421."),
    ("09:11", "Owen Blake", "Queue depth drops. On-call: +1 415 555 0184."),
    ("09:14", "Lina Chen", "Added a failing repeated-dispatch test."),
    ("09:19", "Dev Shah", "Flag off. Runbook checked in Confluence case MAIL-28."),
    ("09:26", "Arjun Mehta", "Fix review: https://github.example.test/harborline/dispatch/pull/1842."),
    ("09:34", "Neha Kapoor", "Patch and replay pass. Owner ID: HS-EMP-1057."),
    ("09:42", "Owen Blake", "Bluebird Air confirms three messages once; Isha validates."),
    ("09:49", "Lina Chen", "Canary clean; CI: https://github.example.test/harborline/dispatch/actions/runs/8124."),
    ("10:04", "Dev Shah", "Rollback documented; escalation +1 415 555 0192."),
)


def slack_pdf(path: Path) -> None:
    pdf = canvas.Canvas(str(path), pagesize=A4, pageCompression=1, invariant=1)
    pdf.setTitle("Synthetic developer Slack incident thread")
    y = header(pdf, "Engineering channel  /  5 developers", "Bug resolution thread",
               "#incident-p0-7421  |  01 Oct 2026  |  Fictional Slack-style conversation")
    roster_height = 176
    pdf.setFillColor(PALE)
    pdf.setStrokeColor(LINE)
    pdf.roundRect(LEFT, y - roster_height, RIGHT - LEFT, roster_height, 7, fill=1, stroke=1)
    pdf.setFillColor(TEAL)
    pdf.setFont("Helvetica-Bold", 8.3)
    pdf.drawString(LEFT + 13, y - 16, "PARTICIPANTS")
    pdf.setFillColor(INK)
    pdf.setFont("Helvetica", 10)
    for index, participant in enumerate(PARTICIPANTS):
        pdf.drawString(LEFT + 13, y - 34 - index * 18, participant)
    pdf.setFillColor(TEAL)
    pdf.setFont("Helvetica-Bold", 7.8)
    pdf.drawString(LEFT + 13, y - 122, "ESCALATION ROSTER")
    pdf.setFillColor(INK)
    pdf.setFont("Helvetica", 7.8)
    pdf.drawString(LEFT + 13, y - 143, "Lina Chen is assistant to Maya Patel.")
    pdf.drawString(LEFT + 13, y - 164, "Lina Chen is assistant for Harborline Systems.")
    y -= roster_height + 8
    for time, author, message in MESSAGES:
            # One reading column avoids asking OCR to infer the ordering of
            # timestamp, author, and message cells on a shared baseline.
            lines = wrapped(f"{time}  {author}: {message}", "Helvetica", 10.2, RIGHT - LEFT - 8)
            height = max(38, 14 + 20 * len(lines) + 5)
            if y - height < 60:
                raise ValueError("Slack thread no longer fits a single demo PDF page")
            pdf.setStrokeColor(LINE)
            pdf.line(LEFT, y - height, RIGHT, y - height)
            pdf.setFillColor(INK)
            pdf.setFont("Helvetica", 10.2)
            for index, line in enumerate(lines):
                pdf.drawString(LEFT + 2, y - 15 - index * 20, line)
            y -= height + 4
    footer(pdf)
    pdf.showPage()
    pdf.save()


CALENDAR_EXPORT = """SYNTHETIC TEST DATA ONLY - FICTIONAL PEOPLE, ORGANIZATIONS, ADDRESSES, PHONES, IDS, AND .test LINKS
Calendar export: 01-07 October 2026 | Time zone: UTC
Workspace: Harborline Systems / Bluebird Air P0 follow-up

EXPLICIT ROLE EVIDENCE (labeled source data)
Arjun Mehta works on Duplicate Dispatch Guard.
Duplicate Dispatch Guard is assigned to Neha Kapoor.

EVENT 1
Date: 2026-10-01
Time: 09:00-09:30 UTC
Title: P0 checkout confirmation incident handoff
Organizer: Maya Patel <maya.patel@harborline.test>
Invitees: Isha Rao <isha.rao@bluebird-air.test>, Arjun Mehta <arjun.mehta@harborline.test>, Neha Kapoor <neha.kapoor@harborline.test>
Location: Video meeting - synthetic room P0-7421
Contact: Maya Patel | HS-EMP-1008 | +1 415 555 0161
Office: Harborline Systems, 25 Sample Street, Example City, CA 90000
Notes: Review the synthetic customer impact window, mitigation, and remaining verification steps for BB-TEST-6732. No production credentials or real customer records are included.

EVENT 2
Date: 2026-10-02
Time: 14:00-14:25 UTC
Title: 1:1 - Isha Rao and Maya Patel - client recovery check
Organizer: Maya Patel <maya.patel@harborline.test>
Invitees: Isha Rao <isha.rao@bluebird-air.test>, Maya Patel <maya.patel@harborline.test>
Location: Video meeting - synthetic room CLIENT-1
Client contact: Isha Rao | BA-EMP-2041 | +1 415 555 0148
Mailing address: Bluebird Air, 100 Example Quay, Example City, CA 90000
Notes: Confirm the client can see confirmation emails for synthetic bookings BB-TEST-6732 and BB-TEST-6733; agree on the written follow-up.

EVENT 3
Date: 2026-10-05
Time: 11:00-11:30 UTC
Title: Bug fix review - duplicate dispatch guard
Organizer: Arjun Mehta <arjun.mehta@harborline.test>
Invitees: Neha Kapoor <neha.kapoor@harborline.test>, Owen Blake <owen.blake@harborline.test>, Lina Chen <lina.chen@harborline.test>, Dev Shah <dev.shah@harborline.test>
Location: Video meeting - synthetic room ENG-28
Owner: Arjun Mehta | HS-EMP-1042 | +1 415 555 0184
Review link: https://github.example.test/harborline/dispatch/pull/1842
Runbook link: https://confluence.example.test/x/MAIL-28
Notes: Inspect the idempotency test, queue retry trace, feature flag, and rollback checklist for fictional ticket P0-7421.

EVENT 4
Date: 2026-10-07
Time: 16:00-16:20 UTC
Title: 1:1 - Isha Rao and Kabir Sen - client resolution sign-off
Organizer: Kabir Sen <kabir.sen@harborline.test>
Invitees: Isha Rao <isha.rao@bluebird-air.test>, Kabir Sen <kabir.sen@harborline.test>, Maya Patel <maya.patel@harborline.test>
Location: Video meeting - synthetic room CLIENT-2
Contact: Kabir Sen | HS-EMP-1089 | +1 415 555 0173
Reference: https://confluence.example.test/x/P0-7421
Notes: Walk through final validation evidence and the fictional incident timeline. Resolution is for this synthetic scenario only.
"""


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    email_pdf(OUTPUT / "11-p0-client-email-thread.pdf")
    slack_pdf(OUTPUT / "12-developer-slack-thread.pdf")
    # LF is intentional: role expressions are complete line-bounded statements.
    # Avoid touching this independent fixture when its deterministic source is unchanged.
    calendar_path = OUTPUT / "13-calendar-events.txt"
    if not calendar_path.exists():
        calendar_path.write_bytes(CALENDAR_EXPORT.encode("utf-8"))
    for path in sorted(OUTPUT.glob("1[1-3]-*")):
        print(f"{path.relative_to(ROOT)}: {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
