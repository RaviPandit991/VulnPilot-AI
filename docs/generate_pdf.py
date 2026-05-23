"""Generate a PDF version of docs/USAGE.md.

Usage (with the project venv activated, so reportlab is available):

    python docs/generate_pdf.py

Output: docs/USAGE.pdf

The renderer is intentionally simple: it understands the subset of Markdown
used in USAGE.md (headings, paragraphs, fenced code blocks, lists, tables,
inline emphasis). For a perfect render, install pandoc and run:

    pandoc docs/USAGE.md -o docs/USAGE.pdf --pdf-engine=xelatex
"""
from __future__ import annotations

import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
)


HERE = Path(__file__).parent
SRC = HERE / "USAGE.md"
DST = HERE / "USAGE.pdf"


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title", parent=base["Title"], fontSize=22, leading=26,
            spaceAfter=18, textColor=colors.HexColor("#0f4c81"),
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontSize=16, leading=20,
            spaceBefore=14, spaceAfter=8,
            textColor=colors.HexColor("#0f4c81"),
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontSize=13, leading=17,
            spaceBefore=10, spaceAfter=6,
            textColor=colors.HexColor("#1f6feb"),
        ),
        "h3": ParagraphStyle(
            "H3", parent=base["Heading3"], fontSize=11, leading=14,
            spaceBefore=8, spaceAfter=4,
            textColor=colors.HexColor("#444"),
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontSize=9.5, leading=13,
            alignment=TA_LEFT, spaceAfter=4,
        ),
        "code": ParagraphStyle(
            "Code", parent=base["Code"], fontName="Courier", fontSize=8,
            leading=10, leftIndent=10, backColor=colors.HexColor("#f3f4f6"),
            borderColor=colors.HexColor("#d0d7de"), borderWidth=0.5,
            borderPadding=4, spaceAfter=8,
        ),
        "warn": ParagraphStyle(
            "Warn", parent=base["BodyText"], fontSize=9.5, leading=13,
            leftIndent=10, backColor=colors.HexColor("#fff7e6"),
            borderColor=colors.HexColor("#ffb800"), borderWidth=0.5,
            borderPadding=6, spaceAfter=8,
        ),
        "list": ParagraphStyle(
            "List", parent=base["BodyText"], fontSize=9.5, leading=13,
            leftIndent=18, bulletIndent=6, spaceAfter=2,
        ),
    }


_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
_BARE_URL = re.compile(r"(?<![\w\(])(https?://[^\s)]+)")


def _md_inline_to_html(text: str) -> str:
    text = (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))
    text = _LINK.sub(
        lambda m: f'<link href="{m.group(2)}" color="#1f6feb">{m.group(1)}</link>',
        text,
    )
    text = _BARE_URL.sub(
        lambda m: f'<link href="{m.group(1)}" color="#1f6feb">{m.group(1)}</link>',
        text,
    )
    text = _BOLD.sub(r"<b>\1</b>", text)
    text = _INLINE_CODE.sub(
        r'<font face="Courier" size="9" backColor="#f3f4f6">\1</font>', text,
    )
    return text


def _flush_table(rows, story, styles):
    if not rows:
        return
    body_style = ParagraphStyle("td", parent=styles["body"], fontSize=8.5,
                                leading=11)
    head_style = ParagraphStyle("th", parent=body_style, textColor=colors.white)
    data = []
    header, *body = rows
    data.append([Paragraph(_md_inline_to_html(c), head_style) for c in header])
    for row in body:
        data.append([Paragraph(_md_inline_to_html(c), body_style) for c in row])
    tbl = Table(data, repeatRows=1, colWidths=[None] * len(header))
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f4c81")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bcc4cc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 8))


def _flush_list(items, story, styles):
    for item in items:
        story.append(
            Paragraph(f"&bull;&nbsp; {_md_inline_to_html(item)}", styles["list"])
        )
    if items:
        story.append(Spacer(1, 4))


def render(md_path: Path, pdf_path: Path) -> Path:
    styles = _styles()
    story = []

    lines = md_path.read_text(encoding="utf-8").splitlines()

    in_code = False
    code_buf: list[str] = []
    list_buf: list[str] = []
    table_buf: list[list[str]] = []

    def flush_code():
        if code_buf:
            story.append(Preformatted("\n".join(code_buf), styles["code"]))
            code_buf.clear()

    def flush_list():
        _flush_list(list_buf, story, styles)
        list_buf.clear()

    def flush_table():
        _flush_table(table_buf, story, styles)
        table_buf.clear()

    title_done = False

    for raw in lines:
        line = raw.rstrip()

        if line.strip().startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                flush_list()
                flush_table()
                in_code = True
            continue
        if in_code:
            code_buf.append(raw)
            continue

        # Tables: lines starting with `|`
        if line.lstrip().startswith("|"):
            flush_list()
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            # Skip alignment row (---|---)
            if all(set(c) <= set("-: ") for c in cells if c):
                continue
            table_buf.append(cells)
            continue
        else:
            flush_table()

        # Lists
        m_list = re.match(r"^\s*[-*]\s+(.*)$", line)
        if m_list:
            list_buf.append(m_list.group(1))
            continue
        else:
            flush_list()

        # Headings
        if line.startswith("# ") and not title_done:
            story.append(Paragraph(_md_inline_to_html(line[2:]), styles["title"]))
            title_done = True
            continue
        if line.startswith("# "):
            story.append(Paragraph(_md_inline_to_html(line[2:]), styles["h1"]))
            continue
        if line.startswith("## "):
            story.append(Paragraph(_md_inline_to_html(line[3:]), styles["h1"]))
            continue
        if line.startswith("### "):
            story.append(Paragraph(_md_inline_to_html(line[4:]), styles["h2"]))
            continue
        if line.startswith("#### "):
            story.append(Paragraph(_md_inline_to_html(line[5:]), styles["h3"]))
            continue

        # Horizontal rules
        if line.strip() in {"---", "***"}:
            story.append(Spacer(1, 6))
            continue

        # Blockquotes -> warning callout
        if line.startswith("> "):
            story.append(
                Paragraph(_md_inline_to_html(line[2:]), styles["warn"])
            )
            continue

        if not line.strip():
            story.append(Spacer(1, 4))
            continue

        story.append(Paragraph(_md_inline_to_html(line), styles["body"]))

    flush_code()
    flush_list()
    flush_table()

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title="VulnPilot AI - Complete Guide",
        author="VulnPilot AI",
    )
    doc.build(story)
    return pdf_path


def main() -> int:
    if not SRC.exists():
        print(f"Source not found: {SRC}")
        return 1
    out = render(SRC, DST)
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
