"""Professional pentest report PDF generator — matches PTES template style."""

from __future__ import annotations

import io
import math
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from models import (
    CommandStatus,
    Finding,
    Lead,
    PendingCommand,
    Project,
    Session,
    Severity,
)

# ---------------------------------------------------------------------------
# Colors (extracted from the PDF template)
# ---------------------------------------------------------------------------
GREEN_HEADER = colors.HexColor("#00b050")
GREEN_COVER = colors.HexColor("#29ec72")
DARK_BG = colors.HexColor("#1a1a2e")
DARK_BG2 = colors.HexColor("#16213e")
BODY_TEXT = colors.HexColor("#000000")
TABLE_TEXT = colors.HexColor("#1f497d")
WHITE = colors.HexColor("#ffffff")
LIGHT_GRAY = colors.HexColor("#f2f2f2")
MED_GRAY = colors.HexColor("#d9d9d9")
DARK_GRAY = colors.HexColor("#404040")
STATUS_PINK = colors.HexColor("#d99594")

SEV_COLORS = {
    "critical": colors.HexColor("#8064a2"),
    "high": colors.HexColor("#ee0000"),
    "medium": colors.HexColor("#ffc000"),
    "low": colors.HexColor("#92d050"),
    "info": colors.HexColor("#00b0f0"),
}

SEV_BG = {
    "critical": colors.HexColor("#f0e6f6"),
    "high": colors.HexColor("#fde8e8"),
    "medium": colors.HexColor("#fff8e1"),
    "low": colors.HexColor("#e8f5e9"),
    "info": colors.HexColor("#e3f2fd"),
}

SEV_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}

SEV_CVSS = {
    "critical": 9.5,
    "high": 7.8,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}

SEV_VECTOR = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
}

# ---------------------------------------------------------------------------
# Font registration
# ---------------------------------------------------------------------------
FONT_DIR = Path(__file__).parent / "fonts"


def _register_fonts():
    mapping = {
        "Poppins": "Poppins-Regular.ttf",
        "Poppins-Bold": "Poppins-Bold.ttf",
        "Poppins-SemiBold": "Poppins-SemiBold.ttf",
        "Poppins-Black": "Poppins-Black.ttf",
        "Poppins-Italic": "Poppins-Italic.ttf",
    }
    for name, fname in mapping.items():
        path = FONT_DIR / fname
        if path.exists():
            try:
                pdfmetrics.registerFont(TTFont(name, str(path)))
            except Exception:
                pass


_register_fonts()

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
PAGE_W, PAGE_H = A4
MARGIN = 2.0 * cm


def _styles():
    """Build all paragraph styles used in the report."""
    s = {}

    s["cover_title"] = ParagraphStyle(
        "cover_title",
        fontName="Poppins-Black",
        fontSize=24,
        textColor=GREEN_COVER,
        alignment=TA_CENTER,
        leading=30,
    )
    s["cover_sub"] = ParagraphStyle(
        "cover_sub",
        fontName="Poppins",
        fontSize=14,
        textColor=WHITE,
        alignment=TA_CENTER,
        leading=20,
    )
    s["cover_small"] = ParagraphStyle(
        "cover_small",
        fontName="Poppins",
        fontSize=11,
        textColor=WHITE,
        alignment=TA_CENTER,
        leading=16,
    )

    s["section"] = ParagraphStyle(
        "section",
        fontName="Poppins-Black",
        fontSize=16,
        textColor=GREEN_HEADER,
        spaceAfter=10,
        spaceBefore=6,
    )
    s["subsection"] = ParagraphStyle(
        "subsection",
        fontName="Poppins-SemiBold",
        fontSize=12,
        textColor=GREEN_HEADER,
        spaceAfter=6,
        spaceBefore=10,
    )
    s["body"] = ParagraphStyle(
        "body",
        fontName="Poppins",
        fontSize=10,
        textColor=BODY_TEXT,
        alignment=TA_JUSTIFY,
        leading=14,
        spaceAfter=6,
    )
    s["body_small"] = ParagraphStyle(
        "body_small",
        fontName="Poppins",
        fontSize=9,
        textColor=BODY_TEXT,
        leading=12,
        spaceAfter=4,
    )
    s["bullet"] = ParagraphStyle(
        "bullet",
        fontName="Poppins",
        fontSize=10,
        textColor=BODY_TEXT,
        leading=14,
        leftIndent=18,
        bulletIndent=6,
        spaceAfter=3,
    )
    s["table_header"] = ParagraphStyle(
        "table_header",
        fontName="Poppins-Bold",
        fontSize=9,
        textColor=WHITE,
        alignment=TA_CENTER,
        leading=12,
    )
    s["table_cell"] = ParagraphStyle(
        "table_cell",
        fontName="Poppins",
        fontSize=8,
        textColor=BODY_TEXT,
        leading=11,
    )
    s["table_cell_center"] = ParagraphStyle(
        "table_cell_center",
        fontName="Poppins",
        fontSize=8,
        textColor=BODY_TEXT,
        alignment=TA_CENTER,
        leading=11,
    )
    s["code"] = ParagraphStyle(
        "code",
        fontName="Courier",
        fontSize=7,
        textColor=colors.HexColor("#333333"),
        leading=9,
        leftIndent=12,
        spaceAfter=4,
        backColor=colors.HexColor("#f5f5f5"),
    )
    s["vuln_label"] = ParagraphStyle(
        "vuln_label",
        fontName="Poppins",
        fontSize=10,
        textColor=BODY_TEXT,
        leading=14,
    )
    s["vuln_value"] = ParagraphStyle(
        "vuln_value",
        fontName="Poppins-SemiBold",
        fontSize=10,
        textColor=BODY_TEXT,
        leading=14,
    )
    s["footer"] = ParagraphStyle(
        "footer",
        fontName="Poppins",
        fontSize=7,
        textColor=DARK_GRAY,
        alignment=TA_CENTER,
    )
    s["phase_name"] = ParagraphStyle(
        "phase_name",
        fontName="Poppins-Bold",
        fontSize=9,
        textColor=GREEN_HEADER,
        leading=12,
    )
    s["phase_desc"] = ParagraphStyle(
        "phase_desc",
        fontName="Poppins",
        fontSize=9,
        textColor=BODY_TEXT,
        leading=12,
        spaceAfter=6,
        leftIndent=12,
    )
    s["toc"] = ParagraphStyle(
        "toc",
        fontName="Poppins",
        fontSize=11,
        textColor=BODY_TEXT,
        leading=20,
        leftIndent=12,
    )
    s["sev_label"] = ParagraphStyle(
        "sev_label",
        fontName="Poppins-SemiBold",
        fontSize=11,
        textColor=BODY_TEXT,
        spaceAfter=2,
        spaceBefore=8,
    )
    s["evidence_label"] = ParagraphStyle(
        "evidence_label",
        fontName="Poppins-SemiBold",
        fontSize=9,
        textColor=DARK_GRAY,
        leading=12,
        spaceAfter=2,
        spaceBefore=6,
    )
    s["step_number"] = ParagraphStyle(
        "step_number",
        fontName="Poppins",
        fontSize=9,
        textColor=BODY_TEXT,
        leading=13,
        spaceAfter=1,
    )
    s["step_code"] = ParagraphStyle(
        "step_code",
        fontName="Courier",
        fontSize=7,
        textColor=colors.HexColor("#333333"),
        leading=9,
        leftIndent=24,
        spaceAfter=4,
        backColor=colors.HexColor("#f5f5f5"),
    )
    s["cronograma_label"] = ParagraphStyle(
        "cronograma_label",
        fontName="Poppins",
        fontSize=10,
        textColor=BODY_TEXT,
        leading=14,
        spaceAfter=6,
    )
    return s


# ---------------------------------------------------------------------------
# Page templates
# ---------------------------------------------------------------------------

def _cover_bg(canvas, doc):
    """Draw dark background for cover page."""
    canvas.saveState()
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=True, stroke=False)

    # Subtle gradient overlay at bottom
    canvas.setFillColor(DARK_BG2)
    canvas.rect(0, 0, PAGE_W, PAGE_H * 0.35, fill=True, stroke=False)

    # Decorative line
    canvas.setStrokeColor(GREEN_COVER)
    canvas.setLineWidth(2)
    canvas.line(MARGIN, PAGE_H * 0.42, PAGE_W - MARGIN, PAGE_H * 0.42)

    # Thin green border
    canvas.setStrokeColor(GREEN_COVER)
    canvas.setLineWidth(0.5)
    canvas.rect(
        MARGIN * 0.7, MARGIN * 0.7,
        PAGE_W - MARGIN * 1.4, PAGE_H - MARGIN * 1.4,
        fill=False, stroke=True,
    )
    canvas.restoreState()


def _draw_hades_logo(canvas, x, y, size=18):
    """Draw the HADES bident logo — just the bident, no hexagon."""
    canvas.saveState()
    s = size / 32.0

    canvas.setStrokeColor(GREEN_HEADER)
    canvas.setLineWidth(1.5)
    canvas.setLineCap(1)

    def sx(v):
        return x + v * s

    def sy(v):
        return y + size - v * s

    # Left prong with pointed tip
    canvas.line(sx(10), sy(6), sx(10), sy(20.5))
    canvas.line(sx(10), sy(20.5), sx(16), sy(27))
    # Left tip arrow
    canvas.line(sx(8), sy(9), sx(10), sy(6))
    canvas.line(sx(12), sy(9), sx(10), sy(6))

    # Right prong with pointed tip
    canvas.line(sx(22), sy(6), sx(22), sy(20.5))
    canvas.line(sx(22), sy(20.5), sx(16), sy(27))
    # Right tip arrow
    canvas.line(sx(20), sy(9), sx(22), sy(6))
    canvas.line(sx(24), sy(9), sx(22), sy(6))

    # Crossbar
    canvas.line(sx(10), sy(14), sx(22), sy(14))

    # Handle (bottom)
    canvas.line(sx(16), sy(27), sx(16), sy(31))

    canvas.restoreState()


def _normal_page(canvas, doc):
    """Header line + HADES logo + page number for normal pages."""
    canvas.saveState()

    # Top green line (shifted right to make room for logo)
    canvas.setStrokeColor(GREEN_HEADER)
    canvas.setLineWidth(1.5)
    logo_area_w = 60  # space for logo + "HADES" text
    canvas.line(
        MARGIN + logo_area_w, PAGE_H - MARGIN + 8,
        PAGE_W - MARGIN, PAGE_H - MARGIN + 8,
    )

    # HADES logo (top-left, next to the green line)
    _draw_hades_logo(canvas, MARGIN, PAGE_H - MARGIN + 1, size=16)
    canvas.setFont("Poppins-Bold", 8)
    canvas.setFillColor(GREEN_HEADER)
    canvas.drawString(MARGIN + 20, PAGE_H - MARGIN + 4, "HADES")

    # Footer
    canvas.setFont("Poppins", 7)
    canvas.setFillColor(DARK_GRAY)
    canvas.drawCentredString(
        PAGE_W / 2, 1.2 * cm,
        f"Classificação: Confidencial  |  Página {doc.page}",
    )

    # Bottom green line
    canvas.setStrokeColor(GREEN_HEADER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 1.6 * cm, PAGE_W - MARGIN, 1.6 * cm)

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Helper: build steps to reproduce
# ---------------------------------------------------------------------------

def _build_steps(finding: Finding, cmds: list[PendingCommand]) -> list[str]:
    """Legacy wrapper — delegates to _build_reproduction_steps."""
    return []  # kept for compatibility; callers now use _build_reproduction_steps


_CMD_RE = re.compile(
    r'(?:^|\n)\s*(?:Command:\s*|[$#]\s*)'
    r'((?:curl|nmap|nuclei|sqlmap|ffuf|gobuster|nikto|testssl|snmpwalk|openssl'
    r'|wget|httpx|whatweb|katana|feroxbuster|hydra|wfuzz|arjun|amass'
    r'|subfinder|dig|host|whois|searchsploit|python3?|bash)\s[^\n]+)',
    re.IGNORECASE,
)


def _extract_commands_from_evidence(evidence: str) -> list[str]:
    """Extract real CLI commands from evidence text."""
    return [m.strip() for m in _CMD_RE.findall(evidence) if len(m.strip()) > 10]


def _describe_command(cmd: str) -> str:
    """Generate a short pt-BR description for a command."""
    cl = cmd.lower()
    if "curl" in cl:
        if "origin" in cl:
            return "Enviar requisição com header Origin malicioso para testar CORS"
        if "apikey" in cl or "authorization" in cl or "bearer" in cl:
            return "Testar acesso à API com a chave/token encontrado"
        if "-I" in cmd or "--head" in cl:
            return "Verificar headers de resposta do servidor"
        if "grep" in cl:
            return "Extrair informações sensíveis da resposta HTTP"
        if "-X POST" in cmd or "-d " in cmd or "--data" in cl:
            return "Enviar requisição POST ao endpoint alvo"
        if "supabase" in cl:
            return "Acessar endpoint Supabase com chave extraída"
        if "functions" in cl or "edge" in cl or "invoke" in cl:
            return "Invocar edge function sem autenticação"
        return "Realizar requisição HTTP ao endpoint identificado"
    if "nmap" in cl:
        if "ssl" in cl:
            return "Verificar cifras e protocolos SSL/TLS aceitos"
        if "script" in cl:
            return "Executar scripts NSE no alvo"
        return "Executar scan de portas e serviços"
    if "nuclei" in cl:
        return "Executar scan de vulnerabilidades conhecidas"
    if "sqlmap" in cl:
        return "Testar injeção SQL automatizada"
    if "ffuf" in cl or "gobuster" in cl or "feroxbuster" in cl:
        return "Enumerar diretórios e arquivos no servidor"
    if "testssl" in cl:
        return "Analisar configuração SSL/TLS do servidor"
    if "openssl" in cl:
        return "Verificar protocolo e cifras SSL/TLS"
    if "snmpwalk" in cl:
        return "Enumerar informações via SNMP"
    if "hydra" in cl:
        return "Testar credenciais por força bruta"
    if "searchsploit" in cl:
        return "Buscar exploits públicos para o serviço"
    if "dig" in cl or "host" in cl:
        return "Consultar registros DNS do alvo"
    if "katana" in cl:
        return "Rastrear URLs e endpoints da aplicação"
    if "python" in cl:
        return "Executar script de exploração"
    return "Executar comando de verificação"


def _build_reproduction_steps(
    finding: Finding, target: str, cmds: list[PendingCommand],
) -> list[dict]:
    """Build actionable steps from REAL commands in evidence and executed commands.

    Returns list of {step: str, command: str}. Every step has a real command.
    """
    evidence = finding.evidence or ""
    seen: set[str] = set()
    steps: list[dict] = []

    # 1. Primary source: commands extracted from the evidence itself
    ev_cmds = _extract_commands_from_evidence(evidence)
    for cmd in ev_cmds:
        norm = cmd.strip().lower()
        if norm not in seen:
            seen.add(norm)
            steps.append({"step": _describe_command(cmd), "command": cmd.strip()})

    # 2. Secondary source: executed commands near this finding's timestamp
    if len(steps) < 2:
        preceding = [c for c in cmds if c.created_at <= finding.created_at]
        relevant = preceding[-5:]
        for c in relevant:
            norm = c.command.strip().lower()
            if norm not in seen and len(c.command.strip()) > 10:
                seen.add(norm)
                steps.append({"step": _describe_command(c.command), "command": c.command.strip()})
            if len(steps) >= 5:
                break

    # 3. Last resort: if still empty, build from evidence URLs
    if not steps:
        urls = re.findall(r'https?://[^\s"\'<>]+', evidence)
        if urls:
            steps.append({
                "step": "Acessar o endpoint vulnerável identificado",
                "command": f"curl -sk '{urls[0]}'",
            })
        else:
            steps.append({
                "step": "Acessar o ativo alvo",
                "command": f"curl -sk '{target}' -D -",
            })

    return steps[:5]


def _strip_commands_from_evidence(evidence: str) -> str:
    """Remove command lines from evidence, leaving only output/responses."""
    lines = evidence.split("\n")
    output_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        # Skip lines that are commands
        if re.match(r'^(Command:\s*|[$#]\s*)?(curl|nmap|nuclei|sqlmap|ffuf|gobuster|nikto|testssl|snmpwalk|openssl|wget|httpx|whatweb|katana|feroxbuster|hydra|python)\s', stripped, re.I):
            continue
        if stripped.startswith("Command:"):
            continue
        if stripped.startswith("$ "):
            continue
        output_lines.append(line)
    result = "\n".join(output_lines).strip()
    # Clean up excessive blank lines
    result = re.sub(r'\n{3,}', '\n\n', result)
    return result


def _esc(text: str) -> str:
    """Escape XML special chars for Paragraph.

    Handles &, <, >, and strips control characters that break reportlab's
    XML parser (e.g. null bytes, vertical tabs, form feeds).
    """
    import re as _re
    # Strip control characters (keep \n and \t)
    text = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Main PDF builder
# ---------------------------------------------------------------------------

def generate_pdf(
    session: Session,
    project: Project | None,
    findings: list[Finding],
    leads: list[Lead],
    commands: list[PendingCommand],
) -> bytes:
    """Generate the full PDF report and return it as bytes."""
    executed_cmds = [
        c for c in commands
        if c.status in (CommandStatus.executed, CommandStatus.failed)
    ]

    client_name = (
        project.client if project and project.client
        else project.name if project
        else session.target
    )
    target = session.target
    scope_list = project.scope if project and project.scope else [target]
    report_date = datetime.now(timezone.utc).strftime("%d/%m/%Y")
    st = _styles()

    buf = io.BytesIO()

    # -- Doc setup --
    cover_frame = Frame(
        MARGIN, MARGIN, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN,
        id="cover",
    )
    normal_frame = Frame(
        MARGIN, 2 * cm, PAGE_W - 2 * MARGIN, PAGE_H - MARGIN - 2.2 * cm,
        id="normal",
    )

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=2 * cm,
    )
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=_cover_bg),
        PageTemplate(id="Normal", frames=[normal_frame], onPage=_normal_page),
    ])

    story: list = []

    # =====================================================================
    # COVER PAGE
    # =====================================================================
    story.append(Spacer(1, 6 * cm))
    story.append(Paragraph(
        "Relatório Técnico de<br/>Segurança Ofensiva",
        st["cover_title"],
    ))
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph(f"Cliente: {_esc(client_name)}", st["cover_sub"]))
    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph("Classificação: Confidencial", st["cover_small"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"Data: {report_date}", st["cover_small"]))

    story.append(NextPageTemplate("Normal"))
    story.append(PageBreak())

    # =====================================================================
    # TABLE OF CONTENTS
    # =====================================================================
    story.append(Paragraph("Sumário", st["section"]))
    story.append(Spacer(1, 0.5 * cm))
    toc_items = [
        "1. Metodologia",
        "2. Classificação CVSS",
        "3. Introdução",
        "4. Cronograma",
        "5. Versionamento",
        "6. Vulnerabilidades Detectadas",
        "7. Detalhamento das Vulnerabilidades",
    ]
    open_leads = [ld for ld in leads if ld.status.value == "open"]
    next_num = 8
    if open_leads:
        toc_items.append(f"{next_num}. Pontos de Investigação em Aberto")
        next_num += 1
    toc_items.append(f"{next_num}. Conclusão")
    next_num += 1
    if executed_cmds:
        toc_items.append(f"{next_num}. Apêndice: Comandos Executados")

    for item in toc_items:
        story.append(Paragraph(item, st["toc"]))
    story.append(PageBreak())

    # =====================================================================
    # 1. METODOLOGIA
    # =====================================================================
    story.append(Paragraph("Metodologia", st["section"]))
    story.append(Paragraph(
        "Utilizamos uma metodologia de ataque baseada no <b>Penetration Testing "
        "Execution Standard (PTES)</b>, visando fornecer um dos melhores e mais "
        "atuais métodos para testar a segurança dos ativos. As etapas seguidas:",
        st["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    ptes = [
        ("Pré-Engajamento",
         "Definição do escopo, regras de execução e critérios de sucesso, "
         "alinhando objetivos e limitações com as áreas envolvidas."),
        ("Reconhecimento",
         "Coleta de informações sobre o alvo (OSINT e scans ativos) para "
         "identificar serviços expostos, versões de software e possíveis vetores de ataque."),
        ("Modelagem de Ameaças",
         "Definição dos vetores de ataque, avaliando se os controles existentes "
         "são capazes de identificar ou bloquear as abordagens."),
        ("Análise de Vulnerabilidade",
         "Descoberta de falhas em sistemas e aplicações que podem ser exploradas, "
         "incluindo configurações incorretas e design inseguro."),
        ("Exploração",
         "Estabelecimento de acesso ao sistema contornando restrições de segurança, "
         "executado como um ataque de precisão baseado nas vulnerabilidades identificadas."),
        ("Pós-Exploração",
         "Determinação do valor da máquina comprometida e manutenção do controle "
         "para avaliar impacto real e possibilidade de movimentação lateral."),
        ("Relatório",
         "Comunicação dos achados, objetivos e recomendações, incluindo evidências "
         "técnicas e passos para reprodução."),
    ]
    for name, desc in ptes:
        story.append(Paragraph(f"{name}:", st["phase_name"]))
        story.append(Paragraph(desc, st["phase_desc"]))

    story.append(PageBreak())

    # =====================================================================
    # 2. CLASSIFICAÇÃO CVSS
    # =====================================================================
    story.append(Paragraph("Classificação CVSS", st["section"]))
    story.append(Paragraph(
        "Os critérios de classificação de severidade das vulnerabilidades "
        "e ameaças identificadas são baseados no cálculo <i>CVSS</i>. "
        "Os níveis de severidade são:",
        st["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    cvss_data = [
        ["Severidade", "Score", "Descrição"],
        [
            Paragraph('<font color="#8064a2"><b>Crítica</b></font>', st["table_cell"]),
            Paragraph("9.0 – 10", st["table_cell_center"]),
            Paragraph(
                "Vulnerabilidades que permitem execução de código arbitrário "
                "ou acesso a dados confidenciais. Prioridade máxima de correção.",
                st["table_cell"],
            ),
        ],
        [
            Paragraph('<font color="#ee0000"><b>Alta</b></font>', st["table_cell"]),
            Paragraph("7.0 – 8.9", st["table_cell_center"]),
            Paragraph(
                "Acesso remoto, execução de código ou controle do sistema. "
                "Pode exigir alguma interação do usuário.",
                st["table_cell"],
            ),
        ],
        [
            Paragraph('<font color="#ffc000"><b>Média</b></font>', st["table_cell"]),
            Paragraph("4.0 – 6.9", st["table_cell_center"]),
            Paragraph(
                "Leitura de informações privilegiadas. Pode ser reclassificada "
                "como alta sob certas circunstâncias.",
                st["table_cell"],
            ),
        ],
        [
            Paragraph('<font color="#92d050"><b>Baixa</b></font>', st["table_cell"]),
            Paragraph("0.1 – 3.9", st["table_cell_center"]),
            Paragraph(
                "Vazamento de informações que podem auxiliar ataques mais sofisticados.",
                st["table_cell"],
            ),
        ],
    ]
    cvss_table = Table(cvss_data, colWidths=[3 * cm, 2.5 * cm, 11 * cm])
    cvss_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cvss_table)

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "O <b>Common Vulnerability Scoring System (CVSS) 3.1</b> é um padrão "
        "internacional para mensurar a gravidade de vulnerabilidades. A pontuação "
        "vai de 0 a 10 e considera métricas <b>Base</b> (explorabilidade e impacto), "
        "<b>Temporal</b> e <b>Ambiental</b>. Essa padronização facilita a priorização "
        "de correções e auxilia na tomada de decisão estratégica.",
        st["body"],
    ))
    story.append(PageBreak())

    # =====================================================================
    # 3. INTRODUÇÃO
    # =====================================================================
    story.append(Paragraph("Introdução", st["section"]))
    story.append(Paragraph("Escopo", st["subsection"]))
    story.append(Paragraph(
        "Os testes contidos neste relatório foram realizados nos ativos abaixo:",
        st["body"],
    ))

    scope_data = [["Escopo"]]
    for s in scope_list:
        scope_data.append([Paragraph(_esc(s), st["table_cell"])])
    scope_table = Table(scope_data, colWidths=[16.5 * cm])
    scope_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(scope_table)

    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(
        "O modelo utilizado neste teste foi <b>Gray-box</b> "
        "(automatizado via HADES AI).",
        st["body"],
    ))
    story.append(PageBreak())

    # =====================================================================
    # 4. CRONOGRAMA
    # =====================================================================
    story.append(Paragraph("Cronograma", st["section"]))
    story.append(Paragraph(
        "Cronograma de execução das atividades de teste de segurança:",
        st["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    # Compute scan start/end from executed commands or fall back to report date
    scan_start = report_date
    scan_end = report_date
    if executed_cmds:
        sorted_cmds = sorted(executed_cmds, key=lambda c: c.created_at)
        scan_start = sorted_cmds[0].created_at.strftime("%d/%m/%Y %H:%M")
        scan_end = sorted_cmds[-1].created_at.strftime("%d/%m/%Y %H:%M")

    crono_data = [
        ["Atividade", "Data / Período"],
        [
            Paragraph("Execução do Scan Automatizado", st["table_cell"]),
            Paragraph(scan_start, st["table_cell_center"]),
        ],
        [
            Paragraph("Finalização da Coleta", st["table_cell"]),
            Paragraph(scan_end, st["table_cell_center"]),
        ],
        [
            Paragraph("Geração do Relatório", st["table_cell"]),
            Paragraph(report_date, st["table_cell_center"]),
        ],
    ]
    crono_table = Table(crono_data, colWidths=[9 * cm, 7.5 * cm])
    crono_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(crono_table)
    story.append(PageBreak())

    # =====================================================================
    # 5. VERSIONAMENTO
    # =====================================================================
    story.append(Paragraph("Versionamento", st["section"]))
    ver_data = [
        ["Versão", "Data", "Autor", "Observações"],
        [
            Paragraph("1.0", st["table_cell_center"]),
            Paragraph(report_date, st["table_cell_center"]),
            Paragraph("HADES AI", st["table_cell"]),
            Paragraph("Geração automática do relatório", st["table_cell"]),
        ],
    ]
    ver_table = Table(ver_data, colWidths=[2 * cm, 3 * cm, 4 * cm, 7.5 * cm])
    ver_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(ver_table)
    story.append(PageBreak())

    # =====================================================================
    # 6. VULNERABILIDADES DETECTADAS (summary table)
    # =====================================================================
    story.append(Paragraph("Vulnerabilidades Detectadas", st["section"]))
    story.append(Paragraph(
        "As vulnerabilidades a seguir foram identificadas durante a Avaliação "
        "Técnica de Segurança. Cada uma está documentada com severidade, "
        "descrição detalhada, passos para reprodução, impactos e recomendações "
        "de correção.",
        st["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    severity_order = ["critical", "high", "medium", "low", "info"]
    finding_num = 0
    numbered_findings: list[tuple[int, Finding]] = []

    for sev in severity_order:
        sev_findings = [f for f in findings if f.severity.value == sev]
        if not sev_findings:
            continue

        story.append(Paragraph(
            f'<font color="{SEV_COLORS[sev].hexval()}">'
            f'<b>{SEV_PT[sev]}s</b></font>',
            st["sev_label"],
        ))

        rows = [["Vulnerabilidade", "Ativo", "CVSS", "Status"]]
        for f in sev_findings:
            finding_num += 1
            numbered_findings.append((finding_num, f))
            cvss = SEV_CVSS[sev]

            sev_color = SEV_COLORS[sev].hexval()

            rows.append([
                Paragraph(f"#{finding_num} - {_esc(f.title)}", st["table_cell"]),
                Paragraph(_esc(target), st["table_cell"]),
                Paragraph(
                    f'<font color="{sev_color}"><b>{cvss}</b></font>',
                    st["table_cell_center"],
                ),
                Paragraph(
                    '<font color="#d99594">Pendente de Correção</font>',
                    st["table_cell"],
                ),
            ])

        tbl = Table(rows, colWidths=[6 * cm, 4.5 * cm, 2 * cm, 4 * cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 0.2 * cm))

    if not findings:
        story.append(Paragraph(
            "Nenhuma vulnerabilidade foi identificada durante o teste.",
            st["body"],
        ))

    story.append(PageBreak())

    # =====================================================================
    # 7. DETALHAMENTO DAS VULNERABILIDADES
    # =====================================================================
    story.append(Paragraph("Detalhamento das Vulnerabilidades", st["section"]))
    story.append(Spacer(1, 0.3 * cm))

    for num, f in numbered_findings:
        sev = f.severity.value
        sev_pt = SEV_PT.get(sev, sev.capitalize())
        cvss_score = SEV_CVSS[sev]
        cvss_vector = SEV_VECTOR[sev]
        sev_color = SEV_COLORS[sev]

        # -- Vuln header table --
        header_data = [
            [
                Paragraph("Ativo:", st["vuln_label"]),
                Paragraph(_esc(target), st["vuln_value"]),
            ],
            [
                Paragraph("Severidade:", st["vuln_label"]),
                Paragraph(
                    f'<font color="{sev_color.hexval()}"><b>{sev_pt}</b></font>',
                    st["vuln_value"],
                ),
            ],
            [
                Paragraph("Vulnerabilidade:", st["vuln_label"]),
                Paragraph(f"<b>#{num} - {_esc(f.title)}</b>", st["vuln_value"]),
            ],
            [
                Paragraph("CVSS Score:", st["vuln_label"]),
                Paragraph(
                    f"<b>{cvss_score}</b><br/>"
                    f'<font size="8">{cvss_vector}</font>',
                    st["vuln_value"],
                ),
            ],
        ]
        ht = Table(header_data, colWidths=[3.5 * cm, 13 * cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            # Colored left stripe for severity
            ("BACKGROUND", (0, 1), (0, 1), SEV_BG.get(sev, LIGHT_GRAY)),
        ]))
        story.append(ht)
        story.append(Spacer(1, 0.3 * cm))

        # -- Descrição --
        story.append(Paragraph("Descrição:", st["subsection"]))
        for line in f.description.strip().split("\n"):
            line = line.strip()
            if line:
                story.append(Paragraph(_esc(line), st["body"]))

        # -- Evidência (screenshots + terminal fallback) --
        if f.evidence:
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph("Evidência:", st["subsection"]))

            # 1. Screenshots (real images captured by Chromium)
            screenshot_files = []
            if f.screenshot_paths:
                screenshot_files = [
                    p for p in f.screenshot_paths.split("|")
                    if p and Path(p).exists()
                ]

            if screenshot_files:
                for sc_idx, sc_path in enumerate(screenshot_files, 1):
                    story.append(Paragraph(
                        f"<i>Evidência {sc_idx} — Captura de tela</i>",
                        st["evidence_label"],
                    ))
                    try:
                        img_w = PAGE_W - 2 * MARGIN - 6
                        img = Image(sc_path, width=img_w, height=img_w * 0.6)
                        img.hAlign = "CENTER"

                        img_tbl = Table(
                            [[" ", img]],
                            colWidths=[3, PAGE_W - 2 * MARGIN - 3],
                        )
                        ev_sev_color = SEV_COLORS.get(sev, GREEN_HEADER)
                        img_tbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (0, -1), ev_sev_color),
                            ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f5f5f5")),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("LEFTPADDING", (0, 0), (0, -1), 0),
                            ("LEFTPADDING", (1, 0), (1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ]))
                        story.append(img_tbl)
                        story.append(Spacer(1, 0.2 * cm))
                    except Exception:
                        pass

            # 2. Terminal output (text evidence, stripped of commands)
            output_only = _strip_commands_from_evidence(f.evidence.strip())
            if not output_only or len(output_only.strip()) < 30:
                output_only = f.evidence.strip()

            truncated = len(output_only) > 2000
            if truncated:
                output_only = output_only[:2000]

            evidence_blocks = [
                blk.strip()
                for blk in re.split(r'\n{2,}', output_only)
                if blk.strip()
            ]
            if not evidence_blocks:
                evidence_blocks = [output_only]

            sc_offset = len(screenshot_files)
            for ev_idx, ev_block in enumerate(evidence_blocks, sc_offset + 1):
                brief_desc = ev_block.split("\n")[0][:80]
                if len(ev_block.split("\n")[0]) > 80:
                    brief_desc += "..."
                story.append(Paragraph(
                    f"<i>Evidência {ev_idx} — {_esc(brief_desc)}</i>",
                    st["evidence_label"],
                ))

                ev_lines = _esc(ev_block).split("\n")
                ev_cell_content = "<br/>".join(
                    line if line.strip() else "&nbsp;" for line in ev_lines
                )

                term_style = ParagraphStyle(
                    f"term_{num}_{ev_idx}",
                    fontName="Courier",
                    fontSize=7,
                    textColor=colors.HexColor("#e0e0e0"),
                    leading=9,
                    leftIndent=8,
                    spaceAfter=0,
                )
                ev_inner = Paragraph(ev_cell_content, term_style)
                ev_sev_color = SEV_COLORS.get(sev, GREEN_HEADER)

                title_bar = Table(
                    [["  Terminal — Output"]],
                    colWidths=[PAGE_W - 2 * MARGIN],
                )
                title_bar.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#2d2d2d")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#888888")),
                    ("FONTNAME", (0, 0), (-1, -1), "Courier"),
                    ("FONTSIZE", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ]))
                story.append(title_bar)

                ev_tbl = Table(
                    [[" ", ev_inner]],
                    colWidths=[3, PAGE_W - 2 * MARGIN - 3],
                )
                ev_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), ev_sev_color),
                    ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#1e1e1e")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (0, -1), 0),
                    ("LEFTPADDING", (1, 0), (1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                story.append(ev_tbl)
                story.append(Spacer(1, 0.2 * cm))

            if truncated:
                story.append(Paragraph(
                    "<i>[... saída completa disponível no painel]</i>",
                    st["body_small"],
                ))

        # -- Passos para Reprodução (narrative, with code boxes) --
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("Passos para Reprodução:", st["subsection"]))

        repro_steps = _build_reproduction_steps(f, target, executed_cmds)
        for step_idx, step_item in enumerate(repro_steps, 1):
            story.append(Paragraph(
                f"<b>{step_idx}.</b> {_esc(step_item['step'])}",
                st["step_number"],
            ))
            if step_item.get("command"):
                story.append(Paragraph(
                    f"<font face='Courier' size='7'>$ {_esc(step_item['command'])}</font>",
                    st["step_code"],
                ))

        # -- Correções --
        if f.remediation:
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph("Correções:", st["subsection"]))
            for ri in f.remediation.strip().split("\n"):
                ri = ri.strip()
                if ri:
                    if ri.startswith(("- ", "* ", "• ")):
                        ri = ri[2:]
                    story.append(Paragraph(
                        f"&bull; {_esc(ri)}", st["bullet"],
                    ))

        # -- Impacto da Correção --
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("Impacto da Correção:", st["subsection"]))
        story.append(Paragraph(
            f"A implementação das correções recomendadas para a vulnerabilidade "
            f"<b>{_esc(f.title)}</b> resultará na eliminação ou mitigação "
            f"significativa do risco associado. Sistemas ou integrações que "
            f"dependam do comportamento atual podem requerer ajustes. Após a "
            f"aplicação, o ativo estará em conformidade com as melhores práticas "
            f"de segurança, reduzindo a superfície de ataque identificada.",
            st["body"],
        ))

        story.append(Spacer(1, 0.5 * cm))

        # Page break between vulnerabilities (except last)
        if (num, f) != numbered_findings[-1]:
            story.append(PageBreak())

    if not numbered_findings:
        story.append(Paragraph(
            "Nenhuma vulnerabilidade para detalhar.", st["body"],
        ))

    story.append(PageBreak())

    # =====================================================================
    # 8. LEADS EM ABERTO (conditional)
    # =====================================================================
    section_num = 8
    if open_leads:
        story.append(Paragraph("Pontos de Investigação em Aberto", st["section"]))
        story.append(Paragraph(
            "Os seguintes pontos foram identificados e requerem investigação "
            "adicional para determinar se representam vulnerabilidades exploráveis:",
            st["body"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        _cat_pt = {"route": "Rota", "technology": "Tecnologia", "config": "Configuração",
                   "credential": "Credencial", "exposure": "Exposição", "other": "Outro"}
        leads_data = [["#", "Ponto de Investigação", "Categoria", "Descrição"]]
        for i, ld in enumerate(open_leads, 1):
            desc = ld.description.replace("\n", " ").strip()[:200]
            leads_data.append([
                Paragraph(str(i), st["table_cell_center"]),
                Paragraph(_esc(ld.title), st["table_cell"]),
                Paragraph(_cat_pt.get(ld.category.value, ld.category.value), st["table_cell_center"]),
                Paragraph(_esc(desc), st["table_cell"]),
            ])

        lt = Table(leads_data, colWidths=[1 * cm, 4 * cm, 2.5 * cm, 9 * cm])
        lt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(lt)
        story.append(PageBreak())
        section_num += 1

    # =====================================================================
    # CONCLUSÃO
    # =====================================================================
    story.append(Paragraph("Conclusão", st["section"]))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f.severity.value] += 1

    total = len(findings)
    if total == 0:
        story.append(Paragraph(
            f"Os testes de segurança realizados no ativo <b>{_esc(target)}</b> "
            f"não identificaram vulnerabilidades exploráveis durante o período de "
            f"avaliação. Isso indica uma postura de segurança adequada para os "
            f"vetores testados, porém não garante ausência total de falhas.",
            st["body"],
        ))
    else:
        story.append(Paragraph(
            f"Os testes de segurança realizados no ativo <b>{_esc(target)}</b> "
            f"demonstram que o ambiente possui vulnerabilidades que podem ser "
            f"exploradas por agentes maliciosos. Essas falhas aumentam a superfície "
            f"de ataque e podem comprometer a confidencialidade, integridade e "
            f"disponibilidade das informações processadas.",
            st["body"],
        ))

        if severity_counts["critical"] > 0:
            crit_names = ", ".join(
                f.title for f in findings if f.severity.value == "critical"
            )
            story.append(Paragraph(
                f"Destaca-se, de forma prioritária, a(s) vulnerabilidade(s) "
                f"classificada(s) como <b>Crítica(s)</b>: <b>{_esc(crit_names)}</b>. "
                f"A correção deve ser tratada com prioridade máxima, devido ao "
                f"impacto direto na segurança dos dados e na continuidade operacional.",
                st["body"],
            ))

        if severity_counts["high"] > 0 or severity_counts["medium"] > 0:
            story.append(Paragraph(
                "As vulnerabilidades de severidade <b>Alta</b> e <b>Média</b> "
                "indicam fragilidades nos controles de acesso, tratamento de erros "
                "e gestão de informações sensíveis. Essas falhas podem ser combinadas "
                "em cenários reais para facilitar o reconhecimento do ambiente e a "
                "exploração de funcionalidades internas.",
                st["body"],
            ))

        story.append(Paragraph(
            "Recomenda-se priorizar a correção imediata das vulnerabilidades de "
            "severidade Crítica, seguida pela remediação das classificadas como "
            "Alta e Média. A incorporação de práticas contínuas de segurança ao "
            "ciclo de desenvolvimento (<b>SSDLC</b>) e a realização periódica de "
            "testes contribuirão para a redução de riscos e alinhamento com "
            "<b>OWASP Top 10</b>, <b>CIS Controls</b> e <b>CVSS 3.1</b>.",
            st["body"],
        ))

    # Mention security controls observed (dismissed leads indicate defenses)
    dismissed_leads = [ld for ld in leads if ld.status.value == "dismissed"]
    if dismissed_leads:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("Controles de Segurança Observados:", st["subsection"]))
        story.append(Paragraph(
            f"Durante a avaliação, foram identificados <b>{len(dismissed_leads)}</b> "
            f"ponto(s) que, após investigação, demonstraram possuir controles de "
            f"segurança adequados ou não representarem risco explorável no contexto "
            f"atual. Isso indica que o ambiente possui algumas camadas de proteção "
            f"ativas, embora as vulnerabilidades reportadas ainda necessitem de "
            f"correção prioritária.",
            st["body"],
        ))

    story.append(PageBreak())

    # =====================================================================
    # APÊNDICE: COMANDOS EXECUTADOS
    # =====================================================================
    if executed_cmds:
        story.append(Paragraph("Apêndice: Comandos Executados", st["section"]))
        story.append(Paragraph(
            f"Total de comandos executados: <b>{len(executed_cmds)}</b>",
            st["body"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        _phase_pt = {"recon": "Recon", "enumeration": "Enumeração", "exploitation": "Exploração",
                     "post_exploitation": "Pós-Exploração"}
        _risk_pt = {"safe": "Seguro", "low": "Baixo", "medium": "Médio", "high": "Alto",
                    "destructive": "Destrutivo"}
        cmd_data = [["#", "Comando", "Fase", "Risco", "Saída"]]
        for i, c in enumerate(executed_cmds, 1):
            exit_str = str(c.exit_code) if c.exit_code is not None else "N/A"
            cmd_text = c.command if len(c.command) <= 60 else c.command[:57] + "..."
            cmd_data.append([
                Paragraph(str(i), st["table_cell_center"]),
                Paragraph(f'<font face="Courier" size="7">{_esc(cmd_text)}</font>', st["table_cell"]),
                Paragraph(_phase_pt.get(c.phase.value, c.phase.value), st["table_cell_center"]),
                Paragraph(_risk_pt.get(c.risk_level.value, c.risk_level.value), st["table_cell_center"]),
                Paragraph(exit_str, st["table_cell_center"]),
            ])

        ct = Table(cmd_data, colWidths=[1 * cm, 9.5 * cm, 2.2 * cm, 2 * cm, 1.8 * cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), GREEN_HEADER),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Poppins-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ct)

    # =====================================================================
    # Build
    # =====================================================================
    import logging as _logging
    _pdf_logger = _logging.getLogger("hades.report_pdf")
    try:
        doc.build(story)
    except Exception as exc:
        _pdf_logger.exception("PDF generation failed: %s", exc)
        raise
    return buf.getvalue()
