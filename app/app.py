from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI(
    title="Rule 142 — Replace WS_UPLOAD/WS_DOWNLOAD",
    version="2.0"
)

# ---------------------------------------------------------------------------
# Models (aligned with reference: header + findings)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None   # ObsoleteUploadDownload
    severity: Optional[str] = None      # always "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None       # full line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which
    that match occurs (no extra lines).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1  # right after '\n'

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


# ---------------------------------------------------------------------------
# Detection (statement-scoped, multi-line safe)
# ---------------------------------------------------------------------------
# Capture ONE ABAP "CALL FUNCTION ... ." statement at a time.
STMT_RE = re.compile(r"(?is)\bCALL\s+FUNCTION\b[^.]*\.", re.DOTALL)

# Extract the function name inside the statement (handles 'NAME' or "NAME")
FN_NAME_RE = re.compile(
    r"(?i)\bCALL\s+FUNCTION\s+(?:'|\"|)\s*(?P<fname>[A-Z0-9_]+)\s*(?:'|\"|)",
    re.DOTALL,
)

# Obsolete, non-Unicode FMs to flag per Rule 142
OBSOLETE_FMS = {"WS_UPLOAD", "WS_DOWNLOAD", "UPLOAD", "DOWNLOAD"}


def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings: List[Finding] = []

    base_start = unit.start_line or 0  # block start line in full program

    for m in STMT_RE.finditer(src):
        stmt_start = m.start()
        stmt_end = m.end()
        stmt = m.group(0)

        # Try to extract the FM name
        name_match = FN_NAME_RE.search(stmt)
        if not name_match:
            continue

        fm = name_match.group("fname").upper()

        if fm in OBSOLETE_FMS:
            # Build a concrete suggestion depending on direction
            if "UPLOAD" in fm:
                suggestion = (
                    "Replace with Unicode-compliant APIs:\n"
                    "  CALL FUNCTION 'GUI_UPLOAD'\n"
                    "    EXPORTING\n"
                    "      filename = <path>\n"
                    "      filetype = 'ASC'\n"
                    "      encoding = 'UTF-8'\n"
                    "    TABLES\n"
                    "      data_tab = <itab>.\n"
                    "Or use CL_GUI_FRONTEND_SERVICES=>GUI_UPLOAD for OO style."
                )
            else:  # DOWNLOAD
                suggestion = (
                    "Replace with Unicode-compliant APIs:\n"
                    "  CALL FUNCTION 'GUI_DOWNLOAD'\n"
                    "    EXPORTING\n"
                    "      filename = <path>\n"
                    "      filetype = 'ASC'\n"
                    "      encoding = 'UTF-8'\n"
                    "    TABLES\n"
                    "      data_tab = <itab>.\n"
                    "Or use CL_GUI_FRONTEND_SERVICES=>GUI_DOWNLOAD for OO style."
                )

            # Line within this block (1-based)
            line_in_block = src[:stmt_start].count("\n") + 1

            # Snippet = full line containing the CALL FUNCTION statement
            snippet_line = get_line_snippet(src, stmt_start, stmt_end)
            snippet_line_count = snippet_line.count("\n") + 1  # usually 1

            # Absolute line numbers in full program
            starting_line_abs = base_start + line_in_block
            ending_line_abs = base_start + line_in_block + snippet_line_count

            finding = Finding(
                prog_name=unit.pgm_name,
                incl_name=unit.inc_name,
                types=unit.type,
                blockname=unit.name,
                starting_line=starting_line_abs,
                ending_line=ending_line_abs,
                issues_type="ObsoleteUploadDownload",
                severity="error",  # per your rule
                message=f"Obsolete function module '{fm}' detected (non-Unicode).",
                suggestion=suggestion,
                snippet=snippet_line.replace("\n", "\\n"),
            )
            findings.append(finding)

    out_unit = Unit(**unit.model_dump())
    out_unit.findings = findings
    return out_unit


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def scan_rule_array(units: List[Unit] = Body(...)):
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def scan_rule_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rule": 142, "version": "2.0"}
