#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GTFOBins Auditor (SAFE)
- Detects installed binaries that have entries in GTFOBins (via local repo clone)
- Optional: performs a real SUID scan and correlates with GTFOBins
- Optional: audits sudo permissions using 'sudo -n -l' (non-interactive)
- Adds a SAFE risk scoring model (no payload execution)
- DOES NOT execute payloads or exploit chains
- Optional JSON export
"""

import argparse
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any


# ----------------------------
# Data models
# ----------------------------

@dataclass
class BinFinding:
    binary: str
    path: Optional[str]
    gtfobins_page: Optional[str]
    functions: List[str]
    has_suid: bool
    file_caps: Optional[str]
    risk_score: int = 0
    risk_level: str = "INFO"
    risk_reasons: List[str] = None


@dataclass
class SuidFinding:
    path: str
    owner_uid: int
    group_gid: int
    mode_octal: str
    binary_name: str
    gtfobins_page: Optional[str]
    # will be filled after scoring:
    risk_score: int = 0
    risk_level: str = "INFO"
    risk_reasons: List[str] = None


@dataclass
class SudoAudit:
    ran: bool
    method: str
    ok: bool
    requires_password: bool
    raw: str
    nopasswd_cmds: List[str]
    allowed_cmds_lines: List[str]
    # overall sudo risk
    risk_score: int = 0
    risk_level: str = "INFO"
    risk_reasons: List[str] = None


# ----------------------------
# GTFOBins parsing (best-effort)
# ----------------------------

FRONT_MATTER_RE = re.compile(r"^---\s*(.*?)\s*---\s*", re.DOTALL)
FUNC_RE_INLINE = re.compile(r"functions:\s*\[(.*?)\]", re.IGNORECASE)
FUNC_RE_BLOCK = re.compile(r"functions:\s*\n((?:\s*-\s*.+\n)+)", re.IGNORECASE)
LIST_ITEM_RE = re.compile(r"^\s*-\s*(.+?)\s*$", re.MULTILINE)

# Light fallback for tags/keywords in the markdown (not perfect, but useful)
FALLBACK_FUNC_WORDS = {
    "shell",
    "suid",
    "sudo",
    "capabilities",
    "limited",
    "file-read",
    "file-write",
    "library-load",
}


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def extract_front_matter(md: str) -> str:
    m = FRONT_MATTER_RE.match(md)
    return m.group(1) if m else ""


def parse_functions(md: str) -> List[str]:
    """
    Tries to parse 'functions' from front-matter.
    If missing, falls back to scanning early content for known keywords.
    """
    fm = extract_front_matter(md)

    m = FUNC_RE_INLINE.search(fm)
    if m:
        raw = m.group(1).strip()
        parts = [p.strip().strip('"').strip("'") for p in raw.split(",") if p.strip()]
        return sorted(set(parts))

    m2 = FUNC_RE_BLOCK.search(fm)
    if m2:
        block = m2.group(1)
        items = [it.strip().strip('"').strip("'") for it in LIST_ITEM_RE.findall(block)]
        return sorted(set([i for i in items if i]))

    # fallback (best-effort)
    head = md[:4000].lower()
    found = sorted({w for w in FALLBACK_FUNC_WORDS if w in head})
    return found


def list_gtfobins_pages(gtfopath: str) -> Dict[str, str]:
    """
    Returns: binary_name -> page_path
    Typical GTFOBins structure: _gtfobins/<binary>.md
    """
    gdir = os.path.join(gtfopath, "_gtfobins")
    if not os.path.isdir(gdir):
        raise FileNotFoundError(f"Directory not found: {gdir}")

    mapping: Dict[str, str] = {}
    for fn in os.listdir(gdir):
        if fn.endswith(".md"):
            binary = fn[:-3]
            mapping[binary] = os.path.join(gdir, fn)
    return mapping


# ----------------------------
# System helpers
# ----------------------------

def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def is_suid(path: str) -> bool:
    try:
        st = os.stat(path)
        return bool(st.st_mode & 0o4000)
    except Exception:
        return False


def get_file_caps(path: str) -> Optional[str]:
    """
    Reads Linux capabilities via getcap if available.
    """
    if not shutil.which("getcap"):
        return None
    try:
        out = subprocess.check_output(
            ["getcap", "-n", path], stderr=subprocess.DEVNULL
        ).decode("utf-8", "replace").strip()
        return out if out else None
    except Exception:
        return None


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    """
    Runs a command with locale forced to English (C), to keep output consistent for parsing/logs.
    """
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    out, err = p.communicate()
    return p.returncode, out or "", err or ""


# ----------------------------
# Risk scoring (SAFE)
# ----------------------------

RISK_LEVELS = [
    ("CRITICAL", 80),
    ("HIGH", 60),
    ("MEDIUM", 35),
    ("LOW", 15),
    ("INFO", 0),
]


def risk_level_from_score(score: int) -> str:
    for level, threshold in RISK_LEVELS:
        if score >= threshold:
            return level
    return "INFO"


def compute_risk_for_binary(has_suid: bool, file_caps: Optional[str], functions: List[str]) -> Tuple[int, str, List[str]]:
    """
    SAFE scoring heuristic (no exploitation).
    Focus: privilege-related conditions + GTFOBins function categories.
    """
    score = 0
    reasons: List[str] = []

    funcs = set([f.lower() for f in (functions or [])])

    # Privilege context weights
    if has_suid:
        score += 60
        reasons.append("SUID bit set (runs with elevated privileges)")

    if file_caps:
        score += 20
        reasons.append(f"Linux capabilities present ({file_caps})")

    # GTFOBins function weights (capability-to-impact proxy)
    if "shell" in funcs:
        score += 20
        reasons.append("GTFOBins indicates potential shell capability in certain contexts")

    if "file-write" in funcs:
        score += 15
        reasons.append("GTFOBins indicates potential file-write capability in certain contexts")

    if "library-load" in funcs:
        score += 15
        reasons.append("GTFOBins indicates potential library-load abuse patterns in certain contexts")

    if "suid" in funcs:
        score += 10
        reasons.append("GTFOBins has SUID-related techniques for this binary")

    if "sudo" in funcs:
        score += 5
        reasons.append("GTFOBins has sudo-related techniques for this binary")

    if "capabilities" in funcs:
        score += 5
        reasons.append("GTFOBins has capabilities-related techniques for this binary")

    if "limited" in funcs:
        score += 2
        reasons.append("GTFOBins notes limited but non-zero abuse potential")

    # Clamp to 0..100
    score = max(0, min(100, score))
    level = risk_level_from_score(score)
    return score, level, reasons


def compute_risk_for_sudo_audit(nopasswd_cmds: List[str], ok: bool, requires_password: bool, raw: str) -> Tuple[int, str, List[str]]:
    score = 0
    reasons: List[str] = []

    if nopasswd_cmds:
        score = 100
        reasons.append("NOPASSWD sudo rules detected (automatic privilege escalation risk)")
        reasons.append(f"NOPASSWD entries count: {len(nopasswd_cmds)}")
        return score, "CRITICAL", reasons

    # If sudo listing was successful and no NOPASSWD, that's typically a good baseline
    if ok and not nopasswd_cmds:
        score = 10
        reasons.append("sudo permissions listed successfully; no NOPASSWD rules found (good baseline)")

    # If non-interactive listing requires password/TTY, it blocks automated enumeration
    if requires_password:
        score = max(score, 5)
        reasons.append("Non-interactive sudo listing requires password/TTY (reduces automation)")

    # If sudo audit failed for other reasons (e.g., not in sudoers), keep as INFO/LOW but record reason
    if (not ok) and (not requires_password):
        score = max(score, 5)
        if raw.strip():
            reasons.append("sudo audit did not return a permissions list; check raw output for details")

    score = max(0, min(100, score))
    level = risk_level_from_score(score)
    return score, level, reasons


# ----------------------------
# SUID scan
# ----------------------------

def suid_scan(paths: Optional[List[str]] = None) -> List[str]:
    """
    Scans for SUID files using 'find'. Suppresses errors.
    Default scope: common binary directories. Adjust as needed.
    """
    if not paths:
        paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]

    find_cmd = ["find"] + paths + ["-xdev", "-type", "f", "-perm", "-4000", "-print"]
    try:
        out = subprocess.check_output(find_cmd, stderr=subprocess.DEVNULL).decode("utf-8", "replace")
        files = [line.strip() for line in out.splitlines() if line.strip()]
        return sorted(set(files))
    except Exception:
        return []


def build_suid_findings(suid_files: List[str], gtfomap: Dict[str, str]) -> List[SuidFinding]:
    findings: List[SuidFinding] = []
    for p in suid_files:
        try:
            st = os.stat(p)
            mode = oct(st.st_mode & 0o7777)
            name = os.path.basename(p)
            page = gtfomap.get(name)
            findings.append(
                SuidFinding(
                    path=p,
                    owner_uid=st.st_uid,
                    group_gid=st.st_gid,
                    mode_octal=mode,
                    binary_name=name,
                    gtfobins_page=page,
                )
            )
        except Exception:
            continue
    return findings


# ----------------------------
# Sudo audit
# ----------------------------

SUDO_NOPASSWD_RE = re.compile(r"NOPASSWD:\s*(.*)$", re.IGNORECASE)


def parse_sudo_output(raw: str, method: str, ok: bool, requires_password: bool) -> SudoAudit:
    nopass = []
    allowed_lines = []

    for line in raw.splitlines():
        m = SUDO_NOPASSWD_RE.search(line)
        if m:
            cmdpart = m.group(1).strip()
            if cmdpart:
                nopass.append(cmdpart)

        # Typical sudo -l lines include (/path) patterns; keep them for reference
        if "(" in line and ")" in line and "/" in line:
            allowed_lines.append(line.strip())

    nopass = sorted(set(nopass))
    allowed_lines = sorted(set(allowed_lines))

    audit = SudoAudit(
        ran=True,
        method=method,
        ok=ok,
        requires_password=requires_password,
        raw=raw,
        nopasswd_cmds=nopass,
        allowed_cmds_lines=allowed_lines,
        risk_score=0,
        risk_level="INFO",
        risk_reasons=[],
    )
    # score it
    audit.risk_score, audit.risk_level, audit.risk_reasons = compute_risk_for_sudo_audit(
        audit.nopasswd_cmds, audit.ok, audit.requires_password, audit.raw
    )
    return audit


def audit_sudo(non_interactive_first: bool = True) -> SudoAudit:
    """
    Tries 'sudo -n -l' first (non-interactive).
    If it fails due to password requirements, marks requires_password=True.
    """
    if not shutil.which("sudo"):
        audit = SudoAudit(
            ran=False,
            method="none",
            ok=False,
            requires_password=False,
            raw="sudo command not found on this system",
            nopasswd_cmds=[],
            allowed_cmds_lines=[],
            risk_score=0,
            risk_level="INFO",
            risk_reasons=[],
        )
        audit.risk_score, audit.risk_level, audit.risk_reasons = compute_risk_for_sudo_audit(
            audit.nopasswd_cmds, audit.ok, audit.requires_password, audit.raw
        )
        return audit

    if non_interactive_first:
        rc, out, err = run_cmd(["sudo", "-n", "-l"])
        raw = (out + "\n" + err).strip()

        if rc == 0:
            return parse_sudo_output(raw, method="sudo -n -l", ok=True, requires_password=False)

        lowered = raw.lower()
        # Common non-interactive failures:
        if (
            "a password is required" in lowered
            or "password is required" in lowered
            or "no tty present" in lowered
            or "you must have a tty" in lowered
        ):
            return parse_sudo_output(raw, method="sudo -n -l", ok=False, requires_password=True)

        # Other errors (e.g., not in sudoers, policy issues, sudoers syntax, etc.)
        return parse_sudo_output(raw, method="sudo -n -l", ok=False, requires_password=False)

    # Optional interactive method (not recommended for automated runs)
    rc, out, err = run_cmd(["sudo", "-l"])
    raw = (out + "\n" + err).strip()
    return parse_sudo_output(raw, method="sudo -l", ok=(rc == 0), requires_password=(rc != 0))


# ----------------------------
# Main report builder
# ----------------------------

def build_installed_gtfobins_report(gtfomap: Dict[str, str], only_installed: bool = True) -> List[BinFinding]:
    findings: List[BinFinding] = []

    for binary, page_path in sorted(gtfomap.items(), key=lambda x: x[0].lower()):
        p = which(binary) if only_installed else None
        if only_installed and not p:
            continue

        md = read_text(page_path)
        funcs = parse_functions(md)

        has_suid = is_suid(p) if p else False
        caps = get_file_caps(p) if p else None

        bf = BinFinding(
            binary=binary,
            path=p,
            gtfobins_page=page_path,
            functions=funcs,
            has_suid=has_suid,
            file_caps=caps,
            risk_score=0,
            risk_level="INFO",
            risk_reasons=[],
        )
        bf.risk_score, bf.risk_level, bf.risk_reasons = compute_risk_for_binary(
            bf.has_suid, bf.file_caps, bf.functions
        )
        findings.append(bf)

    return findings


def summarize(findings: List[BinFinding]) -> Dict[str, int]:
    by_func: Dict[str, int] = {}
    suid_count = 0
    caps_count = 0

    for f in findings:
        if f.has_suid:
            suid_count += 1
        if f.file_caps:
            caps_count += 1
        for fn in f.functions:
            by_func[fn] = by_func.get(fn, 0) + 1

    out = {
        "total_gtfobins_installed": len(findings),
        "installed_with_suid": suid_count,
        "installed_with_capabilities": caps_count,
    }
    for k, v in sorted(by_func.items()):
        out[f"func_{k}"] = v
    return out


def top_risky(items: List[Any], top_n: int = 15) -> List[Any]:
    return sorted(items, key=lambda x: int(getattr(x, "risk_score", 0)), reverse=True)[:top_n]


def main():
    ap = argparse.ArgumentParser(
        description="GTFOBins Auditor (SAFE) - inventory + SUID scan + sudo audit + risk scoring (no payload execution)"
    )
    ap.add_argument("--gtfopath", required=True, help="Path to the locally cloned GTFOBins.github.io repository")
    ap.add_argument("--all", action="store_true", help="Include non-installed binaries (catalog mode)")
    ap.add_argument("--export", help="Export JSON report (e.g., report.json)")

    ap.add_argument("--scan-suid", action="store_true", help="Perform a real SUID scan and correlate with GTFOBins")
    ap.add_argument(
        "--suid-paths",
        nargs="*",
        default=None,
        help="Custom paths to scan for SUID files (default: common system binary dirs)",
    )
    ap.add_argument("--sudo-check", action="store_true", help="Audit sudo privileges using 'sudo -n -l'")
    ap.add_argument("--print-top", type=int, default=2000, help="Max lines to print in console sections")
    ap.add_argument("--top-risk", type=int, default=15, help="Show top N risky findings")
    args = ap.parse_args()

    gtfomap = list_gtfobins_pages(args.gtfopath)
    findings = build_installed_gtfobins_report(gtfomap, only_installed=not args.all)
    stats = summarize(findings)

    report: Dict[str, Any] = {
        "stats": stats,
        "findings": [asdict(x) for x in findings],
        "suid_scan": None,
        "sudo_audit": None,
        "notes": [
            "Risk score is a heuristic for prioritization only. It does NOT confirm exploitation.",
            "This tool is SAFE: it does not execute payloads or exploit chains.",
        ],
    }

    print("\n== GTFOBins Auditor (SAFE) ==")
    for k, v in stats.items():
        print(f"{k}: {v}")

    # --- SUID scan ---
    suid_findings: List[SuidFinding] = []
    if args.scan_suid:
        files = suid_scan(args.suid_paths)
        suid_findings = build_suid_findings(files, gtfomap)

        # score SUID findings:
        for s in suid_findings:
            # For SUID scan items, we often don't have parsed GTFOBins functions here.
            # Heuristic: if it has GTFOBins page, treat it as higher; otherwise lower.
            # We'll approximate functions:
            approx_funcs = ["suid"]
            if s.gtfobins_page:
                approx_funcs += ["shell", "file-write", "sudo"]  # conservative: mark as potentially abusable
            s.risk_score, s.risk_level, s.risk_reasons = compute_risk_for_binary(
                has_suid=True,
                file_caps=None,
                functions=approx_funcs
            )
            if s.gtfobins_page:
                s.risk_reasons.insert(0, "Has GTFOBins entry (known abuse techniques exist)")

        suid_gtfo = [x for x in suid_findings if x.gtfobins_page]
        report["suid_scan"] = {
            "paths_scanned": args.suid_paths or ["(default common dirs)"],
            "total_suid_found": len(suid_findings),
            "suid_with_gtfobins_page": len(suid_gtfo),
            "note": "SUID binaries that also have GTFOBins entries are higher priority for hardening/monitoring.",
            "items": [asdict(x) for x in suid_findings],
            "items_with_gtfobins": [asdict(x) for x in suid_gtfo],
        }

        print("\n== SUID Scan ==")
        print(f"total_suid_found: {len(suid_findings)}")
        print(f"suid_with_gtfobins_page: {len(suid_gtfo)}")

        print("\n-- SUID binaries with GTFOBins entries (HIGH PRIORITY) --")
        for x in suid_gtfo[:min(args.print_top, len(suid_gtfo))]:
            print(f"- {x.path}  mode={x.mode_octal}  owner={x.owner_uid}:{x.group_gid}  (gtfo: {x.binary_name})")

    # --- sudo audit ---
    if args.sudo_check:
        sudo_a = audit_sudo(non_interactive_first=True)
        report["sudo_audit"] = asdict(sudo_a)

        print("\n== Sudo Audit ==")
        print(f"method: {sudo_a.method}")
        print(f"ok: {sudo_a.ok}")
        print(f"requires_password: {sudo_a.requires_password}")
        print(f"risk_level: {sudo_a.risk_level}  risk_score: {sudo_a.risk_score}")

        if not sudo_a.ok:
            print("\n-- sudo raw output (error/details) --")
            print(sudo_a.raw)

        if sudo_a.nopasswd_cmds:
            print("\n-- NOPASSWD entries (CRITICAL) --")
            for c in sudo_a.nopasswd_cmds[:min(args.print_top, len(sudo_a.nopasswd_cmds))]:
                print(f"- {c}")

        if sudo_a.allowed_cmds_lines:
            print("\n-- Allowed command lines (from sudo output) --")
            for l in sudo_a.allowed_cmds_lines[:min(args.print_top, len(sudo_a.allowed_cmds_lines))]:
                print(f"- {l}")

        if sudo_a.requires_password:
            print("\n[!] 'sudo -n -l' indicates a password or TTY is required (non-interactive sudo listing is not allowed).")
            print("    If you want to inspect manually, run: sudo -l")

        if sudo_a.ok and not sudo_a.nopasswd_cmds:
            print("\n[+] No NOPASSWD sudo rules detected (good baseline).")

    # --- Top risky summary ---
    print("\n== Top Risky Findings (Installed binaries) ==")
    for x in top_risky(findings, top_n=args.top_risk):
        reasons = "; ".join((x.risk_reasons or [])[:4])
        print(f"- {x.binary:18} score={x.risk_score:3} level={x.risk_level:8} path={x.path or 'n/a'} | {reasons}")

    if args.scan_suid:
        print("\n== Top Risky Findings (SUID scan) ==")
        for x in top_risky(suid_findings, top_n=args.top_risk):
            reasons = "; ".join((x.risk_reasons or [])[:4])
            gtfo = "yes" if x.gtfobins_page else "no"
            print(f"- {x.binary_name:18} score={x.risk_score:3} level={x.risk_level:8} gtfo={gtfo} path={x.path} | {reasons}")

    # Installed findings list
    print("\n-- Installed GTFOBins-mapped binaries --" if not args.all else "\n-- GTFOBins catalog entries (including not installed) --")
    for f in findings[:min(args.print_top, len(findings))]:
        tags = []
        if f.has_suid:
            tags.append("SUID")
        if f.file_caps:
            tags.append("CAPS")
        tag_str = f" [{' '.join(tags)}]" if tags else ""
        funcs = ", ".join(f.functions) if f.functions else "n/a"
        print(f"- {f.binary:20} {f.path or 'n/a'}{tag_str} | risk={f.risk_level}:{f.risk_score} | funcs: {funcs}")
        if f.file_caps:
            print(f"  caps: {f.file_caps}")

    if args.export:
        with open(args.export, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
        print(f"\n[+] Report exported: {args.export}")


if __name__ == "__main__":
    main()
