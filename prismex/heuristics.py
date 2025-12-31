"""Richer, offline heuristics for PE triage.

Heuristics are **opinionated** signals that can be computed without internet
access and without executing the sample. Each heuristic produces a
:class:`HeuristicHit` with:

- id: stable identifier used by reports and config overrides
- severity: low/medium/high/critical (informational, not CVSS)
- message: human-readable explanation
- score: point contribution to the PrismEX risk score

Configuration:
- Rules can be tuned/disabled via the rules JSON under ``heuristics``.
- Overrides can change score/severity or disable a heuristic entirely.

@QK
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None  # type: ignore

from .utils import compute_overlay_size


@dataclass
class HeuristicHit:
    """A single heuristic finding.

    score: contribution to the overall risk score (non-negative)
    """

    id: str
    severity: str
    message: str
    score: int
    data: Optional[Dict[str, Any]] = None


_PACKER_SECTION_PREFIXES = (
    "UPX",
    "ASPACK",
    "MPRESS",
    "FSG",
    "MEW",
    "PEC",
    "PES",
    "PETITE",
)

# A small, opinionated set of high-signal APIs for common behaviors.
# (This is additive to the legacy list used by apialert.)
_API_SETS: Dict[str, Tuple[str, int, List[str]]] = {
    "process_injection": (
        "Process injection / hollowing primitives",
        15,
        [
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "VirtualProtectEx",
            "QueueUserAPC",
            "SetThreadContext",
            "ResumeThread",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
        ],
    ),
    "credential_access": (
        "Credential access primitives",
        12,
        [
            "CredRead",
            "CredEnumerate",
            "CryptUnprotectData",
            "LsaRetrievePrivateData",
            "LogonUser",
        ],
    ),
    "persistence_registry": (
        "Registry persistence primitives",
        8,
        [
            "RegSetValue",
            "RegSetValueEx",
            "RegCreateKey",
            "RegCreateKeyEx",
            "RegOpenKey",
            "RegOpenKeyEx",
        ],
    ),
    "networking": (
        "Networking primitives",
        6,
        [
            "InternetOpen",
            "InternetOpenUrl",
            "InternetConnect",
            "HttpSendRequest",
            "URLDownloadToFile",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "WSAStartup",
            "connect",
            "recv",
            "send",
        ],
    ),
    "evasion": (
        "Evasion / anti-analysis primitives",
        10,
        [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugString",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "GetTickCount",
            "QueryPerformanceCounter",
            "Sleep",
        ],
    ),
}


_URL_RE = re.compile(r"https?://[^\s\"'>]{6,}", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BASE64ISH_RE = re.compile(r"\b[A-Za-z0-9+/]{100,}={0,2}\b")


def _section_flags(characteristics: int) -> Dict[str, bool]:
    # IMAGE_SCN_MEM_* flags
    return {
        "read": bool(characteristics & 0x40000000),
        "write": bool(characteristics & 0x80000000),
        "execute": bool(characteristics & 0x20000000),
    }


def run_heuristics(
    *,
    pe: pefile.PE,
    path: str,
    report: Dict[str, Any],
    include_strings: bool,
    rules: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[HeuristicHit]]:
    """Compute richer heuristics + attach high-level metrics.

    Returns (metrics, hits).
    """

    hits: List[HeuristicHit] = []
    metrics: Dict[str, Any] = {}

    hr = rules if isinstance(rules, dict) else {}
    overrides = hr.get("overrides", {}) if isinstance(hr.get("overrides"), dict) else {}

    def _apply_override(hit: HeuristicHit) -> Optional[HeuristicHit]:
        o = overrides.get(hit.id)
        if isinstance(o, dict):
            if o.get("enabled") is False:
                return None
            if "severity" in o:
                hit.severity = str(o.get("severity"))
            if "score" in o:
                try:
                    hit.score = int(o.get("score"))
                except Exception:
                    pass
        return hit

    def _emit(hit: HeuristicHit) -> None:
        h = _apply_override(hit)
        if h is None:
            return
        if h.score is None:
            h.score = 0
        hits.append(h)

    # ---- Overlay ----
    overlay = compute_overlay_size(pe, path)
    metrics["overlay_size"] = overlay
    try:
        fsize = int(report.get("target", {}).get("size") or 0)
    except Exception:
        fsize = 0

    if overlay > 0:
        frac = (overlay / fsize) if fsize else 0.0
        metrics["overlay_fraction"] = round(frac, 4)
        ov = hr.get("overlay", {}) if isinstance(hr.get("overlay"), dict) else {}
        min_bytes = int(ov.get("min_bytes", 1024 * 1024))
        min_frac = float(ov.get("min_fraction", 0.1))
        score_pts = int(ov.get("score", 8))
        severity = str(ov.get("severity", "medium"))
        if overlay > min_bytes or frac > min_frac:
            _emit(
                HeuristicHit(
                    id="overlay",
                    severity=severity,
                    message=f"File contains an overlay ({overlay} bytes).",
                    score=score_pts,
                    data={"overlay_size": overlay, "overlay_fraction": frac},
                )
            )

    # ---- Timestamp sanity ----
    ts = report.get("pe", {}).get("timestamp_utc")
    if ts:
        try:
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if dt.year < 1995:
                _emit(
                    HeuristicHit(
                        id="timestamp_old",
                        severity="low",
                        message=f"Timestamp is unusually old ({ts} UTC).",
                        score=2,
                    )
                )
            if dt > now:
                _emit(
                    HeuristicHit(
                        id="timestamp_future",
                        severity="low",
                        message=f"Timestamp is in the future ({ts} UTC).",
                        score=3,
                    )
                )
        except Exception:
            pass
    else:
        _emit(
            HeuristicHit(
                id="timestamp_missing",
                severity="low",
                message="Timestamp missing or unparsable.",
                score=1,
            )
        )

    # ---- Section anomalies ----
    sec = report.get("analysis", {}).get("sections", {})
    details = sec.get("details", []) if isinstance(sec, dict) else []

    high_entropy = []
    rwx = []
    packerish = []

    for s in details:
        name = str(s.get("section_name", ""))
        ent = float(s.get("entropy") or 0.0)
        raw = int(s.get("size_of_raw_data") or 0)
        ch = int(s.get("characteristics") or 0)
        fl = _section_flags(ch)

        ent_rule = hr.get("high_entropy", {}) if isinstance(hr.get("high_entropy"), dict) else {}
        ent_min_raw = int(ent_rule.get("min_raw_size", 4096))
        ent_th = float(ent_rule.get("entropy_threshold", 7.2))
        if raw >= ent_min_raw and ent >= ent_th:
            high_entropy.append({"name": name, "entropy": ent, "raw": raw})

        if fl["execute"] and fl["write"]:
            rwx.append({"name": name, "characteristics": ch})

        upper = name.upper().lstrip(".")
        if any(upper.startswith(p) for p in _PACKER_SECTION_PREFIXES):
            packerish.append(name)

    metrics["high_entropy_sections"] = high_entropy
    metrics["rwx_sections"] = rwx
    metrics["packerish_sections"] = packerish

    if high_entropy:
        _emit(
            HeuristicHit(
                id="high_entropy",
                severity=str((hr.get("high_entropy", {}) or {}).get("severity", "medium")),
                message=f"High entropy section(s) detected ({len(high_entropy)}).",
                score=int((hr.get("high_entropy", {}) or {}).get("score", 10)),
                data={"sections": high_entropy[:10]},
            )
        )

    if rwx:
        _emit(
            HeuristicHit(
                id="rwx_section",
                severity=str((hr.get("rwx_section", {}) or {}).get("severity", "high")),
                message=f"Writable + executable section(s) detected ({len(rwx)}).",
                score=int((hr.get("rwx_section", {}) or {}).get("score", 18)),
                data={"sections": rwx[:10]},
            )
        )

    if packerish:
        _emit(
            HeuristicHit(
                id="packerish_sections",
                severity=str((hr.get("packerish_sections", {}) or {}).get("severity", "medium")),
                message=f"Section name(s) resemble common packers: {', '.join(packerish[:6])}.",
                score=int((hr.get("packerish_sections", {}) or {}).get("score", 8)),
            )
        )

    # ---- Entrypoint location ----
    try:
        ep = int(report.get("pe", {}).get("entrypoint_rva") or 0)
        ep_sec = pe.get_section_by_rva(ep) if ep else None
        if ep_sec is not None:
            ch = int(ep_sec.Characteristics)
            fl = _section_flags(ch)
            if not fl["execute"]:
                name = ep_sec.Name.decode(errors="ignore").strip("\x00")
                _emit(
                    HeuristicHit(
                        id="entrypoint_nonexec",
                        severity=str((hr.get("entrypoint_nonexec", {}) or {}).get("severity", "high")),
                        message=f"Entrypoint is located in a non-executable section ({name}).",
                        score=int((hr.get("entrypoint_nonexec", {}) or {}).get("score", 14)),
                    )
                )
    except Exception:
        pass

    # ---- Import behavior clusters ----
    imports = report.get("analysis", {}).get("imports", {})
    flat_imports: List[str] = []
    if isinstance(imports, dict):
        for _dll, funcs in imports.items():
            if isinstance(funcs, list):
                for f in funcs:
                    if isinstance(f, str):
                        flat_imports.append(f)

    flat_upper = {x.upper() for x in flat_imports}
    beh_hits: List[Dict[str, Any]] = []
    for key, (desc, points, names) in _API_SETS.items():
        matched = [n for n in names if n.upper() in flat_upper]
        if matched:
            beh_hits.append({"id": key, "description": desc, "matched": matched})
            sev = "high" if points >= 12 else "medium"
            _emit(
                HeuristicHit(
                    id=f"imports_{key}",
                    severity=sev,
                    message=f"{desc}: {', '.join(matched[:8])}{'...' if len(matched) > 8 else ''}.",
                    score=points,
                    data={"matched": matched},
                )
            )

    metrics["import_behavior"] = beh_hits

    # ---- Strings signals ----
    if include_strings:
        strings = (report.get("analysis", {}).get("strings") or {}).get("samples", [])
        if isinstance(strings, list):
            urls = []
            ips = []
            b64ish = 0
            for s in strings:
                if not isinstance(s, str):
                    continue
                if len(urls) < 20:
                    urls.extend(_URL_RE.findall(s))
                if len(ips) < 20:
                    ips.extend(_IP_RE.findall(s))
                if _BASE64ISH_RE.search(s):
                    b64ish += 1

            urls = list(dict.fromkeys(urls))
            ips = list(dict.fromkeys(ips))
            metrics["string_urls"] = urls[:50]
            metrics["string_ips"] = ips[:50]
            metrics["string_base64ish_count"] = b64ish

            if urls:
                _emit(
                    HeuristicHit(
                        id="strings_urls",
                        severity="medium",
                        message=f"Found URL-like strings ({len(urls)}).",
                        score=6,
                        data={"urls": urls[:10]},
                    )
                )
            if ips:
                _emit(
                    HeuristicHit(
                        id="strings_ips",
                        severity="medium",
                        message=f"Found IP-like strings ({len(ips)}).",
                        score=6,
                        data={"ips": ips[:10]},
                    )
                )
            b64_min = int((hr.get("strings_base64ish", {}) or {}).get("min_count", 3))
            if b64ish >= b64_min:
                _emit(
                    HeuristicHit(
                        id="strings_base64ish",
                        severity=str((hr.get("strings_base64ish", {}) or {}).get("severity", "low")),
                        message=f"Found multiple base64-looking strings ({b64ish}).",
                        score=int((hr.get("strings_base64ish", {}) or {}).get("score", 3)),
                    )
                )

            # High-signal substrings
            hs = [
                ("powershell", 6, "medium"),
                ("cmd.exe", 4, "low"),
                ("rundll32", 4, "low"),
                ("reg add", 4, "low"),
                ("schtasks", 4, "low"),
            ]
            joined = "\n".join(strings[:200]).lower()
            for needle, pts, sev in hs:
                if needle in joined:
                    _emit(
                        HeuristicHit(
                            id=f"strings_{needle.replace('.', '_').replace(' ', '_')}",
                            severity=sev,
                            message=f"String indicators contain '{needle}'.",
                            score=pts,
                        )
                    )


    # ---- TLS callbacks ----
    try:
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls is not None:
            # pefile may expose a struct with AddressOfCallBacks; presence is already a signal.
            addr = getattr(getattr(tls, "struct", None), "AddressOfCallBacks", None)
            metrics["tls_callbacks"] = True
            metrics["tls_callbacks_address"] = int(addr) if isinstance(addr, int) else addr
            _emit(
                HeuristicHit(
                    id="tls_callbacks",
                    severity=str((hr.get("tls_callbacks", {}) or {}).get("severity", "medium")),
                    message="TLS callbacks present (often used for early execution before main entrypoint).",
                    score=int((hr.get("tls_callbacks", {}) or {}).get("score", 10)),
                    data={"address": metrics["tls_callbacks_address"]},
                )
            )
        else:
            metrics["tls_callbacks"] = False
    except Exception:
        pass

    # ---- Authenticode / certificate table presence ----
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        metrics["has_authenticode"] = bool(getattr(sec_dir, "Size", 0))
    except Exception:
        metrics["has_authenticode"] = False

    # ---- Import anomalies ----
    if isinstance(imports, dict) and not imports:
        _emit(
            HeuristicHit(
                id="no_imports",
                severity=str((hr.get("no_imports", {}) or {}).get("severity", "medium")),
                message="No import table entries found (packed/obfuscated binaries often hide imports).",
                score=int((hr.get("no_imports", {}) or {}).get("score", 6)),
            )
        )

    try:
        ordinal_count = sum(1 for x in flat_imports if isinstance(x, str) and x.lower().startswith("ordinal:"))
        total_imps = len(flat_imports)
        if total_imps >= 20:
            ratio = ordinal_count / max(1, total_imps)
            metrics["ordinal_import_ratio"] = round(ratio, 3)
            if ratio >= 0.5:
                _emit(
                    HeuristicHit(
                        id="ordinal_heavy_imports",
                        severity="medium",
                        message=f"Many imports are by ordinal ({ordinal_count}/{total_imps}).",
                        score=5,
                        data={"ordinal": ordinal_count, "total": total_imps},
                    )
                )
    except Exception:
        pass

    # ---- Section count anomalies ----
    try:
        sec_count = int(sec.get("count") or len(details) or 0)
        metrics["section_count"] = sec_count
        min_sec = int((hr.get("few_sections", {}) or {}).get("min_sections", 3))
        if sec_count and sec_count < min_sec:
            _emit(
                HeuristicHit(
                    id="few_sections",
                    severity="medium",
                    message=f"Unusually low number of sections ({sec_count}).",
                    score=6,
                )
            )
    except Exception:
        pass

    return metrics, hits
