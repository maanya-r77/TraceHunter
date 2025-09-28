import os
import csv
import glob
import json
import subprocess
import datetime
from pathlib import Path
from typing import List, Tuple, Optional

# Third-party libs
from Evtx.Evtx import Evtx

# Optional (not strictly required for core flow); retained for future enhancement
try:
    from Registry import Registry
except Exception:
    Registry = None


def _safe_ts(dt: datetime.datetime) -> str:
    try:
        return dt.isoformat(sep=" ")
    except Exception:
        return str(dt)


def evtx_paths(drive_letter: str) -> List[str]:
    base = Path(f"{drive_letter}:\\Windows\\System32\\winevt\\Logs")
    if not base.exists():
        return []
    return [str(p) for p in base.glob("*.evtx")]


def check_event_log_tamper(drive_letter: str, log_callback=print) -> None:
    """
    Heuristic: if Security.evtx exists, scan for events that often indicate tampering.
    - 1102 (The audit log was cleared)
    - 1100 (The event logging service has shut down)
    - 104  (The audit log was cleared) (older systems / alt sources)
    """
    sec_log = Path(f"{drive_letter}:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    if not sec_log.exists():
        log_callback("[!] Security.evtx not found; cannot evaluate tamper indicators.")
        return

    suspects = {1102, 1100, 104}
    hits = 0
    try:
        with Evtx(str(sec_log)) as ev:
            for rec in ev.records():
                try:
                    eid = int(rec.lxml().xpath("System/EventID/text()")[0])
                    if eid in suspects:
                        ts = rec.timestamp()
                        log_callback(f"[!] Possible tamper indicator EventID={eid} at {ts}")
                        hits += 1
                except Exception:
                    continue
    except Exception as e:
        log_callback(f"[!] Error reading Security.evtx: {e}")

    if hits == 0:
        log_callback("[+] No obvious EVTX tamper indicators found in Security.evtx.")


def find_log_deletions(drive_letter: str, log_callback=print) -> None:
    """
    Look for Security 1102 events (audit log cleared).
    """
    sec_log = Path(f"{drive_letter}:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    if not sec_log.exists():
        log_callback("[!] Security.evtx not found; cannot check log deletions.")
        return

    count_1102 = 0
    try:
        with Evtx(str(sec_log)) as ev:
            for rec in ev.records():
                try:
                    eid = int(rec.lxml().xpath("System/EventID/text()")[0])
                    if eid == 1102:
                        count_1102 += 1
                except Exception:
                    continue
    except Exception as e:
        log_callback(f"[!] Error reading Security.evtx: {e}")
        return

    if count_1102 > 0:
        log_callback(f"[!] Detected {count_1102} instances of EventID 1102 (audit log cleared).")
    else:
        log_callback("[+] No Security 1102 (audit log cleared) events detected.")


def count_events_by_date_range(drive_letter: str, start: datetime.datetime, end: datetime.datetime, log_callback=print) -> None:
    """
    Iterate all EVTX logs in standard path and count records within [start, end].
    """
    logs = evtx_paths(drive_letter)
    if not logs:
        log_callback("[!] No EVTX logs found under standard path.")
        return

    log_callback(f"[i] Counting EVTX records between {start} and {end}...")

    total = 0
    per_file = []
    for p in logs:
        count = 0
        try:
            with Evtx(p) as ev:
                for rec in ev.records():
                    try:
                        ts = rec.timestamp()
                        if start <= ts <= end:
                            count += 1
                    except Exception:
                        continue
            per_file.append((os.path.basename(p), count))
            total += count
        except Exception as e:
            log_callback(f"[!] Error reading {p}: {e}")

    for fname, cnt in per_file:
        log_callback(f"[+] {fname}: {cnt} events in range.")
    log_callback(f"[=] Total events in range: {total}")


def run_mftecmd_and_detect_timestomp(drive_letter: str, tools_dir: str, output_dir: str, log_callback=print) -> None:
    """
    Run MFTECmd.exe to parse $MFT and output CSV. Then diff StandardInfo vs FileName timestamps.
    Flags entries where Created/Modified/Accessed differ suspiciously.
    """
    exe_path = Path(tools_dir) / "MFTECmd.exe"
    if not exe_path.exists():
        log_callback("[!] tools/MFTECmd.exe not found. Skipping MFT analysis.")
        return

    os.makedirs(output_dir, exist_ok=True)
    out_csv = Path(output_dir) / "mftecmd_mft.csv"

    # Prefer device path for performance (may require admin): \\.\I:
    device_path = f"\\\\.\\{drive_letter}:"

    cmd = [
        str(exe_path),
        "-f", f"{device_path}\\$MFT",
        "--csv", str(out_csv),
        "--csvf", "mft.csv"
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_callback("[+] MFTECmd completed. Analyzing timestamps...")
    except Exception as e:
        log_callback(f"[!] MFTECmd failed: {e}")
        return

    suspicious = 0
    checked = 0
    try:
        with open(out_csv, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                checked += 1
                # Field names depend on MFTECmd version; keep robust keys
                si_ct = row.get("SI Creation", "") or row.get("SI Created", "")
                fn_ct = row.get("FN Creation", "") or row.get("FN Created", "")
                si_m = row.get("SI Last Modification", "") or row.get("SI Last Modified", "")
                fn_m = row.get("FN Last Modification", "") or row.get("FN Last Modified", "")
                si_a = row.get("SI Last Access", "")
                fn_a = row.get("FN Last Access", "")

                # Flag if large divergence exists
                def differs(a: str, b: str) -> bool:
                    return (a and b) and (a != b)

                if any([differs(si_ct, fn_ct), differs(si_m, fn_m), (si_a and fn_a and si_a != fn_a)]):
                    suspicious += 1
                    path = row.get("Path", row.get("File Path", ""))
                    log_callback(f"[!] Possible timestomp: {path} | SI vs FN mismatch")

        log_callback(f"[=] Timestomp check complete. Checked {checked} records, flagged {suspicious}.")
    except Exception as e:
        log_callback(f"[!] Error analyzing MFTECmd CSV: {e}")


def inspect_recycle_bin(drive_letter: str, log_callback=print) -> None:
    """
    Enumerate $Recycle.Bin and list $I* (info) and $R* (data) files per SID.
    """
    base = Path(f"{drive_letter}:\\$Recycle.Bin")
    if not base.exists():
        log_callback("[!] $Recycle.Bin not found.")
        return

    for sid_dir in base.iterdir():
        if not sid_dir.is_dir():
            continue
        items = list(sid_dir.glob("$I*"))
        data = list(sid_dir.glob("$R*"))
        if not items and not data:
            continue
        log_callback(f"[+] Recycle Bin SID {sid_dir.name}: {len(items)} info files, {len(data)} data files.")


def check_vss_presence(drive_letter: str, log_callback=print) -> None:
    """
    Heuristic checks in System Volume Information for offline images.
    """
    svi = Path(f"{drive_letter}:\\System Volume Information")
    if not svi.exists():
        log_callback("[!] System Volume Information not present (or access denied).")
        return

    indicators = 0
    for name in ["SPP", "SystemRestore", "tracking.log", "EfaSIDat", "IndexerVolumeGuid"]:
        if (svi / name).exists():
            indicators += 1

    if indicators:
        log_callback(f"[+] Found {indicators} VSS-related artifacts in System Volume Information (heuristic).")
    else:
        log_callback("[i] No obvious VSS artifacts found (heuristic; may still exist).")


def detect_anti_forensic_apps(drive_letter: str, signatures_path: str, log_callback=print) -> None:
    """
    Compare Program Files directories content vs known signatures.
    """
    try:
        with open(signatures_path, "r", encoding="utf-8") as f:
            sig = json.load(f)
    except Exception as e:
        log_callback(f"[!] Cannot load signatures: {e}")
        return

    exec_names = set(x.lower() for x in sig.get("executables", []))
    folder_keys = [x.lower() for x in sig.get("folders_keywords", [])]

    roots = [
        Path(f"{drive_letter}:\\Program Files"),
        Path(f"{drive_letter}:\\Program Files (x86)"),
        Path(f"{drive_letter}:\\Users"),
    ]

    hits = 0
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            try:
                name = p.name.lower()
                if p.is_file() and name in exec_names:
                    log_callback(f"[!] Anti-forensic executable found: {p}")
                    hits += 1
                if any(k in name for k in folder_keys):
                    # Avoid spamming for every nested item; show top dir matches
                    if p.is_dir():
                        log_callback(f"[i] Suspicious folder match: {p}")
            except Exception:
                continue

    if hits == 0:
        log_callback("[+] No anti-forensic executables detected by signature scan.")


