<<<<<<< HEAD
# TraceHunter
TraceHunter (Anti-Forensic Detection Tool) is a Python-based Windows forensics tool that detects anti-forensic techniques, analyzes EVTX logs, checks MFT timestomping, inspects the Recycle Bin and Volume Shadow Copies, and recovers deleted files via carving.
=======
# AFDT — Anti Forensic Detection Tool

AFDT is a Windows-focused forensic analysis GUI that works **against a mounted Windows volume** (e.g., `I:`).
It performs checks on EVTX logs, Recycle Bin, Volume Shadow Copies (best effort on offline images), basic
anti-forensic app detection by signatures, and uses `MFTECmd.exe` for MFT timestomp detection.
It also includes a **simple, best-effort file carver** for common types.

> ⚠️ **Run as Administrator.** AFDT needs elevated privileges to read some paths and raw devices.
> ⚠️ **Image must be mounted** and assigned a drive letter (e.g., via Arsenal, FTK Imager, OS native mount, etc.).

## Features
- Review Windows Event Log service (tamper indicators via key events & EVTX health)
- Identify log deletion in EVTX (e.g., Security 1102)
- Count EVTX events by date range
- Timestomp detection via `MFTECmd.exe` (diff StandardInfo vs FileName timestamps)
- Recycle Bin inspection ($Recycle.Bin)
- Anti-forensic tools presence (signature scan in Program Files and other locations)
- Volume Shadow Copies presence (best-effort checks for offline images)
- **Carving** (best-effort, signature-based) of JPG, PNG, EXE, PS1, TXT, PF, BAT

## Requirements
- Windows 10/11 host
- Python 3.10+
- Mounted forensic image with a drive letter (e.g., `I:`)
- Admin privileges
- External tool: `tools/MFTECmd.exe` (NOT included). Download from Eric Zimmerman's tools and place here.

## Quick Start
```bash
# 1) (optional) Create venv
py -3 -m venv .venv && .venv\Scripts\activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run
python afdt.py
```

## Build a Standalone EXE (PyInstaller)
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --add-data "signatures;signatures" --add-binary "tools/MFTECmd.exe;tools" afdt.py
# Resulting AFDT.exe will be in dist/
```
> Ensure `tools/MFTECmd.exe` exists before building if you need MFT checks in the EXE.

## Notes & Limitations
- EVTX parsing uses `python-evtx` (read-only). Some newer Windows event schemas may be missing extended fields.
- Volume Shadow Copy checks are *heuristic* on mounted images: AFDT looks for known SVI artifacts. Running `vssadmin`
  against an offline image does not work.
- Carving is **best-effort signature-based** and may produce false positives/negatives. For serious cases, prefer
  professional carving tools (e.g., Magnet Axiom, X-Ways, Autopsy/TSK, etc.).
- Timestomp detection relies on `MFTECmd.exe` CSV output; results are heuristic indicators for deeper review.
- Always validate findings with secondary tools and procedures.
>>>>>>> 3dcd643 (Initial commit - AFDT project)
