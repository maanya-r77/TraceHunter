import os
from pathlib import Path

# Very simple, best-effort signature-based carving from a raw device or image file.
# WARNING: This is heuristic and may produce false positives/negatives.

MAGICS = {
    "jpg": (b"\xff\xd8\xff", b"\xff\xd9"),
    "png": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    "exe": (b"MZ", None),   # no reliable footer; carve fixed max length window
}

TEXT_EXTS = {"ps1", "txt", "bat"}
PREFETCH_MAGIC = b"SCCA"  # prefetch files begin with "MAM\x04" or "SCCA"; use SCCA (Win8/10/11)


def carve(drive_letter: str, out_dir: str, max_bytes: int = 1024 * 1024 * 1024, log_callback=print, device_mode: bool=True):
    """
    Attempt to read from raw device (e.g., \\\\.\\I:) and scan for signatures.
    Falls back to reading the root filesystem as a big stream (very limited).
    """
    os.makedirs(out_dir, exist_ok=True)
    for ext in ["jpg", "png", "exe", "ps1", "txt", "pf", "bat"]:
        os.makedirs(os.path.join(out_dir, ext), exist_ok=True)

    target = None
    if device_mode:
        target = f"\\\\.\\{drive_letter}:"
    else:
        # fall back to naive concat of files (poor man's approach)
        target = None

    if target:
        try:
            with open(target, "rb", buffering=1024*1024) as f:
                log_callback(f"[i] Scanning raw device {target} (up to {max_bytes} bytes)...")
                scan_stream(f, out_dir, max_bytes, log_callback)
                return
        except Exception as e:
            log_callback(f"[!] Could not open raw device {target}: {e}")

    # Fallback: walk files under the drive and scan each (very limited; mostly finds live files)
    root_path = Path(f"{drive_letter}:\\")
    log_callback(f"[i] Fallback scanning files under {root_path} (this will NOT find unallocated data).")
    for p in root_path.rglob("*"):
        try:
            if p.is_file():
                with open(p, "rb", buffering=512*1024) as f:
                    scan_stream(f, out_dir, 50*1024*1024, log_callback, prefix=p.name)
        except Exception:
            continue


def scan_stream(f, out_dir: str, max_bytes: int, log_callback=print, prefix: str="carve"):
    read = 0
    bufsize = 1024 * 1024
    window = b""
    jpg_idx = 0
    png_idx = 0
    exe_idx = 0
    pf_idx  = 0
    txt_idx = 0
    bat_idx = 0
    ps1_idx = 0

    # naive rolling buffer scan
    while read < max_bytes:
        chunk = f.read(bufsize)
        if not chunk:
            break
        read += len(chunk)
        window += chunk

        # JPG
        start, end = MAGICS["jpg"]
        si = window.find(start)
        while si != -1:
            ei = window.find(end, si+len(start))
            if ei != -1:
                data = window[si:ei+len(end)]
                out = os.path.join(out_dir, "jpg", f"{prefix}_carved_{jpg_idx:06d}.jpg")
                with open(out, "wb") as o:
                    o.write(data)
                jpg_idx += 1
                window = window[ei+len(end):]
                si = window.find(start)
            else:
                # keep last 1MB to catch boundary
                window = window[-1024*1024:]
                break

        # PNG
        start, end = MAGICS["png"]
        si = window.find(start)
        while si != -1:
            ei = window.find(end, si+len(start))
            if ei != -1:
                data = window[si:ei+len(end)]
                out = os.path.join(out_dir, "png", f"{prefix}_carved_{png_idx:06d}.png")
                with open(out, "wb") as o:
                    o.write(data)
                png_idx += 1
                window = window[ei+len(end):]
                si = window.find(start)
            else:
                window = window[-1024*1024:]
                break

        # EXE (MZ) — carve fixed window (1 MB) after magic
        si = window.find(MAGICS["exe"][0])
        while si != -1:
            endpos = min(si + 1024*1024, len(window))
            data = window[si:endpos]
            out = os.path.join(out_dir, "exe", f"{prefix}_carved_{exe_idx:06d}.exe")
            with open(out, "wb") as o:
                o.write(data)
            exe_idx += 1
            window = window[endpos:]
            si = window.find(MAGICS["exe"][0])

        # Prefetch "SCCA"
        si = window.find(PREFETCH_MAGIC)
        while si != -1:
            endpos = min(si + 512*1024, len(window))
            data = window[si:endpos]
            out = os.path.join(out_dir, "pf", f"{prefix}_carved_{pf_idx:06d}.pf")
            with open(out, "wb") as o:
                o.write(data)
            pf_idx += 1
            window = window[endpos:]
            si = window.find(PREFETCH_MAGIC)

        # Very naive text carving for PS1/TXT/BAT: extract long ASCII sequences
        def carve_text(ext: str, counter: int, min_len: int = 200):
            import re
            nonlocal window
            matches = list(re.finditer(rb"[ -~\r\n\t]{%d,}" % min_len, window))
            for m in matches[:2]:
                data = window[m.start(): m.end()]
                out = os.path.join(out_dir, ext, f"{prefix}_carved_{counter:06d}.{ext}")
                with open(out, "wb") as o:
                    o.write(data)
                counter += 1
            # trim buffer
            window = window[-1024*1024:]
            return counter

        txt_idx = carve_text("txt", txt_idx, min_len=400)
        bat_idx = carve_text("bat", bat_idx, min_len=200)
        ps1_idx = carve_text("ps1", ps1_idx, min_len=200)

    log_callback("[=] Carving pass complete.")
