import os
import threading
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from analysis import (
    check_event_log_tamper,
    find_log_deletions,
    count_events_by_date_range,
    run_mftecmd_and_detect_timestomp,
    inspect_recycle_bin,
    check_vss_presence,
    detect_anti_forensic_apps
)

from carving import carve


APP_NAME = "AFDT — Anti Forensic Detection Tool"
LOG_DIR  = "logs"
TOOLS_DIR = "tools"
SIG_PATH = os.path.join("signatures", "anti_forensics.json")


class Logger:
    def __init__(self, textbox: scrolledtext.ScrolledText):
        self.textbox = textbox
        ts = datetime.datetime.now().strftime("%Y-%m-%dT%H_%M_%S")
        os.makedirs(LOG_DIR, exist_ok=True)
        self.temp_path = os.path.join(LOG_DIR, "afdt_temp.log")
        self.final_path = os.path.join(LOG_DIR, f"afdt_{ts}.log")
        # reset temp
        open(self.temp_path, "w", encoding="utf-8").close()

    def log(self, msg: str):
        line = msg if msg.endswith("\n") else msg + "\n"
        try:
            self.textbox.insert(tk.END, line)
            self.textbox.see(tk.END)
            with open(self.temp_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    def finalize(self):
        try:
            with open(self.temp_path, "r", encoding="utf-8") as src, open(self.final_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
        except Exception:
            pass


class AFDTApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(APP_NAME)
        root.geometry("980x640")

        self.stop_event = threading.Event()
        self.worker = None

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Inputs
        row = 0
        ttk.Label(frm, text="Start Date (YYYY-MM-DD HH:MM:SS):").grid(column=0, row=row, sticky="w")
        self.start_var = tk.StringVar(value="2024-01-01 00:00:00")
        ttk.Entry(frm, textvariable=self.start_var, width=26).grid(column=1, row=row, sticky="w")

        ttk.Label(frm, text="End Date (YYYY-MM-DD HH:MM:SS):").grid(column=2, row=row, sticky="w", padx=(20,0))
        self.end_var = tk.StringVar(value=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ttk.Entry(frm, textvariable=self.end_var, width=26).grid(column=3, row=row, sticky="w")

        row += 1
        ttk.Label(frm, text='Mounted Drive Letter (e.g., "I") :').grid(column=0, row=row, sticky="w", pady=(8,0))
        self.drive_var = tk.StringVar(value="I")
        ttk.Entry(frm, textvariable=self.drive_var, width=6).grid(column=1, row=row, sticky="w", pady=(8,0))

        ttk.Label(frm, text="Tools Dir:").grid(column=2, row=row, sticky="w", padx=(20,0), pady=(8,0))
        self.tools_var = tk.StringVar(value=TOOLS_DIR)
        ttk.Entry(frm, textvariable=self.tools_var, width=30).grid(column=3, row=row, sticky="w", pady=(8,0))

        row += 1
        btn_start = ttk.Button(frm, text="Start Analysis", command=self.on_start)
        btn_start.grid(column=0, row=row, pady=10, sticky="w")

        btn_carve = ttk.Button(frm, text="Carving", command=self.on_carve)
        btn_carve.grid(column=1, row=row, pady=10, sticky="w")

        btn_stop = ttk.Button(frm, text="Stop", command=self.on_stop)
        btn_stop.grid(column=2, row=row, pady=10, sticky="w")

        btn_about = ttk.Button(frm, text="About", command=self.on_about)
        btn_about.grid(column=3, row=row, pady=10, sticky="w")

        row += 1
        self.text = scrolledtext.ScrolledText(frm, wrap=tk.WORD, height=25)
        self.text.grid(column=0, row=row, columnspan=4, sticky="nsew", pady=(10,0))

        frm.rowconfigure(row, weight=1)
        frm.columnconfigure(3, weight=1)

        self.logger = Logger(self.text)

    def parse_dates(self) -> tuple[datetime.datetime, datetime.datetime]:
        s = datetime.datetime.strptime(self.start_var.get(), "%Y-%m-%d %H:%M:%S")
        e = datetime.datetime.strptime(self.end_var.get(), "%Y-%m-%d %H:%M:%S")
        return s, e

    def on_start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("AFDT", "An operation is already running.")
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._run_analysis, daemon=True)
        self.worker.start()

    def on_carve(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("AFDT", "An operation is already running.")
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._run_carving, daemon=True)
        self.worker.start()

    def on_stop(self):
        self.stop_event.set()
        self.logger.log("[i] Stop requested. Current operation will halt ASAP and logs will be finalized.")
        # Finalize when thread ends

    def on_about(self):
        messagebox.showinfo("About AFDT", "AFDT — Anti Forensic Detection Tool\nVersion 0.1.0\nAuthor: You\n© 2025")

    def _run_analysis(self):
        drv = self.drive_var.get().strip(": ").upper()
        if not drv or len(drv) != 1 or not Path(f"{drv}:\\").exists():
            self.logger.log("[!] Invalid drive letter or drive not accessible.")
            return

        try:
            start, end = self.parse_dates()
        except Exception as e:
            self.logger.log(f"[!] Invalid date(s): {e}")
            return

        self.logger.log(f"[=] Starting analysis for {drv}: from {start} to {end}")
        self.logger.log("[i] Checking EVTX tamper indicators...")
        check_event_log_tamper(drv, log_callback=self.logger.log)
        if self.stop_event.is_set(): return self._finalize()

        self.logger.log("[i] Checking for log deletions (Security 1102)...")
        find_log_deletions(drv, log_callback=self.logger.log)
        if self.stop_event.is_set(): return self._finalize()

        self.logger.log("[i] Counting events by date range...")
        count_events_by_date_range(drv, start, end, log_callback=self.logger.log)
        if self.stop_event.is_set(): return self._finalize()

        self.logger.log("[i] Running MFT timestomp analysis (MFTECmd)...")
        run_mftecmd_and_detect_timestomp(drv, self.tools_var.get(), LOG_DIR, log_callback=self.logger.log)
        if self.stop_event.is_set(): return self._finalize()

        self.logger.log("[i] Inspecting Recycle Bin...")
        inspect_recycle_bin(drv, log_callback=self.logger.log)
        if self.stop_event.is_set(): return self._finalize()

        self.logger.log("[i] Checking Volume Shadow Copy artifacts (heuristic)...")
        check_vss_presence(drv, log_callback=self.logger.log)
        if self.stop_event.is_set(): return self._finalize()

        self.logger.log("[i] Scanning for anti-forensic apps (signatures)...")
        detect_anti_forensic_apps(drv, SIG_PATH, log_callback=self.logger.log)

        self._finalize()

    def _run_carving(self):
        drv = self.drive_var.get().strip(": ").upper()
        if not drv or len(drv) != 1 or not Path(f"{drv}:\\").exists():
            self.logger.log("[!] Invalid drive letter or drive not accessible.")
            return

        self.logger.log(f"[=] Starting carving on {drv}: (JPG, PNG, EXE, PS1, TXT, PF, BAT)")
        out_dir = os.getcwd()
        try:
            carve(drv, out_dir, log_callback=self.logger.log, device_mode=True)
        except Exception as e:
            self.logger.log(f"[!] Carving error: {e}")

        self._finalize()

    def _finalize(self):
        self.logger.log("[=] Operation ended. Writing final log...")
        self.logger.finalize()


def main():
    root = tk.Tk()
    app = AFDTApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
