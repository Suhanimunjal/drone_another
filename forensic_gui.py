#!/usr/bin/env python3
"""
forensic_gui.py — GUI Frontend for forensic_extract.sh

A tkinter-based graphical wrapper around the forensic_extract.sh pipeline.
Provides file browsing, option configuration, real-time log output,
and summary display.

Usage:
    ./forensic_gui.py
    python3 forensic_gui.py

Dependencies: python3-tk (apt install python3-tk)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import os
import sys
import signal
import json
from datetime import datetime


# =============================================================================
# UTILITY
# =============================================================================

def which(program):
    """Return path if program is found in PATH, else None."""
    for path in os.environ.get("PATH", "").split(os.pathsep):
        exe = os.path.join(path, program)
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            return exe
    return None


def find_script():
    """Locate forensic_extract.sh — same directory as this GUI, then PATH."""
    gui_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(gui_dir, "forensic_extract.sh"),
        os.path.join(gui_dir, "forensic_extract"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    # PATH lookup
    return which("forensic_extract.sh") or which("forensic_extract")


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class ForensicGUI:
    """tkinter GUI wrapping forensic_extract.sh."""

    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Extraction Pipeline v2.0")
        self.root.geometry("920x780")
        self.root.minsize(700, 600)

        # State
        self.process = None          # subprocess.Popen handle
        self.running = False
        self.cancelled = False
        self.script_path = find_script()

        # ----- Style -----
        style = ttk.Style()
        style.theme_use("clam") if "clam" in style.theme_names() else None
        style.configure("Red.TButton", foreground="red")
        style.configure("Green.TButton", foreground="green")
        style.configure("Header.TLabel", font=("Helvetica", 11, "bold"))

        self._build_menu()
        self._build_main_frame()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var,
                               relief=tk.SUNKEN, anchor=tk.W, padding=(4, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Check prerequisites on startup
        self.root.after(200, self._initial_checks)

    # =========================================================================
    # MENU
    # =========================================================================

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Output Directory", command=self._open_output)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        run_menu = tk.Menu(menubar, tearoff=0)
        run_menu.add_command(label="Start Extraction", command=self._start_extraction)
        run_menu.add_command(label="Cancel", command=self._cancel_extraction)
        run_menu.add_separator()
        run_menu.add_command(label="Clear Log", command=self._clear_log)
        menubar.add_cascade(label="Run", menu=run_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    # =========================================================================
    # MAIN LAYOUT
    # =========================================================================

    def _build_main_frame(self):
        # Outer paned window: top = config, bottom = output
        self.pw = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.pw.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # ----- TOP: Configuration -----
        top_frame = ttk.Frame(self.pw)
        self.pw.add(top_frame, weight=0)

        # -- Image & Output --
        io_frame = ttk.LabelFrame(top_frame, text=" Input / Output ", padding=8)
        io_frame.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(io_frame, text="Image path:", width=12, anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=(0, 4))
        self.img_var = tk.StringVar()
        ttk.Entry(io_frame, textvariable=self.img_var).grid(row=0, column=1, sticky=tk.EW, padx=(0, 4))
        ttk.Button(io_frame, text="Browse", command=self._browse_image).grid(row=0, column=2)

        ttk.Label(io_frame, text="Output dir:", width=12, anchor=tk.E).grid(row=1, column=0, sticky=tk.E, padx=(0, 4))
        self.out_var = tk.StringVar()
        ttk.Entry(io_frame, textvariable=self.out_var).grid(row=1, column=1, sticky=tk.EW, padx=(0, 4))
        ttk.Button(io_frame, text="Browse", command=self._browse_output).grid(row=1, column=2)

        io_frame.columnconfigure(1, weight=1)

        # -- Options --
        opt_frame = ttk.LabelFrame(top_frame, text=" Options ", padding=8)
        opt_frame.pack(fill=tk.X)

        # Row 0
        ttk.Label(opt_frame, text="Partition offset:", width=16, anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=(0, 4))
        self.offset_var = tk.StringVar()
        ttk.Entry(opt_frame, textvariable=self.offset_var, width=12).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(opt_frame, text="FS type:", width=10, anchor=tk.E).grid(row=0, column=2, sticky=tk.E, padx=(8, 4))
        self.fs_var = tk.StringVar(value="auto")
        fs_combo = ttk.Combobox(opt_frame, textvariable=self.fs_var, width=10,
                                values=["auto", "ntfs", "fat", "ext", "hfs", "exfat"])
        fs_combo.state(["readonly"])
        fs_combo.grid(row=0, column=3, sticky=tk.W)

        ttk.Label(opt_frame, text="Parallel jobs:", width=14, anchor=tk.E).grid(row=0, column=4, sticky=tk.E, padx=(8, 4))
        self.jobs_var = tk.IntVar(value=4)
        ttk.Spinbox(opt_frame, from_=1, to=32, textvariable=self.jobs_var, width=5).grid(row=0, column=5, sticky=tk.W)

        ttk.Label(opt_frame, text="Timeout (s):", width=12, anchor=tk.E).grid(row=0, column=6, sticky=tk.E, padx=(8, 4))
        self.timeout_var = tk.IntVar(value=30)
        ttk.Spinbox(opt_frame, from_=5, to=300, textvariable=self.timeout_var, width=6).grid(row=0, column=7, sticky=tk.W)

        # Row 1 — checkboxes
        self.keep_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Keep EWF mount", variable=self.keep_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=4)

        self.resume_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Resume", variable=self.resume_var).grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=4)

        self.dryrun_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Dry run", variable=self.dryrun_var).grid(row=1, column=4, columnspan=2, sticky=tk.W, padx=4)

        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Verbose", variable=self.verbose_var).grid(row=1, column=6, columnspan=2, sticky=tk.W, padx=4)

        # Row 2
        self.nohash_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Skip SHA1", variable=self.nohash_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=4)

        self.nofiletype_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Skip filetype", variable=self.nofiletype_var).grid(row=2, column=2, columnspan=2, sticky=tk.W, padx=4)

        # -- Run / Cancel buttons --
        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(fill=tk.X, pady=(6, 0))

        self.run_btn = ttk.Button(btn_frame, text="▶  Start Extraction",
                                  command=self._start_extraction, style="Green.TButton")
        self.run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.cancel_btn = ttk.Button(btn_frame, text="■  Cancel",
                                     command=self._cancel_extraction, style="Red.TButton",
                                     state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT)

        self.clear_btn = ttk.Button(btn_frame, text="Clear Log", command=self._clear_log)
        self.clear_btn.pack(side=tk.RIGHT)

        # ----- BOTTOM: Log output -----
        log_frame = ttk.LabelFrame(self.pw, text=" Pipeline Output ", padding=4)
        self.pw.add(log_frame, weight=1)

        log_paned = ttk.PanedWindow(log_frame, orient=tk.VERTICAL)
        log_paned.pack(fill=tk.BOTH, expand=True)

        # Log text widget
        text_frame = ttk.Frame(log_paned)
        log_paned.add(text_frame, weight=1)

        self.log_text = tk.Text(text_frame, wrap=tk.WORD, state=tk.DISABLED,
                                font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4",
                                insertbackground="white")
        self.log_text.tag_configure("info", foreground="#6a9955")
        self.log_text.tag_configure("warn", foreground="#dcdcaa")
        self.log_text.tag_configure("error", foreground="#f44747")
        self.log_text.tag_configure("debug", foreground="#569cd6")
        self.log_text.tag_configure("stage", foreground="#c586c0", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("header", foreground="#4fc1ff", font=("Consolas", 10, "bold"))

        vsb = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Summary frame (collapsible at bottom of log section)
        self.summary_frame = ttk.LabelFrame(log_paned, text=" Summary ", padding=4)
        log_paned.add(self.summary_frame, weight=0)

        self.summary_text = tk.Text(self.summary_frame, wrap=tk.WORD, state=tk.DISABLED,
                                    height=6, font=("Consolas", 9), bg="#252526", fg="#cccccc")
        self.summary_text.pack(fill=tk.BOTH, expand=True)

    # =========================================================================
    # LOGGING
    # =========================================================================

    def log(self, message, tag=None):
        """Append line to log widget (thread-safe via root.after)."""
        def _append():
            self.log_text.configure(state=tk.NORMAL)
            if tag:
                self.log_text.insert(tk.END, message + "\n", tag)
            else:
                self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
        self.root.after(0, _append)

    def set_summary(self, text):
        """Set summary widget content."""
        def _set():
            self.summary_text.configure(state=tk.NORMAL)
            self.summary_text.delete(1.0, tk.END)
            self.summary_text.insert(tk.END, text)
            self.summary_text.configure(state=tk.DISABLED)
        self.root.after(0, _set)

    def set_status(self, text):
        """Update status bar."""
        self.root.after(0, lambda: self.status_var.set(text))

    def _clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)

    # =========================================================================
    # DIALOGS / ACTIONS
    # =========================================================================

    def _browse_image(self):
        path = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[("Disk images", "*.dd *.img *.raw *.E01 *.e01 *.bin"),
                       ("All files", "*.*")])
        if path:
            self.img_var.set(path)
            # Auto-suggest output directory
            if not self.out_var.get():
                base = os.path.splitext(os.path.basename(path))[0]
                suggested = os.path.join(os.path.dirname(path), base + "_extracted")
                self.out_var.set(suggested)

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.out_var.set(path)

    def _open_output(self):
        out = self.out_var.get()
        if out and os.path.isdir(out):
            try:
                if sys.platform == "win32":
                    os.startfile(out)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", out])
                else:
                    subprocess.Popen(["xdg-open", out])
            except Exception as e:
                self.log(f"Could not open directory: {e}", "warn")
        else:
            messagebox.showinfo("Output Directory",
                                "No output directory set or does not exist yet.")

    def _show_about(self):
        messagebox.showinfo("About",
                            "Forensic Extraction Pipeline v2.0\n\n"
                            "A GUI frontend for The Sleuth Kit-based\n"
                            "disk image file extraction.\n\n"
                            "Powered by: TSK, ewf-tools, GNU parallel")

    def _initial_checks(self):
        """Warn about missing dependencies."""
        issues = []
        for cmd in ["fls", "icat", "mmls", "fsstat"]:
            if not which(cmd):
                issues.append(f"  • {cmd}  (install: apt install sleuthkit)")
        if not which("ewfmount"):
            issues.append("  • ewfmount  (install: apt install ewf-tools)")
        if not which("parallel") and not which("xargs"):
            issues.append("  • parallel or xargs  (install: apt install parallel)")

        if issues:
            msg = "Some tools are missing:\n" + "\n".join(issues) + \
                  "\n\nInstall them and restart, or the pipeline may fail."
            self.log("[WARN] Missing dependencies detected", "warn")
            for line in issues:
                self.log(f"       {line}", "warn")
            messagebox.showwarning("Missing Tools", msg)
        else:
            self.log("[INFO] All required tools found.", "info")

        if not self.script_path:
            self.log("[ERROR] forensic_extract.sh not found in same directory or PATH.", "error")
            messagebox.showerror("Script Not Found",
                                 "forensic_extract.sh must be in the same directory\n"
                                 "as this GUI, or in your PATH.")

    # =========================================================================
    # COMMAND BUILDING
    # =========================================================================

    def _build_command(self):
        """Build the command list for subprocess."""
        args = [self.script_path, "-i", self.img_var.get(), "-o", self.out_var.get()]

        offset = self.offset_var.get().strip()
        if offset:
            args.extend(["-p", offset])

        fs = self.fs_var.get()
        if fs and fs != "auto":
            args.extend(["-f", fs])

        args.extend(["-j", str(self.jobs_var.get())])
        args.extend(["-t", str(self.timeout_var.get())])

        if self.keep_var.get():
            args.append("-k")
        if self.resume_var.get():
            args.append("-r")
        if self.dryrun_var.get():
            args.append("-n")
        if self.verbose_var.get():
            args.append("-v")
        if self.nohash_var.get():
            args.append("--no-hash")
        if self.nofiletype_var.get():
            args.append("--no-filetype")

        return args

    # =========================================================================
    # EXTRACTION LIFECYCLE
    # =========================================================================

    def _start_extraction(self):
        if self.running:
            messagebox.showwarning("Already Running",
                                   "Extraction is already in progress.")
            return

        # Validate inputs
        img = self.img_var.get().strip()
        out = self.out_var.get().strip()
        if not img:
            messagebox.showerror("Missing Input", "Please select a disk image.")
            return
        if not os.path.isfile(img):
            messagebox.showerror("Invalid Image", f"File not found:\n{img}")
            return
        if not out:
            messagebox.showerror("Missing Input", "Please select an output directory.")
            return

        if not self.script_path:
            messagebox.showerror("Script Not Found", "forensic_extract.sh not found.")
            return

        self.cancelled = False
        self.running = True
        self.run_btn.configure(state=tk.DISABLED)
        self.cancel_btn.configure(state=tk.NORMAL)

        self._clear_log()
        self.set_summary("Running…")

        cmd = self._build_command()

        self.log("═" * 60, "header")
        self.log("  FORENSIC EXTRACTION PIPELINE v2.0", "header")
        self.log("═" * 60, "header")
        self.log(f"Image : {img}")
        self.log(f"Output: {out}")
        self.log(f"Args  : {' '.join(cmd)}")
        self.log("")
        self.set_status("Running…")

        # Launch in background thread
        thread = threading.Thread(target=self._run_pipeline, args=(cmd,), daemon=True)
        thread.start()

    def _run_pipeline(self, cmd):
        """Run forensic_extract.sh in a subprocess, read output line by line."""
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                preexec_fn=(os.setsid if sys.platform != "win32" else None),
            )

            summary_lines = []
            in_summary = False

            for line in iter(self.process.stdout.readline, ""):
                if self.cancelled:
                    break

                line = line.rstrip("\n\r")
                if not line:
                    continue

                # Classify tags for colour
                tag = None
                if line.startswith("[ERROR]") or "ERROR" in line:
                    tag = "error"
                elif line.startswith("[WARN]") or "WARN" in line:
                    tag = "warn"
                elif line.startswith("[DEBUG]") or "DEBUG" in line:
                    tag = "debug"
                elif line.startswith("[INFO ]"):
                    tag = "info"
                elif line.startswith("═══") or line.startswith("╔") or line.startswith("╚") or \
                     line.startswith("║"):
                    tag = "stage"
                elif line.startswith("▸") or "STAGE" in line:
                    tag = "stage"

                self.log(line, tag)

                # Capture summary section
                if "SUMMARY REPORT" in line:
                    in_summary = True
                    summary_lines = [line]
                elif in_summary:
                    if line.startswith("══════════════") and len(summary_lines) > 10:
                        in_summary = False
                        self.set_summary("\n".join(summary_lines))
                    else:
                        summary_lines.append(line)

            self.process.wait()

            if self.cancelled:
                self.log("")
                self.log("[WARN] Extraction cancelled by user.", "warn")
                self.set_status("Cancelled")
            else:
                retcode = self.process.returncode
                if retcode == 0:
                    self.log("")
                    self.log("[INFO] Pipeline completed successfully.", "info")
                    self.set_status("Completed ✓")
                    # Trigger final summary read
                    self._read_summary_file()
                else:
                    self.log("")
                    self.log(f"[ERROR] Pipeline exited with code {retcode}.", "error")
                    self.set_status(f"Failed (exit {retcode})")

        except FileNotFoundError:
            self.log(f"[ERROR] Script not found: {self.script_path}", "error")
            self.set_status("Script not found")
        except Exception as e:
            self.log(f"[ERROR] {e}", "error")
            self.set_status(f"Error: {e}")
        finally:
            self.running = False
            self.root.after(0, lambda: self.run_btn.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.cancel_btn.configure(state=tk.DISABLED))

    def _read_summary_file(self):
        """Read summary.txt after pipeline completes."""
        out_dir = self.out_var.get().strip()
        summary_path = os.path.join(out_dir, "logs", "summary.txt")
        if os.path.isfile(summary_path):
            try:
                with open(summary_path, "r") as f:
                    content = f.read()
                self.set_summary(content)
            except Exception:
                pass

    def _cancel_extraction(self):
        if self.process and self.running:
            self.cancelled = True
            self.log("[WARN] Cancelling… (sending SIGTERM to process group)", "warn")
            try:
                if sys.platform == "win32":
                    self.process.terminate()
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception:
                pass
            self.set_status("Cancelling…")

    def _on_close(self):
        if self.running:
            if not messagebox.askyesno("Confirm Exit",
                                       "Extraction is in progress.\n"
                                       "Cancel and exit?"):
                return
            self._cancel_extraction()
        self.root.destroy()


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    if not which("python3") and not which("python"):
        print("FATAL: Python not found.", file=sys.stderr)
        sys.exit(1)

    root = tk.Tk()
    app = ForensicGUI(root)
    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
