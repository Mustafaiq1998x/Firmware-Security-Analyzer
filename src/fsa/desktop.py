"""Native Tk inspection window. A spawned process handles untrusted images."""
import json
import multiprocessing
import queue
import shutil
import tempfile
import threading
import time
from pathlib import Path

from .analyzer import DEFAULT_MAX_FILE_SIZE
from .reporting import write_html, write_json
from .scan_worker import MAX_SECONDS, _analyze


def describe(report):
    a = report.get("packaged_firmware", report["analysis"])
    profile = a["firmware_profile"]
    identity = profile["identity"]
    archive = report.get("archive_inspection", {})
    count = archive.get("summary", {}).get("files")
    unit = "component images" if archive.get("format") == "components" else "regular archive members"
    inventory = profile.get("zip_inventory")
    if count is None and inventory:
        count, unit = inventory["regular_members"], "declared regular ZIP members"
    rows = [
        ("Image", report["input"]["name"]), ("Outer format", report["analysis"]["firmware_profile"]["outer_format"]),
        ("Firmware format", profile["outer_format"] if "packaged_firmware" in report else None), ("Update directory entries", len(profile["components"])
         if profile.get("directory_bytes") else None),
        ("Firmware member", report.get("packaged_firmware", {}).get("path")),
        ("Vendor", identity.get("vendor")), ("Architecture", identity.get("architecture")),
        ("Board / model ID", identity.get("board")), ("Supported devices", ", ".join(identity.get("supported_devices", []))),
        ("Operating system", identity.get("os_family") or identity.get("os_hint")),
        ("Distribution / release", " ".join(filter(None, (identity.get("distribution"), identity.get("release"))))),
        ("Build", identity.get("build")),
        ("Embedded filesystems", ", ".join(f"{p['format']} · {p['compression']} · {p['inode_count']} inodes" for p in profile.get("embedded_filesystems", []))),
        ("Target", identity.get("target")), ("Kernel strings / header versions", ", ".join(a["kernel_versions"])),
        ("Identification evidence", json.dumps(identity["evidence"], ensure_ascii=False) if identity.get("evidence") else ""),
        ("Encryption", profile["encryption"]["status"]),
        ("Cipher / mode", " ".join(filter(None,(profile["encryption"]["algorithm"],profile["encryption"].get("mode"))))),
        ("Encryption evidence", profile["encryption"]["evidence"]), ("CVE assessment", a["cve_assessment"]),
        ("File inventory", f"{count} {unit}" if count is not None else archive.get("reason","Not enumerated")),
        ("Size (bytes)", str(report["input"]["size_bytes"])), ("SHA-256", report["input"]["sha256"]),
    ]
    visible = [(label, value) for label, value in rows if value not in (None, "", "unknown")]
    if profile["outer_format"] == "unknown":
        formats = sorted({c["format"] for c in profile["components"]})
        visible.insert(1, ("Format coverage", "Outer header unrecognized. " +
                          ("Recognized inside: " + ", ".join(formats) if formats else "No supported component structure found.")))
    return visible


class Inspector:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.root = root
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#f3f6f4")
        style.configure("TLabel", background="#f3f6f4", foreground="#1f3735")
        style.configure("TButton", padding=(10, 7))
        style.configure("TNotebook.Tab", padding=(12, 7))
        style.configure("Treeview", rowheight=27, background="white", fieldbackground="white")
        style.configure("Treeview.Heading", background="#dae8df", padding=5)
        style.map("Treeview", background=[("selected", "#1b6559")])

        self.report = self.process = self.workspace = self.feed = self.poll_id = None
        self.exporting = False
        self.messages = queue.Queue()
        self.root.title("Firmware Security Analyzer")
        self.root.geometry("1040x700")
        self.root.minsize(690, 450)
        root.protocol("WM_DELETE_WINDOW", self.close)
        header = tk.Frame(root, background="#103d39", padx=22, pady=15)
        header.pack(fill="x")
        tk.Label(header, text="Firmware Security Analyzer", font=("DejaVu Sans",18,"bold"),
                 bg="#103d39", fg="white").pack(anchor="w")
        bar = ttk.Frame(root, padding=(14,12))
        bar.pack(fill="x")
        self.buttons = {}
        for label, action in [("Open firmware...",self.choose),("CVE feed...",self.choose_feed),
                              ("Cancel",self.cancel),("Save extracted files...",self.export),
                              ("Save report...",self.save)]:
            button = ttk.Button(bar,text=label,command=action)
            button.pack(side="left",padx=3)
            self.buttons[label] = button
        self.status = tk.StringVar(value="Choose a firmware image to inspect locally.")
        ttk.Label(root,textvariable=self.status,padding=(18,6),wraplength=970).pack(fill="x")
        self.book = ttk.Notebook(root)
        self.book.pack(fill="both",expand=True,padx=16,pady=12)
        self.tables = {}
        for name, cols in [("Overview",("Field","Value")), ("Components",("Type","Name","Offset","Bytes","Compression","Inodes")),
                           ("Files",("Path","Bytes","SHA-256")), ("Evidence",("Rule","Confidence","Evidence")),
                           ("CVEs",("CVE","Version","Assessment")), ("Signatures",("Type","Offset","Magic bytes"))]:
            tab = ttk.Frame(self.book)
            self.book.add(tab,text=name)
            table = ttk.Treeview(tab,columns=cols,show="headings")
            for col in cols:
                table.heading(col,text=col,anchor="w")
                table.column(col,width=330 if col in {"Value","SHA-256","Evidence","Path"} else 145,stretch=True)
            for direction, side, fill in [("vertical","right","y"),("horizontal","bottom","x")]:
                scroll = ttk.Scrollbar(tab,orient=direction,command=table.yview if fill=="y" else table.xview)
                table.configure(**{("yscrollcommand" if fill=="y" else "xscrollcommand"):scroll.set})
                scroll.pack(side=side,fill=fill)
            table.tag_configure("alternate", background="#f1f6f2")
            table.bind("<Double-1>", self.inspect_row)
            table.pack(fill="both",expand=True)
            self.tables[name] = table
        self.controls()

    def inspect_row(self, event):
        from tkinter import messagebox
        table = event.widget
        row = table.identify_row(event.y)
        if row:
            lines = [f"{column}: {value}" for column, value in
                     zip(table["columns"], table.item(row, "values"))]
            messagebox.showinfo("Inspection evidence", "\n\n".join(lines), parent=self.root)

    def controls(self):
        busy = bool(self.process or self.exporting)
        for name, button in self.buttons.items():
            allowed = not busy
            if name == "Cancel":
                allowed = self.process is not None
            elif name == "Save report...":
                allowed = allowed and self.report is not None
            elif name == "Save extracted files...":
                allowed = allowed and bool(self.report and self.report.get("archive_inspection",{}).get("entries"))
            button.configure(state="normal" if allowed else "disabled")

    def choose_feed(self):
        from tkinter import filedialog
        value = filedialog.askopenfilename(title="Select offline normalized CVE feed",filetypes=[("JSON","*.json")])
        if value:
            self.feed = value
            self.status.set(f"Feed for the next scan: {Path(value).name}")

    def choose(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Open firmware",filetypes=[
            ("Firmware images",("*.bin","*.dav","*.img","*.zip","*.tar","*.gz")),("All files","*")])
        if path:
            self.start(path)

    def start(self, path):
        self.source = path
        self.clear()
        self.workspace = tempfile.TemporaryDirectory(prefix="fsa-desktop-")
        self.process = multiprocessing.get_context("spawn").Process(
            target=_analyze,args=(path,self.workspace.name,DEFAULT_MAX_FILE_SIZE,False,self.feed,True))
        try:
            self.process.start()
        except OSError as exc:
            self.process = None
            self.clear()
            self.status.set(str(exc))
            self.controls()
            return
        self.deadline = time.monotonic()+MAX_SECONDS
        self.controls()
        self.status.set(f"Inspecting {Path(path).name}...")
        self.poll_id = self.root.after(100,self.poll)

    def poll(self):
        self.poll_id = None
        if self.process is None:
            return
        if self.process.is_alive():
            if time.monotonic() >= self.deadline:
                self.cancel()
                self.status.set("Analysis reached its time limit.")
            else:
                self.poll_id = self.root.after(100,self.poll)
            return
        self.process.join()
        self.process.close()
        self.process = None
        folder = Path(self.workspace.name)
        try:
            if (folder/"error.txt").exists():
                raise ValueError((folder/"error.txt").read_text(encoding="utf-8"))
            self.report = json.loads((folder/"result.json").read_text(encoding="utf-8"))
            self.display()
            self.status.set(f"Inspection complete · {self.report['input']['name']}")
        except (OSError, ValueError) as exc:
            self.clear()
            self.status.set(f"Inspection failed: {exc}")
        self.controls()

    def display(self):
        analysis = self.report["analysis"]
        firmware = self.report.get("packaged_firmware", analysis)
        contents = self.report.get("archive_inspection", {})
        groups = {"Overview":describe(self.report),
                  "Components":[(c["format"],c.get("name"),hex(c["offset"]),c["size_bytes"],c["compression"],c.get("inode_count"))
                                for c in firmware["firmware_profile"]["components"]],
                  "Files":[(e["path"],e["size_bytes"],e.get("sha256")) for e in contents.get("entries",[])],
                  "Evidence":[(f["rule"],f["confidence"],v) for f in firmware.get("heuristic_findings", analysis["heuristic_findings"]) for v in f["evidence"]],
                  "CVEs":[(c["cve"],c["detected_version"],c["status"]) for c in firmware["cve_matches"]],
                  "Signatures":[(s["name"],hex(s["offset"]),s["magic_hex"]) for s in firmware.get("signatures", analysis["signatures"])]}
        for name, rows in groups.items():
            for index, row in enumerate(rows):
                self.tables[name].insert("", "end",tags=("alternate",) if index % 2 else (),values=tuple("Unknown" if v is None or v=="" else v for v in row))
        self.book.select(0)

    def save(self):
        from tkinter import filedialog, messagebox
        dest = filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json"),("HTML","*.html")])
        if dest:
            try:
                if self.source_matches(dest):
                    raise ValueError("Select a different path from the input firmware.")
                (write_html if Path(dest).suffix.lower()==".html" else write_json)(self.report,dest)
            except (OSError,ValueError) as exc:
                messagebox.showerror("Save report",str(exc))

    def source_matches(self, dest):
        return Path(dest).exists() and Path(dest).samefile(self.source)

    def export(self):
        from tkinter import filedialog
        dest = filedialog.askdirectory(title="Choose parent folder for extracted files")
        if not dest:
            return
        src = Path(self.workspace.name)/"files"
        self.exporting = True
        self.controls()
        self.status.set("Saving extracted files...")
        def copy():
            directory = None
            try:
                directory = Path(tempfile.mkdtemp(prefix="fsa-extracted-",dir=dest))
                shutil.copytree(src,directory,dirs_exist_ok=True)
                self.messages.put(f"Saved extracted files to {directory}")
            except OSError as exc:
                if directory:
                    shutil.rmtree(directory,ignore_errors=True)
                self.messages.put(f"Export failed: {exc}")
        threading.Thread(target=copy).start()
        self.root.after(100,self.export_done)

    def export_done(self):
        try:
            self.status.set(self.messages.get_nowait())
        except queue.Empty:
            self.root.after(100,self.export_done)
            return
        self.exporting = False
        self.controls()

    def clear(self):
        self.report = None
        for table in self.tables.values():
            table.delete(*table.get_children())
        if self.workspace:
            self.workspace.cleanup()
            self.workspace = None

    def cancel(self):
        if self.poll_id is not None:
            self.root.after_cancel(self.poll_id)
            self.poll_id = None
        if self.process:
            self.process.kill()
            self.process.join()
            self.process.close()
            self.process = None
        self.clear()
        self.controls()
        self.status.set("Analysis cancelled.")

    def close(self):
        if self.exporting:
            self.status.set("Finishing file export before closing...")
            self.root.after(250,self.close)
            return
        self.cancel()
        self.root.destroy()


def main():
    multiprocessing.freeze_support()
    try:
        import tkinter as tk
    except ImportError as exc:
        raise SystemExit("Install Python's Tk support (python3-tk on Kali Linux).") from exc
    root = tk.Tk()
    Inspector(root)
    root.mainloop()
