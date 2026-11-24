import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime
from collections import Counter
import threading
from forensic_core import ForensicAnalyzer, discover_browser_profiles, export_csv, analyze_events
from report_generator import generate_html_report

APP_TITLE = "WebForensix V2 | Cross-Browser Digital Forensic Artifact Analyzer"

class AnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1380x850")
        self.root.minsize(1050, 680)
        self.analyzer = ForensicAnalyzer()
        self.events = []
        self.case_name = tk.StringVar(value="WebForensix Investigation")
        self.case_id = tk.StringVar(value="WF-" + datetime.now().strftime("%Y%m%d-%H%M"))
        self.status = tk.StringVar(value="Ready. Select browser profiles or scan default profiles.")
        self.filter_var = tk.StringVar()
        self.type_var = tk.StringVar(value="All")
        self.browser_var = tk.StringVar(value="All")
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style()
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("Title.TLabel", font=("Segoe UI", 19, "bold"), foreground="#17324d")
        style.configure("Sub.TLabel", font=("Segoe UI", 10), foreground="#617386")
        style.configure("Treeview", rowheight=27, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Card.TFrame", background="#eef4fa")
        style.configure("CardValue.TLabel", background="#eef4fa", foreground="#17324d", font=("Segoe UI", 17, "bold"))
        style.configure("CardName.TLabel", background="#eef4fa", foreground="#526477", font=("Segoe UI", 9))

    def _build(self):
        header = ttk.Frame(self.root, padding=(18, 12))
        header.pack(fill="x")
        ttk.Label(header, text="Cross-Browser Digital Forensic Artifact Analyzer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="WEBFORENSIX V2  •  Chrome  •  Microsoft Edge  •  Mozilla Firefox  •  Unified evidence timeline", style="Sub.TLabel").pack(anchor="w", pady=(4, 10))
        meta = ttk.Frame(header); meta.pack(fill="x")
        ttk.Label(meta, text="Case name").pack(side="left")
        ttk.Entry(meta, textvariable=self.case_name, width=30).pack(side="left", padx=(6,16))
        ttk.Label(meta, text="Case ID").pack(side="left")
        ttk.Entry(meta, textvariable=self.case_id, width=20).pack(side="left", padx=6)
        self.total_label = ttk.Label(meta, text="0 artifacts loaded")
        self.total_label.pack(side="right")

        actions = ttk.Frame(self.root, padding=(18, 0, 18, 10)); actions.pack(fill="x")
        ttk.Button(actions, text="Scan default browser profiles", command=self.scan_defaults).pack(side="left", padx=(0,7))
        ttk.Button(actions, text="Add profile / evidence folder", command=self.add_folder).pack(side="left", padx=7)
        ttk.Button(actions, text="Load demo evidence", command=self.load_demo).pack(side="left", padx=7)
        ttk.Button(actions, text="Generate HTML report", command=self.save_report).pack(side="right", padx=4)
        ttk.Button(actions, text="Export CSV", command=self.save_csv).pack(side="right", padx=4)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0,8))
        self.dashboard_tab = ttk.Frame(self.notebook, padding=12)
        self.timeline_tab = ttk.Frame(self.notebook, padding=10)
        self.insights_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.timeline_tab, text="Unified Timeline")
        self.notebook.add(self.insights_tab, text="Investigation Insights")
        self._build_dashboard()
        self._build_timeline()
        self._build_insights()
        ttk.Label(self.root, textvariable=self.status, relief="sunken", anchor="w", padding=7).pack(fill="x", side="bottom")

    def _build_dashboard(self):
        self.cards_frame = ttk.Frame(self.dashboard_tab); self.cards_frame.pack(fill="x", pady=(0,14))
        self.card_vars = {}
        for i, key in enumerate(("Total artifacts","History","Download","Search","Cookie")):
            frame = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=14)
            frame.grid(row=0, column=i, sticky="nsew", padx=5)
            self.cards_frame.columnconfigure(i, weight=1)
            value = tk.StringVar(value="0")
            self.card_vars[key] = value
            ttk.Label(frame, textvariable=value, style="CardValue.TLabel").pack(anchor="w")
            ttk.Label(frame, text=key, style="CardName.TLabel").pack(anchor="w")
        body = ttk.Panedwindow(self.dashboard_tab, orient="horizontal"); body.pack(fill="both", expand=True)
        left = ttk.Labelframe(body, text="Artifacts by browser", padding=12)
        right = ttk.Labelframe(body, text="Investigation summary", padding=12)
        body.add(left, weight=1); body.add(right, weight=2)
        self.browser_stats = ttk.Treeview(left, columns=("browser","count"), show="headings", height=8)
        self.browser_stats.heading("browser", text="Browser"); self.browser_stats.heading("count", text="Artifacts")
        self.browser_stats.column("browser", width=150); self.browser_stats.column("count", width=90, anchor="e")
        self.browser_stats.pack(fill="both", expand=True)
        self.summary_text = tk.Text(right, height=12, wrap="word", font=("Segoe UI",10), relief="flat")
        self.summary_text.pack(fill="both", expand=True)
        self.summary_text.insert("1.0","Scan browser profiles to populate the dashboard.\n\nURL indicators are heuristic review leads only; they do not prove malicious activity.")
        self.summary_text.configure(state="disabled")

    def _build_timeline(self):
        filters = ttk.Frame(self.timeline_tab); filters.pack(fill="x", pady=(0,8))
        ttk.Label(filters, text="Keyword").pack(side="left")
        ent = ttk.Entry(filters, textvariable=self.filter_var, width=30); ent.pack(side="left", padx=7)
        ent.bind("<KeyRelease>", lambda e: self.refresh_table())
        ttk.Label(filters, text="Artifact type").pack(side="left", padx=(15,4))
        cb = ttk.Combobox(filters, textvariable=self.type_var, values=["All","History","Download","Cookie","Search"], state="readonly", width=13)
        cb.pack(side="left"); cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())
        ttk.Label(filters, text="Browser").pack(side="left", padx=(15,4))
        self.browser_combo = ttk.Combobox(filters, textvariable=self.browser_var, values=["All","Chrome","Edge","Firefox"], state="readonly", width=12)
        self.browser_combo.pack(side="left"); self.browser_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())
        columns = ("time","browser","type","title","url","details")
        self.tree = ttk.Treeview(self.timeline_tab, columns=columns, show="headings")
        headings = {"time":"Timestamp (UTC)","browser":"Browser","type":"Artifact","title":"Title / Name","url":"URL / Domain","details":"Details"}
        widths = {"time":190,"browser":90,"type":85,"title":220,"url":360,"details":240}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=80, anchor="w")
        y = ttk.Scrollbar(self.timeline_tab, orient="vertical", command=self.tree.yview)
        x = ttk.Scrollbar(self.timeline_tab, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.tree.pack(fill="both", expand=True, side="top")
        y.pack(side="right", fill="y"); x.pack(fill="x", side="bottom")

    def _build_insights(self):
        self.insight_notebook = ttk.Notebook(self.insights_tab); self.insight_notebook.pack(fill="both", expand=True)
        self.suspicious_tab = ttk.Frame(self.insight_notebook, padding=8)
        self.correlation_tab = ttk.Frame(self.insight_notebook, padding=8)
        self.duplicate_tab = ttk.Frame(self.insight_notebook, padding=8)
        self.error_tab = ttk.Frame(self.insight_notebook, padding=8)
        self.insight_notebook.add(self.suspicious_tab, text="URL Review Indicators")
        self.insight_notebook.add(self.correlation_tab, text="Cross-browser Matches")
        self.insight_notebook.add(self.duplicate_tab, text="Potential Duplicates")
        self.insight_notebook.add(self.error_tab, text="Extraction Messages")
        self.suspicious_tree = self._make_insight_tree(self.suspicious_tab, ("time","browser","url","reason"), ("Timestamp","Browser","URL","Review reason"), (180,85,480,250))
        self.correlation_tree = self._make_insight_tree(self.correlation_tab, ("url","browsers","count","first","last"), ("Normalized URL","Browsers","Occurrences","First seen","Last seen"), (420,150,90,180,180))
        self.duplicate_tree = self._make_insight_tree(self.duplicate_tab, ("browser","type","title","url","time"), ("Browser","Type","Title","URL","Timestamp"), (90,90,220,420,180))
        self.error_text = tk.Text(self.error_tab, wrap="word", font=("Segoe UI",10))
        self.error_text.pack(fill="both", expand=True)
        self.error_text.insert("1.0","No scan has been performed yet.")

    def _make_insight_tree(self, parent, cols, heads, widths):
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        for c,h,w in zip(cols,heads,widths):
            tree.heading(c,text=h); tree.column(c,width=w,minwidth=80,anchor="w")
        y=ttk.Scrollbar(parent,orient="vertical",command=tree.yview)
        x=ttk.Scrollbar(parent,orient="horizontal",command=tree.xview)
        tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        tree.pack(fill="both",expand=True,side="top"); y.pack(side="right",fill="y"); x.pack(fill="x",side="bottom")
        return tree

    def _set_status(self, text):
        self.status.set(text)
        self.root.update_idletasks()

    def scan_defaults(self):
        paths = discover_browser_profiles()
        if not paths:
            messagebox.showinfo("No profiles found","No default browser profiles were detected. Use manual profile selection.")
            return
        self._run_extraction(paths)

    def add_folder(self):
        folder = filedialog.askdirectory(title="Select browser profile or evidence folder")
        if folder: self._run_extraction([Path(folder)])

    def _run_extraction(self, paths):
        self._set_status("Scanning selected browser profiles…")
        def progress(i,total,browser,path):
            self.root.after(0, lambda: self._set_status(f"Scanning database {i}/{total}: {browser} — {Path(path).parent.name}"))
        def work():
            try:
                self.analyzer.extract_from_paths(paths, progress=progress)
                self.events = self.analyzer.events
                self.root.after(0, self.refresh_all)
                msg = f"Extraction complete: {len(self.events):,} artifacts from selected profiles."
                self.root.after(0, lambda: self._set_status(msg))
            except Exception as exc:
                self.root.after(0, lambda: messagebox.showerror("Extraction error",str(exc)))
                self.root.after(0, lambda: self._set_status("Extraction failed."))
        threading.Thread(target=work,daemon=True).start()

    def load_demo(self):
        now = datetime.now().astimezone().isoformat()
        self.events = [
            {"timestamp":now,"browser":"Chrome","artifact_type":"History","title":"Example search","url":"https://www.google.com/search?q=digital+forensics","details":"Synthetic demo record","source_file":"DEMO"},
            {"timestamp":now,"browser":"Firefox","artifact_type":"History","title":"Forensic resources","url":"https://www.example.org/resources","details":"Synthetic demo record","source_file":"DEMO"},
            {"timestamp":now,"browser":"Edge","artifact_type":"Download","title":"sample_report.pdf","url":"https://www.example.org/sample_report.pdf","details":"Synthetic demo record","source_file":"DEMO"},
            {"timestamp":now,"browser":"Chrome","artifact_type":"Cookie","title":"session_id","url":"example.org","details":"Metadata only; synthetic demo record","source_file":"DEMO"},
            {"timestamp":now,"browser":"Chrome","artifact_type":"Search","title":"digital forensics","url":"https://www.google.com/search?q=digital+forensics","details":"Synthetic demo record","source_file":"DEMO"}
        ]
        self.analyzer.events = self.events; self.analyzer.evidence_hashes={}; self.analyzer.errors=[]
        self.refresh_all()
        self._set_status("Synthetic demo evidence loaded; these records are not from this computer.")

    def refresh_all(self):
        self.refresh_table(); self.refresh_dashboard(); self.refresh_insights()
        self.total_label.config(text=f"{len(self.events):,} artifacts loaded")

    def refresh_table(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        term=self.filter_var.get().lower().strip(); typ=self.type_var.get(); browser=self.browser_var.get()
        for e in sorted(self.events,key=lambda x:x.get("timestamp",""),reverse=True):
            if typ!="All" and e.get("artifact_type")!=typ: continue
            if browser!="All" and e.get("browser")!=browser: continue
            hay=" ".join(str(e.get(k,"")) for k in ("timestamp","browser","artifact_type","title","url","details")).lower()
            if term and term not in hay: continue
            self.tree.insert("","end",values=(e.get("timestamp",""),e.get("browser",""),e.get("artifact_type",""),e.get("title",""),e.get("url",""),e.get("details","")))

    def refresh_dashboard(self):
        analysis=analyze_events(self.events)
        counts=analysis["artifact_counts"]
        self.card_vars["Total artifacts"].set(f"{len(self.events):,}")
        for key in ("History","Download","Search","Cookie"): self.card_vars[key].set(f"{counts.get(key,0):,}")
        for item in self.browser_stats.get_children(): self.browser_stats.delete(item)
        for b,n in analysis["browser_counts"].items(): self.browser_stats.insert("","end",values=(b,n))
        lines=[
            f"Profiles produced {len(self.events):,} normalized artifact records.",
            f"Browser databases hashed: {len(self.analyzer.evidence_hashes)}",
            f"Cross-browser URL matches: {len(analysis['correlations'])}",
            f"Potential exact duplicates: {len(analysis['duplicates'])}",
            f"URL review indicators: {len(analysis['suspicious'])}",
            "",
            "Interpretation:",
            "• URL review indicators are heuristic leads, not malware verdicts.",
            "• Cross-browser matches identify URLs observed in multiple browsers; they do not prove common user identity.",
            "• Missing artifacts do not prove that an activity did not occur."
        ]
        self.summary_text.configure(state="normal"); self.summary_text.delete("1.0","end")
        self.summary_text.insert("1.0","\n".join(lines)); self.summary_text.configure(state="disabled")

    def refresh_insights(self):
        a=analyze_events(self.events)
        for tree in (self.suspicious_tree,self.correlation_tree,self.duplicate_tree):
            for item in tree.get_children(): tree.delete(item)
        for r in a["suspicious"]:
            self.suspicious_tree.insert("","end",values=(r["timestamp"],r["browser"],r["url"],r["reasons"]))
        for r in a["correlations"]:
            self.correlation_tree.insert("","end",values=(r["url"],", ".join(r["browsers"]),r["count"],r["first_seen"],r["last_seen"]))
        for r in a["duplicates"]:
            self.duplicate_tree.insert("","end",values=(r.get("browser",""),r.get("artifact_type",""),r.get("title",""),r.get("url",""),r.get("timestamp","")))
        self.error_text.delete("1.0","end")
        self.error_text.insert("1.0","\n".join(self.analyzer.errors) if self.analyzer.errors else "No extraction errors were recorded.")

    def save_csv(self):
        if not self.events:
            messagebox.showinfo("No data","Extract artifacts or load demo evidence first."); return
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile="webforensix_timeline.csv")
        if path:
            export_csv(self.events,path); self._set_status(f"CSV exported: {path}")
            messagebox.showinfo("Export complete","Unified timeline CSV exported successfully.")

    def save_report(self):
        if not self.events:
            messagebox.showinfo("No data","Extract artifacts or load demo evidence first."); return
        path=filedialog.asksaveasfilename(defaultextension=".html",filetypes=[("HTML report","*.html")],initialfile="WebForensix_Investigation_Report.html")
        if path:
            generate_html_report(self.events,path,self.case_name.get(),self.case_id.get(),
                                 self.analyzer.evidence_hashes,self.analyzer.errors)
            self._set_status(f"HTML report generated: {path}")
            messagebox.showinfo("Report complete","Professional HTML report generated. Open it in a browser; use Ctrl+P → Save as PDF for a PDF copy.")

if __name__=="__main__":
    root=tk.Tk()
    AnalyzerApp(root)
    root.mainloop()
