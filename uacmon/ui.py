"""Tkinter front end.

Five views over the same data:

  Processes   -- live token state, one row per process
  Transitions -- the change stream from the diff engine
  Elevation   -- the instrumented self-elevation sequence, step by step
  Bypass      -- detection findings for prompt-bypass activity
  UAC policy  -- what the machine's policy says should happen

Threading contract: the collector and the elevation session both run on worker
threads and communicate only through queues. Every Tk call happens on the main
thread, inside the two `after()` pumps at the bottom of this file. Nothing else
touches a widget.
"""

import datetime
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

from . import collector as collector_module
from . import elevate, model, transitions, uac, wintoken

REFRESH_MILLISECONDS = 250
EVENT_HISTORY_LIMIT = 2000

# Row colouring by integrity. High and above are what the eye should catch.
INTEGRITY_COLOURS = {
    "Untrusted": "#777777",
    "Low": "#3b7dd8",
    "Medium": "#202020",
    "Medium Plus": "#202020",
    "High": "#c8500a",
    "System": "#8b1fa9",
    "Protected": "#8b1fa9",
}

SEVERITY_COLOURS = {
    transitions.INFO: "#404040",
    transitions.NOTICE: "#c8500a",
    transitions.ALERT: "#c00000",
}

STATUS_COLOURS = {
    elevate.OK: "#127a2e",
    elevate.WARN: "#c8500a",
    elevate.FAIL: "#c00000",
    elevate.DENIED: "#c00000",
    elevate.SKIP: "#808080",
    elevate.RUNNING: "#0b5fa5",
    elevate.PENDING: "#808080",
}

PROCESS_COLUMNS = (
    ("pid", "PID", 60),
    ("name", "Process", 190),
    ("integrity", "Integrity", 90),
    ("elevated", "Elevated", 70),
    ("etype", "Token type", 90),
    ("privs", "Privs (on/held)", 100),
    ("user", "User", 170),
    ("session", "Sess", 45),
    ("status", "Visibility", 110),
)

EVENT_COLUMNS = (
    ("time", "Time", 80),
    ("severity", "Severity", 70),
    ("kind", "Transition", 200),
    ("process", "Process", 190),
    ("summary", "Detail", 620),
)


class MonitorWindow(tk.Tk):
    def __init__(self, interval=collector_module.DEFAULT_INTERVAL_SECONDS):
        super().__init__()
        self.title("UAC / Token Integrity Monitor")
        self.geometry("1360x820")
        self.minsize(1050, 640)

        self.collector = collector_module.Collector(interval=interval)
        self.elevation_queue = queue.Queue()
        self.elevation_thread = None
        self._printed_lines = {}
        self._events = []
        self._snapshot = {}
        self._filter = tk.StringVar()
        self._filter.trace_add("write", lambda *_: self._render_processes())
        self._only_elevated = tk.BooleanVar(value=False)
        self._min_severity = tk.StringVar(value=transitions.INFO)

        self._build_layout()
        self.collector.start()
        self.after(REFRESH_MILLISECONDS, self._pump_collector)
        self.after(REFRESH_MILLISECONDS, self._pump_elevation)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # --- layout ------------------------------------------------------------
    def _build_layout(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=(6, 0))

        self._build_process_tab()
        self._build_event_tab()
        self._build_elevation_tab()
        self._build_bypass_tab()
        self._build_policy_tab()

        self.status = tk.StringVar(value="starting scanner...")
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Label(bar, textvariable=self.status).pack(side="left")

        elevated = wintoken.current_process_is_elevated()
        note = ("monitor is ELEVATED -- it can read every token, which is not the "
                "view a real attacker's process would have"
                if elevated else
                "monitor is running unelevated -- SYSTEM and other-user tokens "
                "will read as denied, by design")
        ttk.Label(bar, text=note, foreground="#606060").pack(side="right")

    def _build_process_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Processes")

        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=4)
        ttk.Label(controls, text="Filter:").pack(side="left")
        ttk.Entry(controls, textvariable=self._filter, width=32).pack(side="left", padx=4)
        ttk.Checkbutton(controls, text="High integrity and above only",
                        variable=self._only_elevated,
                        command=self._render_processes).pack(side="left", padx=8)
        ttk.Label(controls, text="Interval (s):").pack(side="left", padx=(16, 2))
        self.interval_box = ttk.Combobox(
            controls, width=6, values=("0.5", "1.0", "2.0", "5.0"), state="readonly")
        self.interval_box.set(f"{self.collector.interval:.1f}")
        self.interval_box.bind("<<ComboboxSelected>>", self._on_interval_change)
        self.interval_box.pack(side="left")

        panes = ttk.PanedWindow(frame, orient="vertical")
        panes.pack(fill="both", expand=True)

        self.process_tree = self._make_tree(panes, PROCESS_COLUMNS)
        self.process_tree.bind("<<TreeviewSelect>>", self._on_process_selected)
        panes.add(self.process_tree, weight=3)

        self.process_detail = scrolledtext.ScrolledText(
            panes, height=12, wrap="word", font=("Consolas", 9))
        self.process_detail.configure(state="disabled")
        panes.add(self.process_detail, weight=2)

        for label, colour in INTEGRITY_COLOURS.items():
            self.process_tree.tag_configure(label, foreground=colour)
        self.process_tree.tag_configure("denied", foreground="#909090")

    def _build_event_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Transitions")

        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=4)
        ttk.Label(controls, text="Minimum severity:").pack(side="left")
        for level in (transitions.INFO, transitions.NOTICE, transitions.ALERT):
            ttk.Radiobutton(controls, text=level, value=level,
                            variable=self._min_severity,
                            command=self._render_events).pack(side="left", padx=4)
        ttk.Button(controls, text="Clear",
                   command=self._clear_events).pack(side="right")

        panes = ttk.PanedWindow(frame, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.event_tree = self._make_tree(panes, EVENT_COLUMNS)
        self.event_tree.bind("<<TreeviewSelect>>", self._on_event_selected)
        panes.add(self.event_tree, weight=3)
        self.event_detail = scrolledtext.ScrolledText(
            panes, height=8, wrap="word", font=("Consolas", 9))
        self.event_detail.configure(state="disabled")
        panes.add(self.event_detail, weight=1)

        for level, colour in SEVERITY_COLOURS.items():
            self.event_tree.tag_configure(level, foreground=colour)

    def _build_elevation_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Elevation")

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=6)
        self.elevate_button = ttk.Button(
            header, text="Request elevation  (raises the real UAC prompt)",
            command=self._start_elevation)
        self.elevate_button.pack(side="left")
        ttk.Button(header, text="Preview linked token  (no prompt)",
                   command=self._preview_linked_token).pack(side="left", padx=6)
        ttk.Button(header, text="Clear log",
                   command=self._clear_elevation_log).pack(side="right")

        ttk.Label(
            frame,
            text=("Elevation is requested through ShellExecuteEx(\"runas\"), the "
                  "supported path: the AppInfo service raises the consent dialog "
                  "and the user must approve it. Every stage below is timestamped "
                  "as it happens."),
            foreground="#606060", wraplength=1280, justify="left").pack(
                fill="x", padx=2, pady=(0, 6))

        body = ttk.PanedWindow(frame, orient="horizontal")
        body.pack(fill="both", expand=True)

        step_frame = ttk.Frame(body)
        self.step_tree = ttk.Treeview(
            step_frame, columns=("status",), show="tree headings", height=14)
        self.step_tree.heading("#0", text="Stage")
        self.step_tree.heading("status", text="Status")
        self.step_tree.column("#0", width=250)
        self.step_tree.column("status", width=90, anchor="center")
        self.step_tree.pack(fill="both", expand=True)
        for status, colour in STATUS_COLOURS.items():
            self.step_tree.tag_configure(status, foreground=colour)
        body.add(step_frame, weight=1)

        self.elevation_log = scrolledtext.ScrolledText(
            body, wrap="word", font=("Consolas", 9))
        self.elevation_log.configure(state="disabled")
        for status, colour in STATUS_COLOURS.items():
            self.elevation_log.tag_configure(status, foreground=colour)
        self.elevation_log.tag_configure("header", font=("Consolas", 9, "bold"))
        self.elevation_log.tag_configure("body", foreground="#303030")
        body.add(self.elevation_log, weight=3)

        self._reset_step_tree()

    def _build_bypass_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Bypass watch")
        ttk.Label(
            frame,
            text=("Detection only. Flags the per-user registry keys that "
                  "prompt-bypass techniques must create, auto-elevating binaries "
                  "spawning children, and elevated processes with no consent "
                  "prompt observed near their creation."),
            foreground="#606060", wraplength=1280, justify="left").pack(
                fill="x", padx=2, pady=6)

        panes = ttk.PanedWindow(frame, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.bypass_tree = self._make_tree(panes, (
            ("severity", "Severity", 80),
            ("title", "Finding", 560),
            ("evidence", "Evidence", 620),
        ))
        self.bypass_tree.bind("<<TreeviewSelect>>", self._on_bypass_selected)
        panes.add(self.bypass_tree, weight=3)
        self.bypass_detail = scrolledtext.ScrolledText(
            panes, height=8, wrap="word", font=("Consolas", 9))
        self.bypass_detail.configure(state="disabled")
        panes.add(self.bypass_detail, weight=1)
        for level, colour in (("alert", "#c00000"), ("notice", "#c8500a"),
                              ("info", "#404040")):
            self.bypass_tree.tag_configure(level, foreground=colour)
        self._bypass_findings = []

    def _build_policy_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="UAC policy")
        self.policy_text = scrolledtext.ScrolledText(
            frame, wrap="word", font=("Consolas", 9))
        self.policy_text.pack(fill="both", expand=True, pady=6)
        self._render_policy()

    def _make_tree(self, parent, columns):
        tree = ttk.Treeview(parent, columns=[c[0] for c in columns],
                            show="headings", selectmode="browse")
        for key, heading, width in columns:
            tree.heading(key, text=heading,
                         command=lambda k=key, t=None: None)
            tree.column(key, width=width, anchor="w", stretch=False)
        return tree

    # --- collector pump ----------------------------------------------------
    def _pump_collector(self):
        latest = None
        try:
            while True:
                latest = self.collector.results.get_nowait()
                if latest.error:
                    self.status.set(f"scan error: {latest.error}")
                    continue
                self._events.extend(latest.events)
        except queue.Empty:
            pass

        if latest is not None and not latest.error:
            self._snapshot = latest.snapshot
            self._bypass_findings = latest.bypass_findings
            if len(self._events) > EVENT_HISTORY_LIMIT:
                del self._events[:len(self._events) - EVENT_HISTORY_LIMIT]
            self._render_processes()
            self._render_events()
            self._render_bypass()
            self.status.set(
                f"{latest.timestamp.strftime('%H:%M:%S')}  "
                f"{len(latest.snapshot)} processes  |  "
                f"{latest.readable_count} tokens readable, "
                f"{latest.denied_count} denied  |  "
                f"scan {latest.duration_ms:.0f} ms  |  "
                f"{len(self._events)} transitions recorded")

        self.after(REFRESH_MILLISECONDS, self._pump_collector)

    # --- rendering ---------------------------------------------------------
    def _render_processes(self):
        needle = self._filter.get().lower().strip()
        selected = self.process_tree.selection()
        keep = selected[0] if selected else None

        self.process_tree.delete(*self.process_tree.get_children())
        for pid in sorted(self._snapshot):
            state = self._snapshot[pid]
            if self._only_elevated and (state.integrity_rid or 0) < 0x3000:
                continue
            if needle and needle not in state.name.lower() and needle not in str(pid):
                continue

            enabled = len(state.enabled_privileges())
            values = (
                pid,
                state.name,
                state.integrity_label,
                "yes" if state.elevated else ("no" if state.elevated is not None else "?"),
                state.elevation_label,
                f"{enabled}/{len(state.privileges)}" if state.readable else "-",
                state.display_user,
                state.session_id if state.session_id is not None else "-",
                state.error or "readable",
            )
            tag = "denied" if not state.readable else state.integrity_label
            self.process_tree.insert("", "end", iid=str(pid), values=values, tags=(tag,))

        if keep and self.process_tree.exists(keep):
            self.process_tree.selection_set(keep)

    def _on_process_selected(self, _event=None):
        selection = self.process_tree.selection()
        if not selection:
            return
        state = self._snapshot.get(int(selection[0]))
        if state is None:
            return

        lines = [
            f"{state.name}  (pid {state.pid}, parent {state.ppid})",
            f"image        {state.image_path or '-'}",
            f"command line {state.command_line or '- (needs an elevated monitor)'}",
            f"user         {state.display_user}",
            f"sid          {state.sid or '-'}",
            f"session      {state.session_id}",
            f"started      {state.create_time.strftime('%Y-%m-%d %H:%M:%S') if state.create_time else '-'}",
            "",
            f"integrity        {state.integrity_label}"
            + (f"  (0x{state.integrity_rid:04X})" if state.integrity_rid is not None else ""),
            f"TokenIsElevated  {state.elevated}",
            f"elevation type   {state.elevation_label}",
            f"virtualization   {state.virtualized}",
            f"UIAccess         {state.ui_access}",
        ]
        if state.error:
            lines += ["", f"token not readable: {state.error}",
                      "An unreadable token is the expected result for SYSTEM, "
                      "protected, and other-user processes when the monitor is "
                      "not elevated."]
        else:
            lines += ["", f"privileges ({len(state.privileges)}):"]
            for name in sorted(state.privileges):
                attrs = state.privileges[name]
                marker = "*" if name in model.DANGEROUS_PRIVILEGES else " "
                lines.append(f"  {marker} {name:<34} "
                             f"{model.describe_privilege_attributes(attrs)}")
            dangerous = state.dangerous_enabled()
            if dangerous:
                lines += ["", "high-value privileges currently ENABLED:"]
                for name in sorted(dangerous):
                    lines.append(f"  {name}: {model.DANGEROUS_PRIVILEGES[name]}")
        self._set_text(self.process_detail, "\n".join(lines))

    def _render_events(self):
        minimum = transitions.SEVERITY_ORDER[self._min_severity.get()]
        self.event_tree.delete(*self.event_tree.get_children())
        for index, event in enumerate(self._events):
            if transitions.SEVERITY_ORDER[event.severity] < minimum:
                continue
            self.event_tree.insert(
                "", "end", iid=str(index),
                values=(event.timestamp.strftime("%H:%M:%S"), event.severity,
                        event.kind, f"{event.name} ({event.pid})", event.summary),
                tags=(event.severity,))
        children = self.event_tree.get_children()
        if children:
            self.event_tree.see(children[-1])

    def _on_event_selected(self, _event=None):
        selection = self.event_tree.selection()
        if not selection:
            return
        event = self._events[int(selection[0])]
        text = [event.format_line()]
        if event.related_pid:
            text.append(f"related pid: {event.related_pid}")
        if event.detail:
            text += ["", event.detail]
        self._set_text(self.event_detail, "\n".join(text))

    def _clear_events(self):
        self._events.clear()
        self._render_events()

    def _render_bypass(self):
        self.bypass_tree.delete(*self.bypass_tree.get_children())
        for index, finding in enumerate(self._bypass_findings):
            self.bypass_tree.insert(
                "", "end", iid=str(index),
                values=(finding.severity, finding.title, finding.evidence),
                tags=(finding.severity,))

    def _on_bypass_selected(self, _event=None):
        selection = self.bypass_tree.selection()
        if not selection:
            return
        finding = self._bypass_findings[int(selection[0])]
        body = [finding.title, "", finding.detail]
        if finding.evidence:
            body += ["", f"evidence: {finding.evidence}"]
        self._set_text(self.bypass_detail, "\n".join(body))

    def _render_policy(self):
        policy = uac.read_policy()
        lines = ["UAC policy  (HKLM\\" + uac.UAC_POLICY_KEY + ")", ""]
        if policy.read_error:
            lines.append(f"could not be read: {policy.read_error}")
        else:
            for name in sorted(policy.values):
                lines.append(f"  {name:<34} {policy.values[name]}")
            admin_label, admin_why = policy.admin_prompt_behaviour()
            user_label, user_why = policy.user_prompt_behaviour()
            lines += [
                "", f"administrators: {admin_label}", f"  {admin_why}",
                "", f"standard users: {user_label}", f"  {user_why}",
            ]
            weakened = policy.weakened()
            lines += ["", "deviations from the hardened baseline:"]
            if weakened:
                for name, actual, expected, consequence in weakened:
                    lines.append(f"  {name}={actual} (expected {expected}) -- {consequence}")
            else:
                lines.append("  none")
        self.policy_text.configure(state="normal")
        self.policy_text.delete("1.0", "end")
        self.policy_text.insert("1.0", "\n".join(lines))
        self.policy_text.configure(state="disabled")

    # --- elevation ---------------------------------------------------------
    def _reset_step_tree(self):
        self.step_tree.delete(*self.step_tree.get_children())
        for key, title in elevate.STEP_TITLES:
            self.step_tree.insert("", "end", iid=key, text=title,
                                  values=(elevate.PENDING,),
                                  tags=(elevate.PENDING,))

    def _start_elevation(self):
        if self.elevation_thread and self.elevation_thread.is_alive():
            return
        self.elevate_button.configure(state="disabled")
        self._printed_lines.clear()
        self._reset_step_tree()
        self._append_elevation_line(
            f"=== elevation sequence started "
            f"{datetime.datetime.now().strftime('%H:%M:%S')} ===", "header")

        session = elevate.ElevationSession(
            on_step=self.elevation_queue.put,
            prompt_lookup=self.collector.prompts_since)

        def worker():
            try:
                session.run()
            finally:
                self.elevation_queue.put(None)      # sentinel: re-enable button

        self.elevation_thread = threading.Thread(
            target=worker, name="uacmon-elevation", daemon=True)
        self.elevation_thread.start()

    def _preview_linked_token(self):
        """The read-only half, on its own: no prompt, nothing elevated."""
        self._append_elevation_line(
            f"=== linked-token preview "
            f"{datetime.datetime.now().strftime('%H:%M:%S')} ===", "header")
        own = wintoken.probe_current_process()
        linked = wintoken.read_linked_token()
        if linked is None:
            self._append_elevation_line(
                "  no linked token -- this account has no elevated counterpart "
                "held in reserve.", elevate.WARN)
            return
        preview = model.state_from_token_probe(linked, "linked token",
                                               datetime.datetime.now())
        gained, _, enabled, _ = model.diff_privileges(own.privileges,
                                                      preview.privileges)
        self._append_elevation_line(
            f"  integrity {model.integrity_name(own.integrity_rid)} -> "
            f"{preview.integrity_label};  {len(gained)} privileges would be gained",
            elevate.OK)
        for name in sorted(gained):
            note = model.DANGEROUS_PRIVILEGES.get(name, "")
            self._append_elevation_line(
                f"    + {name}" + (f"  <- {note}" if note else ""), "body")
        if enabled:
            self._append_elevation_line(
                f"    already held, would become enabled: {', '.join(sorted(enabled))}",
                "body")

    def _pump_elevation(self):
        try:
            while True:
                step = self.elevation_queue.get_nowait()
                if step is None:
                    self.elevate_button.configure(state="normal")
                    self._append_elevation_line("=== sequence complete ===", "header")
                    continue
                self._render_step(step)
        except queue.Empty:
            pass
        self.after(REFRESH_MILLISECONDS, self._pump_elevation)

    def _render_step(self, step):
        """Write a step incrementally: header once, then each new line as it lands."""
        if self.step_tree.exists(step.key):
            self.step_tree.item(step.key, values=(step.status,), tags=(step.status,))
            self.step_tree.see(step.key)

        printed = self._printed_lines.get(step.key)
        if printed is None:
            stamp = (step.started or datetime.datetime.now()).strftime("%H:%M:%S")
            self._append_elevation_line(
                f"[{stamp}] {step.key} -- {step.title}", "header")
            printed = 0

        for line in step.lines[printed:]:
            self._append_elevation_line(f"        {line}", "body")
        self._printed_lines[step.key] = len(step.lines)

        if step.status not in (elevate.PENDING, elevate.RUNNING):
            self._append_elevation_line(
                f"        -> {step.status.upper()}", step.status)
            self._append_elevation_line("", "body")

    def _append_elevation_line(self, text, tag):
        self.elevation_log.configure(state="normal")
        self.elevation_log.insert("end", text + "\n", tag)
        self.elevation_log.see("end")
        self.elevation_log.configure(state="disabled")

    def _clear_elevation_log(self):
        self.elevation_log.configure(state="normal")
        self.elevation_log.delete("1.0", "end")
        self.elevation_log.configure(state="disabled")
        self._printed_lines.clear()
        self._reset_step_tree()

    # --- misc --------------------------------------------------------------
    def _on_interval_change(self, _event=None):
        self.collector.set_interval(float(self.interval_box.get()))

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _on_close(self):
        self.collector.stop()
        self.destroy()


def run(interval=collector_module.DEFAULT_INTERVAL_SECONDS):
    MonitorWindow(interval=interval).mainloop()
