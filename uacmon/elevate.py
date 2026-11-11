"""Self-elevation over the supported path, instrumented end to end.

The monitor needs a way to *generate* a UAC event on demand -- otherwise you
are stuck waiting for the machine to produce one before you can tell whether
the prompt tracker works. This module does that the way Windows intends:

    ShellExecuteExW(lpVerb="runas")

which hands the request to the AppInfo service, which raises the real consent
dialog on the secure desktop. The user must approve it. There is no bypass
here and none is wanted: the point of the exercise is to observe the sanctioned
sequence closely enough to recognise an unsanctioned one by contrast.

What the elevated child does is deliberately minimal -- it re-runs this same
package with --token-report, writes a JSON description of the token it was
given, and exits. Nothing persistent, nothing installed, no second UI.

The sequence, each step timestamped and recorded for the UI log:

    1  PRECHECK_TOKEN              what we hold right now
    2  LINKED_TOKEN_PREVIEW        what elevation would grant (no prompt)
    3  POLICY_PREDICTION           which prompt the policy says we should get
    4  REPORT_CHANNEL              temp file the child will write to
    5  INVOKE_RUNAS                ShellExecuteExW issued
    6  PROMPT_TRIGGER              did consent.exe actually appear?
    7  USER_DECISION               approved, or cancelled (ERROR_CANCELLED)
    8  CHILD_PROCESS               pid, image, creation time
    9  TOKEN_VERIFICATION_SELF     the child's own report of its token
   10  TOKEN_VERIFICATION_EXTERNAL what this unelevated monitor can see of it
   11  PRIVILEGE_DELTA             before/after diff
   12  EXECUTION_RESULT            exit code and verdict
"""

import ctypes
import ctypes.wintypes as wt
import dataclasses
import datetime
import json
import os
import sys
import tempfile

from . import model, uac, wintoken

shell32 = ctypes.WinDLL("shell32", use_last_error=True)
ole32 = ctypes.WinDLL("ole32", use_last_error=True)
kernel32 = wintoken.kernel32

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_HIDE = 0

ERROR_CANCELLED = 1223           # the user clicked No / closed the dialog
ERROR_ELEVATION_REQUIRED = 740

COINIT_APARTMENTTHREADED = 0x2
RPC_E_CHANGED_MODE = 0x80010106

CHILD_WAIT_MILLISECONDS = 30_000
WAIT_TIMEOUT = 0x00000102

# Statuses a step can end in.
PENDING, RUNNING, OK, WARN, FAIL, DENIED, SKIP = (
    "pending", "running", "ok", "warn", "failed", "denied", "skipped")


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wt.HWND),
        ("lpVerb", wt.LPCWSTR),
        ("lpFile", wt.LPCWSTR),
        ("lpParameters", wt.LPCWSTR),
        ("lpDirectory", wt.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wt.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wt.LPCWSTR),
        ("hkeyClass", wt.HKEY),
        ("dwHotKey", wt.DWORD),
        ("hIconOrMonitor", wt.HANDLE),
        ("hProcess", wt.HANDLE),
    ]


shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
shell32.ShellExecuteExW.restype = wt.BOOL
kernel32.GetProcessId.argtypes = [wt.HANDLE]
kernel32.GetProcessId.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, wt.LPDWORD]
kernel32.GetExitCodeProcess.restype = wt.BOOL


@dataclasses.dataclass
class Step:
    key: str
    title: str
    status: str = PENDING
    started: datetime.datetime = None
    finished: datetime.datetime = None
    lines: list = dataclasses.field(default_factory=list)

    def say(self, text):
        self.lines.append(text)

    def close(self, status):
        self.status = status
        self.finished = datetime.datetime.now()

    def format_block(self):
        stamp = (self.finished or self.started or datetime.datetime.now())
        head = f"[{stamp.strftime('%H:%M:%S')}] {self.key:<28} {self.status.upper()}"
        body = "\n".join(f"        {line}" for line in self.lines)
        return f"{head}\n{body}" if body else head


STEP_TITLES = (
    ("PRECHECK_TOKEN", "Read the token this process currently holds"),
    ("LINKED_TOKEN_PREVIEW", "Inspect the linked full token, without elevating"),
    ("POLICY_PREDICTION", "Predict the prompt from UAC policy"),
    ("REPORT_CHANNEL", "Prepare the channel the elevated child reports through"),
    ("INVOKE_RUNAS", "Issue ShellExecuteExW with the runas verb"),
    ("PROMPT_TRIGGER", "Confirm consent.exe was raised"),
    ("USER_DECISION", "Record the user's answer to the prompt"),
    ("CHILD_PROCESS", "Identify the process the service created"),
    ("TOKEN_VERIFICATION_SELF", "Verify the granted token from inside the child"),
    ("TOKEN_VERIFICATION_EXTERNAL", "Verify it again from this unelevated monitor"),
    ("PRIVILEGE_DELTA", "Diff the before and after privilege sets"),
    ("EXECUTION_RESULT", "Final result"),
)


class ElevationSession:
    """Runs the sequence above, publishing each step as it completes.

    `on_step(step)` is called on the worker thread every time a step changes
    state; the UI marshals it back onto the Tk thread. `prompt_lookup(since)`
    returns consent prompts observed by the collector at or after `since`, or
    None when no collector is running (console mode).
    """

    def __init__(self, on_step=None, prompt_lookup=None, report_dir=None):
        self.on_step = on_step or (lambda step: None)
        self.prompt_lookup = prompt_lookup
        self.report_dir = report_dir or tempfile.gettempdir()
        self.steps = [Step(key, title) for key, title in STEP_TITLES]
        self._by_key = {step.key: step for step in self.steps}
        self.before = None
        self.after = None
        self.succeeded = False

    def _begin(self, key):
        step = self._by_key[key]
        step.status = RUNNING
        step.started = datetime.datetime.now()
        self.on_step(step)
        return step

    def _end(self, step, status):
        step.close(status)
        self.on_step(step)
        return step

    def run(self):
        """Execute the whole sequence. Safe to call on a worker thread."""
        # ShellExecuteExW is a shell API; give the thread an apartment.
        result = ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
        try:
            self._run()
        finally:
            if result != RPC_E_CHANGED_MODE:
                ole32.CoUninitialize()
        return self.succeeded

    def _run(self):
        if not self._step_precheck():
            return
        self._step_linked_preview()
        self._step_policy()
        report_path = self._step_report_channel()
        if report_path is None:
            return

        handle, invoked_at, error_code = self._step_invoke(report_path)
        self._step_prompt_trigger(invoked_at)

        if handle is None:
            self._step_decision_failed(error_code)
            self._skip_remaining()
            return

        self._step_decision_granted()
        child_pid = self._step_child_process(handle)
        exit_code = self._wait_for_child(handle)
        self._step_verify_self(report_path)
        self._step_verify_external(child_pid)
        self._step_delta()
        self._step_result(exit_code)

    # --- steps -------------------------------------------------------------
    def _step_precheck(self):
        step = self._begin("PRECHECK_TOKEN")
        probe = wintoken.probe_current_process()
        if probe.error:
            step.say(f"could not read own token: {probe.error}")
            self._end(step, FAIL)
            return False

        self.before = model.state_from_token_probe(
            probe, os.path.basename(sys.executable), datetime.datetime.now())
        step.say(f"pid                {os.getpid()}")
        step.say(f"user               {self.before.display_user}")
        step.say(f"integrity          {self.before.integrity_label} "
                 f"(0x{self.before.integrity_rid:04X})"
                 if self.before.integrity_rid is not None else "integrity unknown")
        step.say(f"TokenIsElevated    {self.before.elevated}")
        step.say(f"elevation type     {self.before.elevation_label}")
        step.say(f"privileges held    {len(self.before.privileges)} "
                 f"({len(self.before.enabled_privileges())} enabled)")
        dangerous = self.before.dangerous_enabled()
        step.say(f"high-value enabled {', '.join(sorted(dangerous)) if dangerous else 'none'}")

        if self.before.elevated:
            step.say("already elevated -- the runas verb would be a no-op; "
                     "run this from a standard session to see the full sequence")
            self._end(step, WARN)
            return True
        self._end(step, OK)
        return True

    def _step_linked_preview(self):
        """The read-only half of the answer: what elevation *would* grant."""
        step = self._begin("LINKED_TOKEN_PREVIEW")
        linked = wintoken.read_linked_token()
        if linked is None:
            step.say("no linked token")
            step.say("This account's token has no elevated counterpart in reserve: "
                     "either it is a genuine standard user (elevation will require "
                     "another account's credentials) or UAC filtering is off.")
            self._end(step, WARN)
            return

        preview = model.state_from_token_probe(
            linked, "linked token", datetime.datetime.now())
        step.say(f"integrity          {preview.integrity_label}")
        step.say(f"TokenIsElevated    {preview.elevated}")
        step.say(f"elevation type     {preview.elevation_label}")
        gained, _, enabled, _ = model.diff_privileges(
            self.before.privileges if self.before else {}, preview.privileges)
        step.say(f"privileges gained  {len(gained)}")
        for name in sorted(gained):
            note = model.DANGEROUS_PRIVILEGES.get(name)
            step.say(f"  + {name}" + (f"  <- {note}" if note else ""))
        if enabled:
            step.say(f"already-held privileges that become enabled: "
                     f"{', '.join(sorted(enabled))}")
        step.say("Read via GetTokenInformation(TokenLinkedToken). No prompt was "
                 "raised and nothing was elevated to obtain this.")
        self._end(step, OK)

    def _step_policy(self):
        step = self._begin("POLICY_PREDICTION")
        policy = uac.read_policy()
        if policy.read_error:
            step.say(f"policy unreadable: {policy.read_error}")
            self._end(step, WARN)
            return
        label, why = policy.predict_prompt(
            self.before.elevation_type if self.before else None)
        step.say(f"EnableLUA                  {policy.get('EnableLUA')}")
        step.say(f"ConsentPromptBehaviorAdmin {policy.get('ConsentPromptBehaviorAdmin')}")
        step.say(f"ConsentPromptBehaviorUser  {policy.get('ConsentPromptBehaviorUser')}")
        step.say(f"PromptOnSecureDesktop      {policy.get('PromptOnSecureDesktop')}")
        step.say(f"expected prompt            {label}")
        step.say(f"  {why}")
        weakened = policy.weakened()
        if weakened:
            step.say("policy deviations that weaken UAC:")
            for name, actual, expected, consequence in weakened:
                step.say(f"  {name}={actual} (hardened: {expected}) -- {consequence}")
            self._end(step, WARN)
            return
        self._end(step, OK)

    def _step_report_channel(self):
        step = self._begin("REPORT_CHANNEL")
        try:
            handle, path = tempfile.mkstemp(
                prefix="uacmon-token-", suffix=".json", dir=self.report_dir)
            os.close(handle)
        except OSError as exc:
            step.say(f"could not create report file: {exc}")
            self._end(step, FAIL)
            return None
        step.say(f"report path {path}")
        step.say("The elevated child writes its own token description here and "
                 "exits. It is the only thing the child does.")
        self._end(step, OK)
        return path

    def _step_invoke(self, report_path):
        step = self._begin("INVOKE_RUNAS")
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        parameters = f'-m uacmon --token-report "{report_path}"'

        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
        info.lpVerb = "runas"
        info.lpFile = sys.executable
        info.lpParameters = parameters
        info.lpDirectory = package_root
        info.nShow = SW_HIDE

        step.say(f"verb        runas")
        step.say(f"file        {sys.executable}")
        step.say(f"parameters  {parameters}")
        step.say(f"directory   {package_root}")
        step.say("Control now passes to the AppInfo service, which decides "
                 "whether to raise a prompt. This call blocks until the user "
                 "answers it.")
        self.on_step(step)

        invoked_at = datetime.datetime.now()
        ok = shell32.ShellExecuteExW(ctypes.byref(info))
        error_code = ctypes.get_last_error()

        if not ok or not info.hProcess:
            step.say(f"ShellExecuteExW returned failure (GetLastError={error_code})")
            self._end(step, FAIL if error_code != ERROR_CANCELLED else DENIED)
            return None, invoked_at, error_code

        step.say("ShellExecuteExW succeeded; a process handle was returned")
        self._end(step, OK)
        return info.hProcess, invoked_at, 0

    def _step_prompt_trigger(self, invoked_at):
        """Did the dialog we predicted actually get raised?

        Checked after the fact: ShellExecuteExW blocks while the prompt is up,
        so the observation is made by the collector thread and read back here.
        """
        step = self._begin("PROMPT_TRIGGER")
        if self.prompt_lookup is None:
            step.say("no collector attached; consent.exe observation unavailable "
                     "(run the GUI, or --console, to have the scanner watching)")
            self._end(step, SKIP)
            return

        prompts = self.prompt_lookup(invoked_at)
        if not prompts:
            step.say("consent.exe was NOT observed between the request and the answer")
            step.say("Either the policy elevates silently, or the dialog opened and "
                     "closed inside one scan interval. Both are normal; a repeatable "
                     "absence with ConsentPromptBehaviorAdmin=2 would not be.")
            self._end(step, WARN)
            return

        for prompt in prompts:
            step.say(f"consent.exe pid {prompt.pid} shown at "
                     f"{prompt.started.strftime('%H:%M:%S')}")
            step.say(f"  {prompt.describe_requestor()}")
            if prompt.duration_seconds is not None:
                step.say(f"  dialog was up for {prompt.duration_seconds:.1f}s "
                         f"(user decision latency)")
        self._end(step, OK)

    def _step_decision_granted(self):
        step = self._begin("USER_DECISION")
        step.say("approved -- the service returned a process handle, which it "
                 "only does once consent is given")
        self._end(step, OK)

    def _step_decision_failed(self, error_code):
        step = self._begin("USER_DECISION")
        if error_code == ERROR_CANCELLED:
            step.say("denied -- ERROR_CANCELLED (1223)")
            step.say("The user dismissed the dialog, or a standard user supplied "
                     "no valid administrator credentials. This process keeps the "
                     "token it started with; nothing changed.")
            self._end(step, DENIED)
        else:
            step.say(f"elevation failed with GetLastError={error_code}")
            self._end(step, FAIL)

    def _step_child_process(self, handle):
        step = self._begin("CHILD_PROCESS")
        child_pid = kernel32.GetProcessId(handle)
        if not child_pid:
            step.say("could not resolve the child pid from the returned handle")
            self._end(step, WARN)
            return None
        step.say(f"pid {child_pid}")
        probe = wintoken.probe_process(child_pid)
        if probe.image_path:
            step.say(f"image {probe.image_path}")
        if probe.create_time:
            step.say(f"created {probe.create_time.strftime('%H:%M:%S.%f')[:-3]}")
        step.say("Created by svchost.exe (AppInfo), not by this process -- an "
                 "elevated child is not a child in the process-tree sense, which "
                 "is why parent-based attribution needs the prompt correlation.")
        self._end(step, OK)
        return child_pid

    def _wait_for_child(self, handle):
        waited = kernel32.WaitForSingleObject(handle, CHILD_WAIT_MILLISECONDS)
        exit_code = wt.DWORD(0)
        if waited == WAIT_TIMEOUT:
            return None
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return None
        kernel32.CloseHandle(handle)
        return exit_code.value

    def _step_verify_self(self, report_path):
        """Authoritative reading: taken from inside the elevated process."""
        step = self._begin("TOKEN_VERIFICATION_SELF")
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, ValueError) as exc:
            step.say(f"no usable report at {report_path}: {exc}")
            step.say("The child may have been blocked or died before writing.")
            self._end(step, FAIL)
            return
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        self.after = model.ProcessState(
            pid=report.get("pid", 0),
            ppid=0,
            name=os.path.basename(report.get("image") or "elevated child"),
            image_path=report.get("image"),
            integrity_rid=report.get("integrity_rid"),
            elevated=report.get("elevated"),
            elevation_type=report.get("elevation_type"),
            user=report.get("user"),
            sid=report.get("sid"),
            privileges=report.get("privileges", {}),
        )
        step.say(f"pid                {self.after.pid}")
        step.say(f"user               {self.after.display_user}")
        step.say(f"integrity          {self.after.integrity_label}")
        step.say(f"TokenIsElevated    {self.after.elevated}")
        step.say(f"elevation type     {self.after.elevation_label}")
        step.say(f"privileges held    {len(self.after.privileges)} "
                 f"({len(self.after.enabled_privileges())} enabled)")
        self.succeeded = bool(self.after.elevated)
        self._end(step, OK if self.succeeded else WARN)

    def _step_verify_external(self, child_pid):
        """The same question asked from outside, by an unelevated observer.

        This step usually fails, and that failure is the useful result: it is a
        direct measurement of the monitor's own blind spot.
        """
        step = self._begin("TOKEN_VERIFICATION_EXTERNAL")
        if child_pid is None:
            step.say("no child pid to probe")
            self._end(step, SKIP)
            return
        probe = wintoken.probe_process(child_pid)
        if probe.error:
            step.say(f"probe failed: {probe.error}")
            step.say("Expected when the monitor is medium-integrity and the child "
                     "is high: the token is readable from inside and opaque from "
                     "outside. Every row this tool shows as 'access denied' is "
                     "this same boundary.")
            self._end(step, WARN)
            return
        step.say(f"integrity       {model.integrity_name(probe.integrity_rid)}")
        step.say(f"TokenIsElevated {probe.elevated}")
        step.say(f"privileges      {len(probe.privileges)} visible")
        step.say("The external view agreed with the child's self-report."
                 if probe.elevated == (self.after.elevated if self.after else None)
                 else "External and self-reported views disagree -- worth a look.")
        self._end(step, OK)

    def _step_delta(self):
        step = self._begin("PRIVILEGE_DELTA")
        if self.before is None or self.after is None:
            step.say("missing one side of the comparison")
            self._end(step, SKIP)
            return
        gained, lost, enabled, disabled = model.diff_privileges(
            self.before.privileges, self.after.privileges)
        step.say(f"integrity  {self.before.integrity_label} -> {self.after.integrity_label}")
        step.say(f"elevated   {self.before.elevated} -> {self.after.elevated}")
        step.say(f"type       {self.before.elevation_label} -> {self.after.elevation_label}")
        step.say(f"privileges {len(self.before.privileges)} -> {len(self.after.privileges)}")
        for name in sorted(gained):
            note = model.DANGEROUS_PRIVILEGES.get(name)
            step.say(f"  + {name}" + (f"  <- {note}" if note else ""))
        for name in sorted(lost):
            step.say(f"  - {name}")
        for name in sorted(enabled):
            step.say(f"  ~ {name} became enabled")
        for name in sorted(disabled):
            step.say(f"  ~ {name} became disabled")
        self._end(step, OK)

    def _step_result(self, exit_code):
        step = self._begin("EXECUTION_RESULT")
        if exit_code is None:
            step.say("child did not exit within the wait window")
            self._end(step, WARN)
            return
        step.say(f"child exit code {exit_code}")
        if self.succeeded:
            step.say("Elevation granted and verified: a full administrator token "
                     "was issued through the consent path and confirmed by "
                     "reading it back.")
            self._end(step, OK)
        else:
            step.say("The child ran but did not report an elevated token.")
            self._end(step, WARN)

    def _skip_remaining(self):
        for step in self.steps:
            if step.status == PENDING:
                step.status = SKIP
                step.finished = datetime.datetime.now()
                self.on_step(step)


def write_token_report(path):
    """Child-mode entry point: describe our own token as JSON, then exit.

    Runs inside the elevated process. It reads its own token and writes the
    result -- it does not adjust anything, start anything, or persist.
    """
    probe = wintoken.probe_current_process()
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "pid": os.getpid(),
        "image": probe.image_path,
        "command_line": probe.command_line,
        "session_id": probe.session_id,
        "integrity_rid": probe.integrity_rid,
        "integrity": model.integrity_name(probe.integrity_rid),
        "elevated": probe.elevated,
        "elevation_type": probe.elevation_type,
        "virtualized": probe.virtualized,
        "ui_access": probe.ui_access,
        "user": probe.user,
        "sid": probe.sid,
        "privileges": probe.privileges,
        "error": probe.error,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    return report
