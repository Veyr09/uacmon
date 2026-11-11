"""UAC policy state and consent-prompt observation.

Two separate things live here:

  * The *policy* -- what HKLM\\...\\Policies\\System says should happen when a
    process asks to elevate. Reading this before an elevation lets the monitor
    predict which prompt (consent, credentials, none) the user will get, and
    then record whether that prediction held.

  * The *prompt itself* -- consent.exe. When the AppInfo service accepts an
    elevation request it launches C:\\Windows\\System32\\consent.exe on the
    secure desktop, and consent.exe's first argument is the PID of the process
    that asked. The lifetime of that process is the lifetime of the dialog, so
    watching it start and stop yields the prompt-shown / user-decided pair and
    the latency between them.
"""

import dataclasses
import datetime
import winreg

CONSENT_IMAGE = "consent.exe"
UAC_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# ConsentPromptBehaviorAdmin: what an administrator's filtered token gets.
CONSENT_PROMPT_ADMIN = {
    0: ("Elevate without prompting",
        "elevation is silent -- no prompt will be observed"),
    1: ("Prompt for credentials on the secure desktop",
        "the user must retype a password"),
    2: ("Prompt for consent on the secure desktop",
        "the user clicks Yes/No"),
    3: ("Prompt for credentials", "on the normal desktop"),
    4: ("Prompt for consent", "on the normal desktop"),
    5: ("Prompt for consent for non-Windows binaries",
        "Windows default; signed Windows binaries auto-elevate silently"),
}

# ConsentPromptBehaviorUser: what a standard (non-admin) user gets.
CONSENT_PROMPT_USER = {
    0: ("Automatically deny elevation requests",
        "the request fails outright with no prompt"),
    1: ("Prompt for credentials on the secure desktop",
        "the user must supply administrator credentials"),
    3: ("Prompt for credentials", "on the normal desktop"),
}

# Settings that weaken UAC, matched on the *weak* value rather than on
# "differs from default" -- several of these are weak in one direction only,
# and flagging the shipped default as a finding trains people to ignore the
# tool. Each entry is (value name, weak values, hardened value, consequence).
WEAKENING_CHECKS = (
    ("EnableLUA", (0,), 1,
     "UAC is switched off entirely; every administrator process runs unfiltered"),
    ("PromptOnSecureDesktop", (0,), 1,
     "prompts render on the normal desktop, where other software can see and "
     "drive them with synthetic input"),
    ("ConsentPromptBehaviorAdmin", (0,), 2,
     "administrators elevate with no prompt at all"),
    ("ConsentPromptBehaviorAdmin", (5,), 2,
     "Windows default: signed Windows binaries auto-elevate silently. Normal, "
     "but it is the precondition every auto-elevated-binary bypass depends on"),
    ("FilterAdministratorToken", (0,), 1,
     "the built-in Administrator account is exempt from token filtering"),
    ("LocalAccountTokenFilterPolicy", (1,), 0,
     "local administrators logging on remotely receive unfiltered tokens"),
    ("EnableInstallerDetection", (0,), 1,
     "setup executables are no longer auto-detected and prompted for"),
)


@dataclasses.dataclass
class UacPolicy:
    values: dict
    read_error: str = None

    def get(self, name):
        return self.values.get(name)

    @property
    def enabled(self):
        """EnableLUA absent is treated as on -- that is the shipped default."""
        return self.values.get("EnableLUA", 1) == 1

    def admin_prompt_behaviour(self):
        value = self.values.get("ConsentPromptBehaviorAdmin", 5)
        return CONSENT_PROMPT_ADMIN.get(value, (f"unknown ({value})", ""))

    def user_prompt_behaviour(self):
        value = self.values.get("ConsentPromptBehaviorUser", 3)
        return CONSENT_PROMPT_USER.get(value, (f"unknown ({value})", ""))

    def predict_prompt(self, elevation_type):
        """What the user should see if this process requests elevation now.

        `elevation_type` is TOKEN_ELEVATION_TYPE for the requesting process --
        Limited means an admin with a filtered token, Default usually means a
        standard user.
        """
        if not self.enabled:
            return ("No prompt",
                    "EnableLUA=0: the request is granted or refused with no UAC UI")
        if elevation_type == 3:
            label, detail = self.admin_prompt_behaviour()
            return (label, f"filtered administrator token; {detail}")
        if elevation_type == 2:
            return ("No prompt", "this process already holds a full token")
        label, detail = self.user_prompt_behaviour()
        return (label, f"non-administrator token; {detail}")

    def weakened(self):
        """Settings currently sitting on a weak value, with the consequence.

        Returns (name, actual, hardened value, consequence) tuples. A value
        that is absent from the registry is skipped rather than assumed: the
        effective default varies by Windows edition and domain policy, and
        guessing produces findings nobody can act on.
        """
        findings = []
        for name, weak_values, hardened, consequence in WEAKENING_CHECKS:
            actual = self.values.get(name)
            if actual is not None and actual in weak_values:
                findings.append((name, actual, hardened, consequence))
        return findings


def read_policy():
    """Read the UAC policy values. HKLM read access needs no elevation."""
    values = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UAC_POLICY_KEY) as key:
            index = 0
            while True:
                try:
                    name, value, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                if kind == winreg.REG_DWORD:
                    values[name] = value
                index += 1
    except OSError as exc:
        return UacPolicy(values={}, read_error=str(exc))
    return UacPolicy(values=values)


@dataclasses.dataclass
class ConsentPrompt:
    """One observed UAC dialog."""

    pid: int
    started: datetime.datetime
    requestor_pid: int = None
    requestor_name: str = None
    command_line: str = None
    ended: datetime.datetime = None

    @property
    def duration_seconds(self):
        if self.ended is None:
            return None
        return (self.ended - self.started).total_seconds()

    def describe_requestor(self):
        if self.requestor_pid is None:
            return "requestor unknown (consent.exe runs as SYSTEM; " \
                   "its command line is unreadable from a medium-integrity monitor)"
        name = self.requestor_name or "?"
        return f"requested by {name} (pid {self.requestor_pid})"


def parse_requestor_pid(command_line):
    """consent.exe <requestor pid> <handle> <address> -- pull the first argument.

    Returns None when the command line is unavailable, which is the normal
    outcome unless the monitor itself is elevated.
    """
    if not command_line:
        return None
    parts = command_line.split()
    # Skip the image path, which may itself be quoted and contain spaces.
    if command_line.startswith('"'):
        closing = command_line.find('"', 1)
        parts = command_line[closing + 1:].split() if closing != -1 else []
    else:
        parts = parts[1:]
    for token in parts:
        if token.isdigit():
            return int(token)
    return None


class PromptTracker:
    """Turns consecutive process snapshots into prompt open/close events.

    Kept separate from the general transition engine because a prompt is a
    lifetime, not a state change: it spans two scans at minimum, and the
    interesting datum -- how long the user took to decide -- only exists once
    it closes.
    """

    def __init__(self):
        self.active = {}        # consent.exe pid -> ConsentPrompt
        self.history = []

    def observe(self, snapshot, now):
        """Returns (opened, closed) lists of ConsentPrompt."""
        current = {pid: state for pid, state in snapshot.items()
                   if state.name.lower() == CONSENT_IMAGE}

        opened = []
        for pid, state in current.items():
            if pid in self.active:
                continue
            prompt = ConsentPrompt(
                pid=pid,
                started=state.create_time or now,
                command_line=state.command_line,
                requestor_pid=parse_requestor_pid(state.command_line),
            )
            if prompt.requestor_pid is not None:
                requestor = snapshot.get(prompt.requestor_pid)
                prompt.requestor_name = requestor.name if requestor else None
            self.active[pid] = prompt
            self.history.append(prompt)
            opened.append(prompt)

        closed = []
        for pid in list(self.active):
            if pid not in current:
                prompt = self.active.pop(pid)
                prompt.ended = now
                closed.append(prompt)
        return opened, closed

    def most_recent_within(self, moment, seconds):
        """The prompt that closed most recently before `moment`, if any.

        Used to attribute a newly elevated process to the dialog the user just
        answered; a match is correlation, not proof, and the UI says so.
        """
        best = None
        for prompt in self.history:
            end = prompt.ended or prompt.started
            delta = (moment - end).total_seconds()
            if 0 <= delta <= seconds:
                if best is None or end > (best.ended or best.started):
                    best = prompt
        return best
