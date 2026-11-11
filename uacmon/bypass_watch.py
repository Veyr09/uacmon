"""Detection of UAC-bypass activity. Detection only -- nothing here performs one.

The techniques in MITRE T1548.002 all share a shape: get code to run inside a
process that Windows auto-elevates without prompting. The two common vehicles
are a per-user registry hijack (point a file-association or protocol handler at
your own command line, then start the auto-elevating binary that consults it)
and an elevated COM object reached through a moniker. Both leave the same two
traces, and this module looks for those traces:

  1. Registry keys under HKCU that do not exist on a clean machine. Every entry
     in HIJACK_POINTS is absent by default; its mere presence is the signal,
     and a DelegateExecute value alongside it is close to conclusive.

  2. A process running at high integrity with no consent.exe observed anywhere
     near its creation. That is what "bypassed the prompt" looks like from the
     outside. The transition engine raises UNPROMPTED_ELEVATION for it; this
     module supplies the context needed to triage one.

Triage matters here, because the second signal has loud, boring causes: signed
Windows binaries that legitimately auto-elevate, anything started by a service,
ConsentPromptBehaviorAdmin=0, and prompts that opened and closed between two
scans. The registry signal has no such excuses.
"""

import dataclasses
import winreg

# Keys a bypass writes so that an auto-elevating binary loads attacker-chosen
# code. None of these exist under HKCU on a clean Windows 11 install; each is
# listed with the binary that reads it, so a hit is immediately actionable.
HIJACK_POINTS = (
    (r"Software\Classes\ms-settings\shell\open\command",
     "fodhelper.exe, computerdefaults.exe",
     "protocol handler for ms-settings; read by auto-elevating settings shims"),
    (r"Software\Classes\mscfile\shell\open\command",
     "eventvwr.exe",
     "MMC saved-console association; Event Viewer opens one at startup"),
    (r"Software\Classes\exefile\shell\open\command",
     "sdclt.exe",
     "the association for .exe itself -- a hijack here is never benign"),
    (r"Software\Classes\Folder\shell\open\command",
     "sdclt.exe",
     "folder-open verb, consulted by the backup control panel"),
    (r"Software\Classes\ms-settings\CurWer",
     "fodhelper.exe",
     "variant staging key used by some fodhelper implementations"),
    (r"Environment",
     "silentcleanup scheduled task",
     "a per-user windir value redirects a SYSTEM-run task to attacker paths",
     "windir"),
)

# Binaries Windows elevates without prompting because their manifests request
# it and they are Microsoft-signed. Running one is completely normal; running
# one immediately before an unexplained elevated process is not.
AUTO_ELEVATE_IMAGES = frozenset((
    "fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe",
    "cmstp.exe", "wsreset.exe", "slui.exe", "dismhost.exe", "taskmgr.exe",
    "msconfig.exe", "cleanmgr.exe", "changepk.exe", "wusa.exe",
))

# The value whose presence turns a shell-command hijack into a working one: it
# makes the shell ignore the default verb handler and run the (Default) string.
DELEGATE_EXECUTE = "DelegateExecute"


@dataclasses.dataclass
class Finding:
    severity: str
    title: str
    detail: str
    evidence: str = ""


def scan_registry_hijacks():
    """Look for the per-user keys the prompt-bypass techniques rely on.

    Read-only, HKCU, no elevation needed -- and deliberately scoped to the
    current user, because that is where these techniques must write.
    """
    findings = []
    for entry in HIJACK_POINTS:
        path, abused_by, why = entry[0], entry[1], entry[2]
        watched_value = entry[3] if len(entry) > 3 else None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                findings.append(_describe_hit(key, path, abused_by, why, watched_value))
        except FileNotFoundError:
            continue                     # absent is the healthy state
        except OSError as exc:
            findings.append(Finding(
                "info", f"HKCU\\{path}", f"could not be read: {exc}"))
    return [f for f in findings if f is not None]


def _describe_hit(key, path, abused_by, why, watched_value):
    values = {}
    index = 0
    while True:
        try:
            name, value, _ = winreg.EnumValue(key, index)
        except OSError:
            break
        values[name or "(Default)"] = value
        index += 1

    # HKCU\Environment legitimately exists; only a specific value is suspect.
    if watched_value is not None:
        if watched_value not in values:
            return None
        return Finding(
            "alert",
            f"HKCU\\{path}\\{watched_value} is set",
            f"A per-user override of {watched_value} redirects processes that "
            f"expand it -- including tasks that run as SYSTEM. Abused by: {abused_by}.",
            f"{watched_value} = {values[watched_value]!r}")

    severity = "alert" if DELEGATE_EXECUTE in values else "notice"
    command = values.get("(Default)", "")
    detail = (f"This key does not exist on a clean system. {why}. "
              f"Abused by: {abused_by}.")
    if DELEGATE_EXECUTE in values:
        detail += (" A DelegateExecute value is present, which is what makes the "
                   "(Default) command actually run -- treat as active tooling.")
    return Finding(severity, f"HKCU\\{path} exists", detail,
                   f"(Default) = {command!r}" + (
                       f", {DELEGATE_EXECUTE} = {values[DELEGATE_EXECUTE]!r}"
                       if DELEGATE_EXECUTE in values else ""))


def assess_snapshot(snapshot, prompt_tracker):
    """Process-side findings: elevated processes nobody consented to.

    `prompt_tracker` supplies the observed consent dialogs; a high-integrity
    process whose creation falls near none of them is what a successful bypass
    looks like from a monitor's seat.
    """
    findings = []
    auto_elevaters = {}

    for state in snapshot.values():
        image = state.name.lower()
        if image in AUTO_ELEVATE_IMAGES:
            auto_elevaters[state.pid] = state

    for state in snapshot.values():
        if state.integrity_rid is None or state.integrity_rid < 0x3000:
            continue
        if state.integrity_rid >= 0x4000:
            continue                     # SYSTEM services are not the question
        if state.create_time is None:
            continue

        parent = snapshot.get(state.ppid)
        if parent is not None and parent.name.lower() in AUTO_ELEVATE_IMAGES:
            findings.append(Finding(
                "alert",
                f"{state.name} ({state.pid}) was spawned by an auto-elevating binary",
                f"Parent {parent.name} ({parent.ppid}) elevates without a prompt by "
                f"design. A child process inheriting that is the payload step of a "
                f"registry-hijack bypass. Confirm the child is a Microsoft component "
                f"the parent legitimately launches.",
                f"integrity {state.integrity_label}, image {state.image_path or '?'}"))
            continue

        prompt = prompt_tracker.most_recent_within(state.create_time, 10.0)
        if prompt is None:
            findings.append(Finding(
                "notice",
                f"{state.name} ({state.pid}) is elevated with no consent prompt seen",
                "Benign causes are common (auto-elevating signed binary, "
                "service-launched, policy set to elevate silently, or the process "
                "predates this monitor). Escalate only if the image is unsigned or "
                "unexpected, or a registry hijack was also found.",
                f"integrity {state.integrity_label}, started "
                f"{state.create_time.strftime('%H:%M:%S')}"))

    for pid, state in auto_elevaters.items():
        findings.append(Finding(
            "info",
            f"auto-elevating binary running: {state.name} ({pid})",
            "Normal on its own. Recorded so that a later unexplained elevation "
            "can be lined up against it."))
    return findings
