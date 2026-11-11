"""Snapshot diff engine: privilege-state transitions.

The collector produces a full picture of the system every scan. This module
turns consecutive pictures into a stream of *changes*, which is what an analyst
actually reads. A process sitting at high integrity is a fact; a process that
*became* high integrity is an event.

Design notes worth keeping in mind when extending the rules:

  * Identity is (pid, create_time), never pid alone. Windows recycles PIDs
    within seconds on a busy host, and a recycled PID compared naively looks
    exactly like a process that silently swapped its token.

  * Visibility changes are events too. A process going from readable to
    "access denied" usually means the monitor lost the race, not that anything
    happened -- but a *newly* unreadable process that was readable a second ago
    is worth surfacing rather than silently blanking the row.

  * Everything is polled, so this engine reports what it *sampled*, not what
    happened. See the sampling caveat in the README before trusting an absence.
"""

import dataclasses
import datetime

from . import model, uac

# Severity ordering drives colouring and filtering in the UI.
INFO = "info"
NOTICE = "notice"
ALERT = "alert"

SEVERITY_ORDER = {INFO: 0, NOTICE: 1, ALERT: 2}

# How long after a consent prompt closes an elevated process may appear and
# still be attributed to it. Generous: the AppInfo service has to start the
# process after the user clicks, and a cold image load is not instant.
PROMPT_ATTRIBUTION_WINDOW_SECONDS = 10.0


@dataclasses.dataclass
class Event:
    timestamp: datetime.datetime
    kind: str
    severity: str
    pid: int
    name: str
    summary: str
    detail: str = ""
    related_pid: int = None

    def format_line(self):
        stamp = self.timestamp.strftime("%H:%M:%S")
        return f"{stamp}  {self.severity.upper():<6} {self.kind:<24} " \
               f"{self.name} ({self.pid}): {self.summary}"


class TransitionEngine:
    """Stateful comparator. Feed it snapshots; it yields Events."""

    def __init__(self, prompt_tracker=None):
        self.previous = {}
        self.prompts = prompt_tracker or uac.PromptTracker()
        self.first_scan_done = False

    def observe(self, snapshot, now=None):
        """Compare `snapshot` (pid -> ProcessState) against the previous one."""
        now = now or datetime.datetime.now()
        events = []

        # The first scan would otherwise emit a PROCESS_START for all ~300
        # processes. Establish the baseline silently instead.
        if not self.first_scan_done:
            self.previous = snapshot
            self.first_scan_done = True
            self.prompts.observe(snapshot, now)
            return []

        opened, closed = self.prompts.observe(snapshot, now)
        events.extend(self._prompt_events(opened, closed, now))

        for pid, state in snapshot.items():
            before = self.previous.get(pid)
            if before is None:
                events.extend(self._started(state, snapshot, now))
                continue
            if before.create_time and state.create_time and \
                    before.create_time != state.create_time:
                events.append(Event(
                    now, "PID_REUSED", NOTICE, pid, state.name,
                    f"pid recycled: was {before.name}, now {state.name}",
                    "Compared by (pid, create_time); the old process exited and "
                    "the kernel handed its number to a new one."))
                events.extend(self._started(state, snapshot, now))
                continue
            events.extend(self._changed(before, state, now))

        for pid, before in self.previous.items():
            if pid not in snapshot:
                events.append(Event(
                    now, "PROCESS_EXIT", INFO, pid, before.name,
                    f"exited (was {before.integrity_label})"))

        self.previous = snapshot
        return events

    # --- rules -------------------------------------------------------------
    def _started(self, state, snapshot, now):
        events = []
        parent = snapshot.get(state.ppid)
        summary = f"started at {state.integrity_label} integrity"
        severity = INFO
        detail = ""

        if state.error:
            detail = f"token unreadable: {state.error}"

        # The signal this whole tool exists for: a process appearing at a
        # higher integrity than the parent that (apparently) spawned it.
        if (parent is not None and parent.integrity_rid is not None
                and state.integrity_rid is not None
                and state.integrity_rid > parent.integrity_rid
                and state.integrity_rid >= 0x3000):
            prompt = self.prompts.most_recent_within(
                now, PROMPT_ATTRIBUTION_WINDOW_SECONDS)
            if prompt is not None:
                events.append(Event(
                    now, "ELEVATED_CHILD_SPAWNED", NOTICE, state.pid, state.name,
                    f"elevated to {state.integrity_label} from parent "
                    f"{parent.name} ({parent.integrity_label})",
                    f"Correlated with the consent prompt that closed "
                    f"{(now - (prompt.ended or prompt.started)).total_seconds():.1f}s "
                    f"ago ({prompt.describe_requestor()}). Correlation by timing, "
                    f"not a causal link the API can confirm.",
                    related_pid=prompt.pid))
            else:
                events.append(Event(
                    now, "UNPROMPTED_ELEVATION", ALERT, state.pid, state.name,
                    f"appeared at {state.integrity_label} with no observed prompt "
                    f"(parent {parent.name} is {parent.integrity_label})",
                    "Legitimate causes: an auto-elevating signed Windows binary, "
                    "a service-launched child, ConsentPromptBehaviorAdmin=0, or a "
                    "prompt that opened and closed between two scans. Illegitimate "
                    "cause: a UAC bypass. Check the parent chain and the policy tab."))

        events.append(Event(now, "PROCESS_START", severity, state.pid, state.name,
                            summary, detail))

        if state.dangerous_enabled():
            names = ", ".join(sorted(state.dangerous_enabled()))
            events.append(Event(
                now, "PRIVILEGE_ENABLED", NOTICE, state.pid, state.name,
                f"starts with high-value privileges enabled: {names}",
                _explain_privileges(state.dangerous_enabled())))
        return events

    def _changed(self, before, after, now):
        events = []

        if before.readable and not after.readable:
            events.append(Event(
                now, "VISIBILITY_LOST", INFO, after.pid, after.name,
                f"token no longer readable: {after.error}",
                "Usually a scan racing process teardown; occasionally a real "
                "protection change."))
            return events
        if not before.readable and after.readable:
            events.append(Event(
                now, "VISIBILITY_GAINED", INFO, after.pid, after.name,
                f"token became readable ({after.integrity_label})"))

        if (before.integrity_rid is not None and after.integrity_rid is not None
                and before.integrity_rid != after.integrity_rid):
            raised = after.integrity_rid > before.integrity_rid
            events.append(Event(
                now,
                "INTEGRITY_RAISED" if raised else "INTEGRITY_LOWERED",
                ALERT if raised else NOTICE,
                after.pid, after.name,
                f"integrity {before.integrity_label} -> {after.integrity_label}",
                "A live token's integrity label is not normally rewritten in "
                "place. Raised is far more suspicious than lowered; lowering is "
                "a documented sandboxing move."))

        if before.elevated is not None and after.elevated is not None \
                and before.elevated != after.elevated:
            events.append(Event(
                now, "ELEVATION_CHANGED", ALERT, after.pid, after.name,
                f"TokenIsElevated {before.elevated} -> {after.elevated}"))

        if before.elevation_type != after.elevation_type \
                and None not in (before.elevation_type, after.elevation_type):
            events.append(Event(
                now, "ELEVATION_TYPE_CHANGED", NOTICE, after.pid, after.name,
                f"elevation type {before.elevation_label} -> {after.elevation_label}"))

        if before.virtualized is not None and after.virtualized is not None \
                and before.virtualized != after.virtualized:
            events.append(Event(
                now, "VIRTUALIZATION_CHANGED", INFO, after.pid, after.name,
                f"UAC file/registry virtualization "
                f"{'enabled' if after.virtualized else 'disabled'}"))

        events.extend(self._privilege_events(before, after, now))
        return events

    def _privilege_events(self, before, after, now):
        """The token-adjustment tracker proper.

        AdjustTokenPrivileges is how a process arms a privilege it was granted
        but not given enabled. Nothing about that call is logged by Windows by
        default below the Security-log 4703 event, so sampling the token is the
        cheap way to notice it.
        """
        gained, lost, enabled, disabled = model.diff_privileges(
            before.privileges, after.privileges)
        events = []

        for group, kind, base_severity in (
                (enabled, "PRIVILEGE_ENABLED", INFO),
                (disabled, "PRIVILEGE_DISABLED", INFO),
                (gained, "PRIVILEGE_ADDED", NOTICE),
                (lost, "PRIVILEGE_REMOVED", INFO)):
            if not group:
                continue
            dangerous = {n: a for n, a in group.items()
                         if n in model.DANGEROUS_PRIVILEGES}
            severity = ALERT if (dangerous and kind in
                                 ("PRIVILEGE_ENABLED", "PRIVILEGE_ADDED")) else base_severity
            names = ", ".join(sorted(group))
            events.append(Event(
                now, kind, severity, after.pid, after.name,
                f"{kind.split('_')[1].lower()}: {names}",
                _explain_privileges(dangerous) if dangerous else ""))
        return events

    def _prompt_events(self, opened, closed, now):
        events = []
        for prompt in opened:
            events.append(Event(
                now, "UAC_PROMPT_SHOWN", NOTICE, prompt.pid, uac.CONSENT_IMAGE,
                "consent dialog displayed",
                prompt.describe_requestor(),
                related_pid=prompt.requestor_pid))
        for prompt in closed:
            seconds = prompt.duration_seconds
            events.append(Event(
                now, "UAC_PROMPT_CLOSED", INFO, prompt.pid, uac.CONSENT_IMAGE,
                f"consent dialog dismissed after "
                f"{seconds:.1f}s" if seconds is not None else "consent dialog dismissed",
                "The dialog closing does not itself say Yes or No. The answer is "
                "inferred from whether an elevated process follows within "
                f"{PROMPT_ATTRIBUTION_WINDOW_SECONDS:.0f}s.",
                related_pid=prompt.requestor_pid))
        return events


def _explain_privileges(privileges):
    return "\n".join(
        f"{name}: {model.DANGEROUS_PRIVILEGES[name]}"
        for name in sorted(privileges) if name in model.DANGEROUS_PRIVILEGES)
