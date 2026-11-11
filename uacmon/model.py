"""Domain model: what a process's privilege state *is*, independent of Win32.

Everything above this layer (transitions, UI, elevation flow) talks in these
terms, so a second collector -- an ETW consumer, an event-log reader -- only
has to produce ProcessState objects to slot in underneath.
"""

import dataclasses
import datetime

from . import wintoken

# The mandatory integrity ladder. The value is the RID at the tail of the
# token's mandatory label SID; the order is what makes "raised" and "lowered"
# meaningful, so keep this sorted ascending.
INTEGRITY_LEVELS = (
    (0x0000, "Untrusted"),
    (0x1000, "Low"),
    (0x2000, "Medium"),
    (0x2100, "Medium Plus"),
    (0x3000, "High"),
    (0x4000, "System"),
    (0x5000, "Protected"),
)

# TOKEN_ELEVATION_TYPE. "Limited" is the interesting one: it means the user is
# an administrator running with a filtered token, and a full token is sitting
# in reserve waiting for a UAC prompt to release it.
ELEVATION_TYPES = {
    1: "Default",    # UAC off, or the account has no split token
    2: "Full",       # this process holds the unfiltered administrator token
    3: "Limited",    # filtered token; a linked full token exists
}

# Privileges that convert directly into full system control when held by a
# non-SYSTEM token. These are the ones whose *enabling* is worth an alert rather than a log line.
DANGEROUS_PRIVILEGES = {
    "SeImpersonatePrivilege": "impersonate a client after authentication (Potato family)",
    "SeAssignPrimaryTokenPrivilege": "assign a primary token to a new process",
    "SeBackupPrivilege": "read any file, bypassing ACLs (e.g. the SAM/SYSTEM hives)",
    "SeRestorePrivilege": "write any file, bypassing ACLs",
    "SeTakeOwnershipPrivilege": "take ownership of any securable object",
    "SeDebugPrivilege": "open any process, including SYSTEM-owned ones",
    "SeLoadDriverPrivilege": "load a kernel driver (BYOVD)",
    "SeTcbPrivilege": "act as part of the operating system",
    "SeCreateTokenPrivilege": "forge an access token",
}


def integrity_name(rid):
    """Nearest named level at or below `rid` -- custom labels round down."""
    if rid is None:
        return "unknown"
    name = None
    for level, label in INTEGRITY_LEVELS:
        if rid >= level:
            name = label
        else:
            break
    return name if name is not None else f"0x{rid:04X}"


def elevation_type_name(value):
    if value is None:
        return "unknown"
    return ELEVATION_TYPES.get(value, f"type {value}")


def privilege_is_enabled(attributes):
    return bool(attributes & wintoken.SE_PRIVILEGE_ENABLED)


def privilege_is_removed(attributes):
    return bool(attributes & wintoken.SE_PRIVILEGE_REMOVED)


def describe_privilege_attributes(attributes):
    flags = []
    if attributes & wintoken.SE_PRIVILEGE_ENABLED:
        flags.append("enabled")
    if attributes & wintoken.SE_PRIVILEGE_ENABLED_BY_DEFAULT:
        flags.append("default")
    if attributes & wintoken.SE_PRIVILEGE_REMOVED:
        flags.append("removed")
    return ", ".join(flags) if flags else "disabled"


@dataclasses.dataclass
class ProcessState:
    """A single process as observed in one scan.

    Immutable by convention: each scan builds fresh instances, and the
    transition engine compares consecutive generations rather than mutating.
    """

    pid: int
    ppid: int
    name: str
    thread_count: int = 0
    image_path: str = None
    command_line: str = None
    session_id: int = None
    create_time: datetime.datetime = None
    integrity_rid: int = None
    elevated: bool = None
    elevation_type: int = None
    virtualized: bool = None
    ui_access: bool = None
    user: str = None
    sid: str = None
    privileges: dict = dataclasses.field(default_factory=dict)
    error: str = None
    first_seen: datetime.datetime = None

    @property
    def identity(self):
        """(pid, create_time) -- survives PID reuse, which is common on busy hosts.

        Windows recycles PIDs aggressively; comparing on PID alone makes a
        recycled PID look like a process that silently changed integrity.
        """
        return (self.pid, self.create_time)

    @property
    def readable(self):
        return self.error is None

    @property
    def integrity_label(self):
        return integrity_name(self.integrity_rid)

    @property
    def elevation_label(self):
        return elevation_type_name(self.elevation_type)

    @property
    def display_user(self):
        return self.user or self.sid or "-"

    def enabled_privileges(self):
        return {name: attrs for name, attrs in self.privileges.items()
                if privilege_is_enabled(attrs)}

    def dangerous_enabled(self):
        return {name: attrs for name, attrs in self.enabled_privileges().items()
                if name in DANGEROUS_PRIVILEGES}


def state_from_probe(entry, probe, now):
    """Fold a Toolhelp entry and a token probe into one ProcessState."""
    return ProcessState(
        pid=entry.pid,
        ppid=entry.ppid,
        name=entry.name,
        thread_count=entry.thread_count,
        image_path=probe.image_path,
        command_line=probe.command_line,
        session_id=probe.session_id,
        create_time=probe.create_time,
        integrity_rid=probe.integrity_rid,
        elevated=probe.elevated,
        elevation_type=probe.elevation_type,
        virtualized=probe.virtualized,
        ui_access=probe.ui_access,
        user=probe.user,
        sid=probe.sid,
        privileges=probe.privileges,
        error=probe.error,
        first_seen=now,
    )


def state_from_token_probe(probe, name, now):
    """Wrap a bare token probe (e.g. a linked token) as a ProcessState."""
    return ProcessState(
        pid=probe.pid,
        ppid=0,
        name=name,
        integrity_rid=probe.integrity_rid,
        elevated=probe.elevated,
        elevation_type=probe.elevation_type,
        virtualized=probe.virtualized,
        ui_access=probe.ui_access,
        user=probe.user,
        sid=probe.sid,
        privileges=probe.privileges,
        error=probe.error,
        first_seen=now,
    )


def diff_privileges(before, after):
    """Compare two privilege maps.

    Returns (gained, lost, enabled, disabled) -- name -> attribute pairs.
    `gained`/`lost` are set membership; `enabled`/`disabled` are the same
    privilege changing state, which is what AdjustTokenPrivileges does.
    """
    gained = {n: a for n, a in after.items() if n not in before}
    lost = {n: a for n, a in before.items() if n not in after}
    enabled, disabled = {}, {}
    for name, attrs in after.items():
        if name not in before:
            continue
        was = privilege_is_enabled(before[name])
        now_on = privilege_is_enabled(attrs)
        if now_on and not was:
            enabled[name] = attrs
        elif was and not now_on:
            disabled[name] = attrs
    return gained, lost, enabled, disabled
