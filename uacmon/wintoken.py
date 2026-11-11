"""Read-only Win32 process/token query layer.

Every call in this module is a query. Nothing here opens a process for write,
adjusts a token, duplicates a handle for use, or reads another process's
memory. The maximum access requested anywhere is:

    PROCESS_QUERY_LIMITED_INFORMATION | TOKEN_QUERY

That matters twice over. It keeps the tool safe to run against a live machine,
and it means the tool sees exactly what an unprivileged monitor can see -- so
its blind spots are honest ones (see README).

Access-denied is the normal case here, not an exception: from a medium-integrity
token you cannot open the token of a SYSTEM, PPL, or other-user process. Those
failures are returned as data (ProcessProbe.error) rather than raised, because
the fact that a process is unreadable is itself something the UI reports.
"""

import ctypes
import ctypes.wintypes as wt
import datetime

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

# --- Constants -------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
MAX_PATH = 260

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000   # weakest handle that still answers
TOKEN_QUERY = 0x0008                         # every question this tool asks

ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# TOKEN_INFORMATION_CLASS members we read.
TokenUser = 1
TokenPrivileges = 3
TokenElevationType = 18
TokenLinkedToken = 19
TokenElevation = 20
TokenVirtualizationEnabled = 24
TokenIntegrityLevel = 25
TokenUIAccess = 26

# PROCESSINFOCLASS. 60 is documented since Windows 8.1 and, unlike walking the
# PEB by hand, is satisfied by a QUERY_LIMITED handle -- no PROCESS_VM_READ.
ProcessCommandLineInformation = 60

SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_REMOVED = 0x00000004

# FILETIME epoch (1601-01-01) to Unix epoch.
FILETIME_EPOCH_DELTA = 11644473600
FILETIME_TICKS_PER_SECOND = 10_000_000


# --- Structures ------------------------------------------------------------
ULONG_PTR = ctypes.c_size_t


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


class TOKEN_LINKED_TOKEN(ctypes.Structure):
    _fields_ = [("LinkedToken", wt.HANDLE)]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wt.USHORT),
        ("MaximumLength", wt.USHORT),
        ("Buffer", wt.LPWSTR),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


# --- Prototypes ------------------------------------------------------------
# argtypes/restype are not optional on 64-bit: without them ctypes truncates
# HANDLEs to 32 bits and every failure looks like a random access denial.
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [
    wt.HANDLE, wt.DWORD, wt.LPWSTR, wt.LPDWORD]
kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
kernel32.ProcessIdToSessionId.argtypes = [wt.DWORD, wt.LPDWORD]
kernel32.ProcessIdToSessionId.restype = wt.BOOL
kernel32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(FILETIME)] * 4
kernel32.GetProcessTimes.restype = wt.BOOL
kernel32.GetCurrentProcess.restype = wt.HANDLE
kernel32.LocalFree.argtypes = [wt.HGLOBAL]
kernel32.LocalFree.restype = wt.HGLOBAL

advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi32.OpenProcessToken.restype = wt.BOOL
advapi32.GetTokenInformation.argtypes = [
    wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, wt.LPDWORD]
advapi32.GetTokenInformation.restype = wt.BOOL
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wt.BOOL
advapi32.LookupAccountSidW.argtypes = [
    wt.LPCWSTR, ctypes.c_void_p, wt.LPWSTR, wt.LPDWORD,
    wt.LPWSTR, wt.LPDWORD, wt.LPDWORD]
advapi32.LookupAccountSidW.restype = wt.BOOL
advapi32.LookupPrivilegeNameW.argtypes = [
    wt.LPCWSTR, ctypes.POINTER(LUID), wt.LPWSTR, wt.LPDWORD]
advapi32.LookupPrivilegeNameW.restype = wt.BOOL

ntdll.NtQueryInformationProcess.argtypes = [
    wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long


# --- Small helpers ---------------------------------------------------------
def _filetime_to_datetime(ft):
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if ticks == 0:
        return None
    return datetime.datetime.fromtimestamp(
        ticks / FILETIME_TICKS_PER_SECOND - FILETIME_EPOCH_DELTA)


def _token_information(token, info_class):
    """Two-call GetTokenInformation. Returns a raw buffer, or None.

    The sizing call is expected to fail; anything that leaves the required
    length at zero means the class is unsupported on this build, and the
    caller treats that as "unknown" rather than as an error.
    """
    size = wt.DWORD(0)
    advapi32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(size))
    if size.value == 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(
            token, info_class, buf, size.value, ctypes.byref(size)):
        return None
    return buf


def _token_dword(token, info_class):
    buf = _token_information(token, info_class)
    if buf is None:
        return None
    return ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]


def _sid_to_string(sid):
    out = wt.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(out)):
        return None
    try:
        return out.value
    finally:
        kernel32.LocalFree(out)


def _sid_to_account(sid):
    """DOMAIN\\user for the SID, or None if unresolvable.

    Unresolvable is routine for AppContainer and virtual service accounts; the
    caller falls back to displaying the SID string.
    """
    name = ctypes.create_unicode_buffer(256)
    domain = ctypes.create_unicode_buffer(256)
    name_len = wt.DWORD(256)
    domain_len = wt.DWORD(256)
    use = wt.DWORD(0)
    ok = advapi32.LookupAccountSidW(
        None, sid, name, ctypes.byref(name_len),
        domain, ctypes.byref(domain_len), ctypes.byref(use))
    if not ok:
        return None
    return f"{domain.value}\\{name.value}" if domain.value else name.value


def _privilege_name(luid):
    length = wt.DWORD(0)
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(luid), None, ctypes.byref(length))
    if length.value == 0:
        return None
    buf = ctypes.create_unicode_buffer(length.value + 1)
    length = wt.DWORD(len(buf))
    if not advapi32.LookupPrivilegeNameW(
            None, ctypes.byref(luid), buf, ctypes.byref(length)):
        return None
    return buf.value


# --- Public query surface --------------------------------------------------
class ProcessEntry:
    """One row of the process snapshot, before any token work."""

    __slots__ = ("pid", "ppid", "name", "thread_count")

    def __init__(self, pid, ppid, name, thread_count):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.thread_count = thread_count


def enumerate_processes():
    """Every process in the system, from a Toolhelp32 snapshot.

    Toolhelp32 needs no per-process handle, so this list stays complete even
    when most of the tokens on it turn out to be unreadable.
    """
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())

    entries = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            entries.append(ProcessEntry(
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                entry.szExeFile,
                entry.cntThreads,
            ))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return entries


class ProcessProbe:
    """Everything the token layer could learn about one process.

    `error` is set when the process or its token could not be opened at all.
    A field left None without `error` means that specific token class was
    unsupported -- unknown, as distinct from denied.
    """

    __slots__ = (
        "pid", "image_path", "session_id", "create_time", "command_line",
        "integrity_rid", "elevated", "elevation_type", "virtualized",
        "ui_access", "user", "sid", "privileges", "error",
    )

    def __init__(self, pid):
        self.pid = pid
        self.image_path = None
        self.session_id = None
        self.create_time = None
        self.command_line = None
        self.integrity_rid = None
        self.elevated = None
        self.elevation_type = None
        self.virtualized = None
        self.ui_access = None
        self.user = None
        self.sid = None
        self.privileges = {}          # name -> attribute bitmask
        self.error = None


def probe_process(pid):
    """Open `pid` read-only and read its token state."""
    probe = ProcessProbe(pid)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        probe.error = ("access denied" if code == ERROR_ACCESS_DENIED
                       else f"open failed ({code})")
        return probe

    try:
        _read_process_facts(handle, probe)
        token = wt.HANDLE()
        if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            code = ctypes.get_last_error()
            probe.error = ("token denied" if code == ERROR_ACCESS_DENIED
                           else f"token failed ({code})")
            return probe
        try:
            read_token_facts(token, probe)
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(handle)
    return probe


def probe_current_process():
    """Probe ourselves. Always succeeds -- a process can read its own token."""
    import os
    return probe_process(os.getpid())


def _read_process_facts(handle, probe):
    buf = ctypes.create_unicode_buffer(MAX_PATH * 2)
    size = wt.DWORD(len(buf))
    if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        probe.image_path = buf.value

    session = wt.DWORD(0)
    if kernel32.ProcessIdToSessionId(probe.pid, ctypes.byref(session)):
        probe.session_id = session.value

    created, exited, kernel_time, user_time = (FILETIME() for _ in range(4))
    if kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                ctypes.byref(kernel_time), ctypes.byref(user_time)):
        probe.create_time = _filetime_to_datetime(created)

    probe.command_line = query_command_line(handle)


def query_command_line(handle):
    """Command line via NtQueryInformationProcess(ProcessCommandLineInformation).

    Used to attribute a consent.exe prompt to the process that asked for the
    elevation: consent.exe's first argument is the requesting PID.
    """
    size = wt.ULONG(0)
    status = ntdll.NtQueryInformationProcess(
        handle, ProcessCommandLineInformation, None, 0, ctypes.byref(size))
    if (status & 0xFFFFFFFF) != STATUS_INFO_LENGTH_MISMATCH or size.value == 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    status = ntdll.NtQueryInformationProcess(
        handle, ProcessCommandLineInformation, buf, size.value, ctypes.byref(size))
    if status != 0:
        return None
    text = ctypes.cast(buf, ctypes.POINTER(UNICODE_STRING))[0]
    if not text.Buffer or text.Length == 0:
        return None
    return ctypes.wstring_at(text.Buffer, text.Length // 2)


def read_token_facts(token, probe):
    """Fill `probe` from an already-open TOKEN_QUERY handle.

    Split out from probe_process so the same reader works on a linked token,
    which never belongs to a process we can open.
    """
    probe.integrity_rid = _read_integrity_rid(token)
    probe.elevation_type = _token_dword(token, TokenElevationType)
    elevation = _token_dword(token, TokenElevation)
    probe.elevated = None if elevation is None else bool(elevation)
    virtualized = _token_dword(token, TokenVirtualizationEnabled)
    probe.virtualized = None if virtualized is None else bool(virtualized)
    ui_access = _token_dword(token, TokenUIAccess)
    probe.ui_access = None if ui_access is None else bool(ui_access)
    probe.user, probe.sid = _read_token_user(token)
    probe.privileges = read_privileges(token)


def _read_integrity_rid(token):
    """The mandatory label's last sub-authority, e.g. 0x3000 for High."""
    buf = _token_information(token, TokenIntegrityLevel)
    if buf is None:
        return None
    label = ctypes.cast(buf, ctypes.POINTER(TOKEN_MANDATORY_LABEL))[0]
    count_ptr = advapi32.GetSidSubAuthorityCount(label.Label.Sid)
    if not count_ptr:
        return None
    return advapi32.GetSidSubAuthority(label.Label.Sid, count_ptr[0] - 1)[0]


def _read_token_user(token):
    buf = _token_information(token, TokenUser)
    if buf is None:
        return None, None
    token_user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER))[0]
    return _sid_to_account(token_user.User.Sid), _sid_to_string(token_user.User.Sid)


def read_privileges(token):
    """name -> attribute bitmask for every privilege present in the token.

    Presence and enabled-ness are different things. A privilege sits in the
    token dormant until AdjustTokenPrivileges sets SE_PRIVILEGE_ENABLED, and
    that flip is exactly the token adjustment the transition engine watches
    for. A privilege can also be permanently dropped (SE_PRIVILEGE_REMOVED),
    which is one-way for the lifetime of the token.
    """
    buf = _token_information(token, TokenPrivileges)
    if buf is None:
        return {}
    count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]
    array = ctypes.cast(
        ctypes.byref(buf, ctypes.sizeof(wt.DWORD)),
        ctypes.POINTER(LUID_AND_ATTRIBUTES))

    privileges = {}
    for index in range(count):
        item = array[index]
        name = _privilege_name(item.Luid)
        if name:
            privileges[name] = item.Attributes
    return privileges


def read_linked_token():
    """Read this process's *linked* token, without elevating anything.

    A member of Administrators logging in gets two tokens: the filtered one the
    shell actually runs with, and a full one held in reserve. Querying
    TokenLinkedToken hands back a read-only view of that reserve token -- so the
    monitor can show precisely what an elevation would grant before any prompt
    is raised. A genuine standard user has no linked token and gets None.

    Returns a ProcessProbe describing the linked token, or None.
    """
    own = wt.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(own)):
        return None
    try:
        buf = _token_information(own, TokenLinkedToken)
        if buf is None:
            return None
        linked = ctypes.cast(buf, ctypes.POINTER(TOKEN_LINKED_TOKEN))[0].LinkedToken
        if not linked:
            return None
        try:
            probe = ProcessProbe(0)
            read_token_facts(linked, probe)
            return probe
        finally:
            kernel32.CloseHandle(linked)
    finally:
        kernel32.CloseHandle(own)


def current_process_is_elevated():
    """Whether *this* monitor is elevated -- it decides how much it can see."""
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        return bool(_token_dword(token, TokenElevation))
    finally:
        kernel32.CloseHandle(token)
