# uacmon

A Windows monitor for access-token integrity and UAC transitions, with detection for UAC-bypass
activity ([MITRE ATT&CK T1548.002](https://attack.mitre.org/techniques/T1548/002/)). It watches
every process's token, reports when integrity or privileges change, ties elevated processes to the
consent prompt that released them, and flags the ones nobody consented to.

Detection only: nothing in this repository performs a bypass. Read-only Win32 queries through
`ctypes`, a `tkinter` front end, standard library only.

`python -m uacmon` · Windows 10/11 · Python 3.10+ · **22 tests**

## What it looks for

| Signal | Why it matters |
|---|---|
| A process appearing at **High** integrity with no consent prompt near its creation | What a successful bypass looks like from the outside. Correlated against `consent.exe` lifetimes, with a 10-second attribution window |
| A child of an **auto-elevating binary** (`fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, …) running elevated | The payload step of a registry-hijack bypass |
| **HKCU hijack keys** that do not exist on a clean system (`ms-settings\shell\open\command`, `mscfile`, `exefile`, a per-user `windir`, …) | Every registry-hijack variant must write one. A `DelegateExecute` value beside it is close to conclusive |
| Integrity **raised in place**, `TokenIsElevated` flipping, high-value privileges **enabled** (`SeDebug`, `SeImpersonate`, `SeBackup`, `SeLoadDriver`, …) | A live token is not normally rewritten; enabling one of these converts directly into system control |
| UAC policy sitting on a **weak value** (`EnableLUA=0`, `PromptOnSecureDesktop=0`, `LocalAccountTokenFilterPolicy=1`, …) | Matched on the weak value, not on "differs from default", so the shipped default is not reported as a finding |

Processes are compared by `(pid, create_time)`, so a recycled PID is reported as `PID_REUSED`
instead of looking like a process that silently swapped its token.

## Run it

```bash
python -m uacmon                 # GUI
python -m uacmon --console       # stream transitions to stdout
python -m uacmon --once          # one scan, summary, exit
python -m uacmon --elevate       # instrumented ShellExecuteEx("runas"), step by step
```

`--once` on a stock Windows 11 desktop, unelevated (host and user names removed):

```text
======================================================================
 WINDOWS TOKEN / UAC MONITOR -- single scan
 Processes: 380   readable: 248   denied: 132
 Monitor elevated: False
======================================================================

=== Tokens holding high-value privileges ===
    3196  L-Connect 3.exe              SeDebugPrivilege, SeImpersonatePrivilege
   34100  taskhostw.exe                SeImpersonatePrivilege

=== UAC policy ===
  EnableLUA=1  ConsentPromptBehaviorAdmin=5  PromptOnSecureDesktop=1
  administrators would get: Prompt for consent for non-Windows binaries
  [!] ConsentPromptBehaviorAdmin=5 (hardened: 2) -- Windows default: signed Windows binaries
      auto-elevate silently. Normal, but it is the precondition every auto-elevated-binary
      bypass depends on

=== Bypass watch ===
  [notice] L-Connect 3.exe (3196) is elevated with no consent prompt seen
      Benign causes are common (auto-elevating signed binary, service-launched, policy set to
      elevate silently, or the process predates this monitor). Escalate only if the image is
      unsigned or unexpected, or a registry hijack was also found.

=== Linked token (what elevation would grant) ===
  integrity Medium -> High, 19 privileges gained
    + SeBackupPrivilege  <- read any file, bypassing ACLs (e.g. the SAM/SYSTEM hives)
    + SeDebugPrivilege  <- open any process, including SYSTEM-owned ones
    + SeImpersonatePrivilege  <- impersonate a client after authentication (Potato family)
```

The notices above are the benign kind the tool is designed to triage: vendor services started
before the monitor, with no hijack key present.

## Sampling caveat

The collector **polls** (default every second); it is not an ETW consumer. It reports what it
sampled, not everything that happened: a process that starts and exits between two scans is never
seen, and a consent prompt answered within one interval may be missed, which turns a legitimate
elevation into an "unprompted" notice. An absence of findings is therefore weaker evidence than a
presence. `collector.py` is the seam where an ETW provider would replace polling.

Run unelevated, roughly a third of processes (SYSTEM and protected ones) are unreadable. That is
reported as a count, never silently dropped.

## Layout

Each layer only knows the one below it:

| Module | Role |
|---|---|
| `wintoken` | `ctypes` Win32 token queries; read-only by construction |
| `model` | `ProcessState`, the integrity ladder, the high-value privilege list |
| `uac` | UAC policy, weak-value checks, `consent.exe` prompt lifetimes |
| `transitions` | Snapshot diffing into typed events (`UNPROMPTED_ELEVATION`, `INTEGRITY_RAISED`, …) |
| `bypass_watch` | Registry hijack points and process-side bypass findings |
| `collector` | The polling thread |
| `elevate` | The instrumented elevation sequence |
| `ui` | `tkinter` front end |

## Tests

```bash
python -m unittest discover -s tests
```

The tests cover the layers above Win32. Every detection rule has a case that must fire and a case
that must stay quiet, so a rule that stops matching, or starts matching everything, fails.

## License

MIT
