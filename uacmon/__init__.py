"""Windows token integrity / UAC transition monitor.

Layering, bottom up -- each layer only knows the one below it:

    wintoken      ctypes Win32 queries. Read-only by construction.
    model         ProcessState and the integrity/privilege vocabulary.
    uac           UAC policy, and consent.exe prompt lifetimes.
    transitions   snapshot diffing -> typed events.
    bypass_watch  detection signatures for prompt-bypass activity.
    collector     the polling thread; the seam where ETW would replace polling.
    elevate       the instrumented ShellExecuteEx("runas") sequence.
    ui            tkinter front end.

Stdlib only: ctypes and tkinter both ship with CPython on Windows.
"""

__all__ = ["wintoken", "model", "uac", "transitions", "bypass_watch",
           "collector", "elevate", "ui"]
