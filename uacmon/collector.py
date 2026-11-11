"""The scanning thread: snapshots in, ScanResults out.

Deliberately the only place that knows scanning is *polled*. The UI consumes a
queue of ScanResult objects and does not care where they came from, so a
production build can drop in an ETW consumer -- Microsoft-Windows-Kernel-Process
for lifetimes, Security 4703 for token-right adjustments -- behind the same
queue and delete nothing above this line.

The sampling caveat, stated once and honestly: at a one-second interval this
misses processes that live and die between scans, and misses a privilege that
is enabled and disabled again inside one interval. It reports what it sampled.
An absence of events is not evidence of absence.
"""

import datetime
import queue
import threading
import time

from . import bypass_watch, model, transitions, uac, wintoken

DEFAULT_INTERVAL_SECONDS = 1.0
MIN_INTERVAL_SECONDS = 0.25
REGISTRY_SCAN_EVERY_N_SCANS = 10        # hijack keys change rarely; don't hammer


class ScanResult:
    __slots__ = ("timestamp", "snapshot", "events", "duration_ms",
                 "readable_count", "denied_count", "bypass_findings", "error")

    def __init__(self, timestamp, snapshot, events, duration_ms,
                 readable_count, denied_count, bypass_findings, error=None):
        self.timestamp = timestamp
        self.snapshot = snapshot
        self.events = events
        self.duration_ms = duration_ms
        self.readable_count = readable_count
        self.denied_count = denied_count
        self.bypass_findings = bypass_findings
        self.error = error


class Collector(threading.Thread):
    """Polls the system and publishes ScanResults onto `self.results`."""

    daemon = True

    def __init__(self, interval=DEFAULT_INTERVAL_SECONDS):
        super().__init__(name="uacmon-collector")
        self.results = queue.Queue()
        self.interval = max(interval, MIN_INTERVAL_SECONDS)
        self.prompts = uac.PromptTracker()
        self.engine = transitions.TransitionEngine(prompt_tracker=self.prompts)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._scan_number = 0
        self._last_registry_findings = []

    def stop(self):
        self._stop.set()

    def set_interval(self, seconds):
        self.interval = max(float(seconds), MIN_INTERVAL_SECONDS)

    def run(self):
        while not self._stop.is_set():
            started = time.perf_counter()
            try:
                result = self._scan()
            except Exception as exc:                      # keep the thread alive
                result = ScanResult(datetime.datetime.now(), {}, [], 0, 0, 0, [],
                                    error=f"{type(exc).__name__}: {exc}")
            self.results.put(result)
            elapsed = time.perf_counter() - started
            self._stop.wait(max(0.0, self.interval - elapsed))

    def _scan(self):
        started = time.perf_counter()
        now = datetime.datetime.now()

        snapshot = {}
        readable = denied = 0
        for entry in wintoken.enumerate_processes():
            probe = wintoken.probe_process(entry.pid)
            state = model.state_from_probe(entry, probe, now)
            snapshot[entry.pid] = state
            if state.readable:
                readable += 1
            else:
                denied += 1

        with self._lock:
            events = self.engine.observe(snapshot, now)
            self._scan_number += 1
            if self._scan_number % REGISTRY_SCAN_EVERY_N_SCANS == 1:
                self._last_registry_findings = bypass_watch.scan_registry_hijacks()
            findings = list(self._last_registry_findings)
            findings.extend(bypass_watch.assess_snapshot(snapshot, self.prompts))

        duration_ms = (time.perf_counter() - started) * 1000
        return ScanResult(now, snapshot, events, duration_ms,
                          readable, denied, findings)

    def prompts_since(self, moment):
        """Consent dialogs first seen at or after `moment`.

        Called from the elevation worker thread, so it copies under the lock
        rather than handing out the tracker's live list.
        """
        with self._lock:
            return [prompt for prompt in self.prompts.history
                    if prompt.started >= moment]
