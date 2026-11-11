"""Tests for the layers that do not touch Win32: model, uac, transitions, bypass_watch.

Each detection rule gets a case that must fire and a case that must stay quiet,
so a rule that silently stops matching -- or starts matching everything -- fails.
"""

import datetime
import unittest

from uacmon import bypass_watch, model, transitions, uac, wintoken

T0 = datetime.datetime(2026, 9, 1, 12, 0, 0)
ON = wintoken.SE_PRIVILEGE_ENABLED
OFF = 0
MEDIUM, HIGH, SYSTEM = 0x2000, 0x3000, 0x4000


def proc(pid, name, ppid=4, rid=MEDIUM, created=T0, **kw):
    return model.ProcessState(pid=pid, ppid=ppid, name=name, integrity_rid=rid,
                              create_time=created, **kw)


def snap(*states):
    return {s.pid: s for s in states}


class IntegrityNames(unittest.TestCase):
    def test_exact_levels(self):
        self.assertEqual(model.integrity_name(0x2000), "Medium")
        self.assertEqual(model.integrity_name(0x3000), "High")
        self.assertEqual(model.integrity_name(0x4000), "System")

    def test_custom_label_rounds_down(self):
        self.assertEqual(model.integrity_name(0x2FFF), "Medium Plus")

    def test_unknown(self):
        self.assertEqual(model.integrity_name(None), "unknown")


class PrivilegeDiff(unittest.TestCase):
    def test_gained_lost_enabled_disabled_are_separate(self):
        before = {"SeDebugPrivilege": OFF, "SeBackupPrivilege": ON, "SeShutdownPrivilege": OFF}
        after = {"SeDebugPrivilege": ON, "SeBackupPrivilege": OFF, "SeImpersonatePrivilege": ON}
        gained, lost, enabled, disabled = model.diff_privileges(before, after)
        self.assertEqual(set(gained), {"SeImpersonatePrivilege"})
        self.assertEqual(set(lost), {"SeShutdownPrivilege"})
        self.assertEqual(set(enabled), {"SeDebugPrivilege"})
        self.assertEqual(set(disabled), {"SeBackupPrivilege"})

    def test_dangerous_requires_enabled(self):
        state = proc(10, "x.exe", privileges={"SeDebugPrivilege": OFF,
                                              "SeImpersonatePrivilege": ON,
                                              "SeChangeNotifyPrivilege": ON})
        self.assertEqual(set(state.dangerous_enabled()), {"SeImpersonatePrivilege"})


class UacPolicyChecks(unittest.TestCase):
    def test_lua_off_means_no_prompt(self):
        label, _ = uac.UacPolicy({"EnableLUA": 0}).predict_prompt(3)
        self.assertEqual(label, "No prompt")

    def test_filtered_admin_gets_admin_behaviour(self):
        label, why = uac.UacPolicy({"ConsentPromptBehaviorAdmin": 2}).predict_prompt(3)
        self.assertEqual(label, "Prompt for consent on the secure desktop")
        self.assertIn("filtered administrator token", why)

    def test_full_token_needs_no_prompt(self):
        label, _ = uac.UacPolicy({}).predict_prompt(2)
        self.assertEqual(label, "No prompt")

    def test_weak_values_flagged(self):
        names = {f[0] for f in uac.UacPolicy(
            {"EnableLUA": 0, "PromptOnSecureDesktop": 0,
             "LocalAccountTokenFilterPolicy": 1}).weakened()}
        self.assertEqual(names, {"EnableLUA", "PromptOnSecureDesktop",
                                 "LocalAccountTokenFilterPolicy"})

    def test_hardened_and_absent_values_not_flagged(self):
        hardened = {"EnableLUA": 1, "PromptOnSecureDesktop": 1,
                    "ConsentPromptBehaviorAdmin": 2, "FilterAdministratorToken": 1,
                    "LocalAccountTokenFilterPolicy": 0, "EnableInstallerDetection": 1}
        self.assertEqual(uac.UacPolicy(hardened).weakened(), [])
        self.assertEqual(uac.UacPolicy({}).weakened(), [])


class RequestorPid(unittest.TestCase):
    def test_plain_and_quoted_image(self):
        self.assertEqual(uac.parse_requestor_pid(
            r"C:\Windows\system32\consent.exe 4120 312 0000020A1B2C3D40"), 4120)
        self.assertEqual(uac.parse_requestor_pid(
            r'"C:\Program Files\x 1\consent.exe" 77 312 0'), 77)

    def test_unreadable(self):
        self.assertIsNone(uac.parse_requestor_pid(None))
        self.assertIsNone(uac.parse_requestor_pid("consent.exe"))


class PromptTracking(unittest.TestCase):
    def test_open_then_close_records_duration_and_requestor(self):
        tracker = uac.PromptTracker()
        caller = proc(500, "setup.exe")
        prompt_proc = proc(900, "consent.exe", rid=SYSTEM,
                           command_line="consent.exe 500 1 0")
        opened, closed = tracker.observe(snap(caller, prompt_proc), T0)
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0].requestor_name, "setup.exe")
        later = T0 + datetime.timedelta(seconds=4)
        opened, closed = tracker.observe(snap(caller), later)
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0].duration_seconds, 4.0)

    def test_attribution_window(self):
        tracker = uac.PromptTracker()
        tracker.observe(snap(proc(900, "consent.exe", rid=SYSTEM)), T0)
        tracker.observe({}, T0 + datetime.timedelta(seconds=1))
        self.assertIsNotNone(tracker.most_recent_within(T0 + datetime.timedelta(seconds=5), 10))
        self.assertIsNone(tracker.most_recent_within(T0 + datetime.timedelta(seconds=30), 10))


class Transitions(unittest.TestCase):
    def setUp(self):
        self.engine = transitions.TransitionEngine()
        self.parent = proc(100, "explorer.exe")
        self.assertEqual(self.engine.observe(snap(self.parent), T0), [])   # silent baseline

    def kinds(self, events):
        return {e.kind for e in events}

    def test_unprompted_elevated_child_alerts(self):
        child = proc(200, "cmd.exe", ppid=100, rid=HIGH)
        events = self.engine.observe(snap(self.parent, child), T0 + datetime.timedelta(seconds=2))
        alert = [e for e in events if e.kind == "UNPROMPTED_ELEVATION"]
        self.assertEqual(len(alert), 1)
        self.assertEqual(alert[0].severity, transitions.ALERT)

    def test_prompted_elevated_child_is_only_a_notice(self):
        t1 = T0 + datetime.timedelta(seconds=1)
        self.engine.observe(snap(self.parent, proc(900, "consent.exe", rid=SYSTEM)), t1)
        t2 = T0 + datetime.timedelta(seconds=3)
        child = proc(200, "cmd.exe", ppid=100, rid=HIGH, created=t2)
        events = self.engine.observe(snap(self.parent, child), t2)
        self.assertIn("ELEVATED_CHILD_SPAWNED", self.kinds(events))
        self.assertNotIn("UNPROMPTED_ELEVATION", self.kinds(events))

    def test_medium_child_is_quiet(self):
        child = proc(200, "notepad.exe", ppid=100)
        events = self.engine.observe(snap(self.parent, child), T0 + datetime.timedelta(seconds=2))
        self.assertEqual(self.kinds(events), {"PROCESS_START"})

    def test_integrity_raised_in_place(self):
        raised = proc(100, "explorer.exe", rid=HIGH)
        events = self.engine.observe(snap(raised), T0 + datetime.timedelta(seconds=2))
        self.assertIn("INTEGRITY_RAISED", self.kinds(events))

    def test_pid_reuse_is_not_a_token_swap(self):
        reused = proc(100, "svchost.exe", rid=HIGH, created=T0 + datetime.timedelta(seconds=5))
        events = self.engine.observe(snap(reused), T0 + datetime.timedelta(seconds=6))
        self.assertIn("PID_REUSED", self.kinds(events))
        self.assertNotIn("INTEGRITY_RAISED", self.kinds(events))


class BypassAssessment(unittest.TestCase):
    def test_child_of_auto_elevating_binary_is_alert(self):
        fod = proc(300, "fodhelper.exe", rid=HIGH)
        payload = proc(301, "cmd.exe", ppid=300, rid=HIGH)
        findings = bypass_watch.assess_snapshot(snap(fod, payload), uac.PromptTracker())
        alerts = [f for f in findings if f.severity == "alert"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("cmd.exe (301)", alerts[0].title)

    def test_system_and_medium_processes_are_not_findings(self):
        findings = bypass_watch.assess_snapshot(
            snap(proc(1, "services.exe", rid=SYSTEM), proc(2, "notepad.exe")),
            uac.PromptTracker())
        self.assertEqual(findings, [])

    def test_hijack_points_cover_known_vehicles(self):
        vehicles = {entry[1] for entry in bypass_watch.HIJACK_POINTS}
        for binary in ("fodhelper.exe", "eventvwr.exe", "sdclt.exe"):
            self.assertIn(binary, vehicles)


if __name__ == "__main__":
    unittest.main()
