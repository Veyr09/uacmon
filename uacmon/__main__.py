"""Entry point.

    python -m uacmon                    GUI
    python -m uacmon --console          stream transitions to stdout
    python -m uacmon --once             one scan, summary only
    python -m uacmon --elevate          run the elevation sequence, no GUI
    python -m uacmon --token-report P   child mode: describe own token, exit

--token-report is what the elevated child runs. It is a normal mode rather than
a hidden one on purpose: the thing that gets elevated should be inspectable.
"""

import argparse
import sys
import time

from . import bypass_watch, collector as collector_module
from . import elevate, model, transitions, uac, wintoken


def main(argv=None):
    parser = argparse.ArgumentParser(prog="uacmon", description=__doc__)
    parser.add_argument("--console", action="store_true",
                        help="stream transitions to stdout instead of opening the GUI")
    parser.add_argument("--once", action="store_true",
                        help="take a single scan, print a summary, exit")
    parser.add_argument("--elevate", action="store_true",
                        help="run the instrumented elevation sequence without the GUI")
    parser.add_argument("--token-report", metavar="PATH",
                        help="write this process's token state to PATH as JSON, then exit")
    parser.add_argument("--interval", type=float,
                        default=collector_module.DEFAULT_INTERVAL_SECONDS,
                        help="seconds between scans (default: %(default)s)")
    args = parser.parse_args(argv)

    if sys.platform != "win32":
        parser.error("this tool reads Windows access tokens; it only runs on Windows")

    if args.token_report:
        report = elevate.write_token_report(args.token_report)
        print(f"token report written to {args.token_report}")
        print(f"  integrity {report['integrity']}, elevated={report['elevated']}, "
              f"{len(report['privileges'])} privileges")
        return 0

    if args.once:
        return run_once()
    if args.elevate:
        return run_elevation()
    if args.console:
        return run_console(args.interval)

    from . import ui
    ui.run(interval=args.interval)
    return 0


def run_once():
    """A single scan. Useful as a smoke test of the Win32 layer."""
    scanner = collector_module.Collector()
    result = scanner._scan()      # deliberate: one synchronous scan, no thread
    elevated = wintoken.current_process_is_elevated()

    print("=" * 70)
    print(" WINDOWS TOKEN / UAC MONITOR -- single scan")
    print(f" Processes: {len(result.snapshot)}   "
          f"readable: {result.readable_count}   denied: {result.denied_count}")
    print(f" Monitor elevated: {elevated}")
    print("=" * 70)

    print("\n=== High integrity and above ===")
    for pid in sorted(result.snapshot):
        state = result.snapshot[pid]
        if (state.integrity_rid or 0) < 0x3000:
            continue
        print(f"  {pid:>6}  {state.name:<28} {state.integrity_label:<12} "
              f"elevated={state.elevated} {state.display_user}")

    print("\n=== Tokens holding high-value privileges ===")
    found = False
    for pid in sorted(result.snapshot):
        state = result.snapshot[pid]
        dangerous = state.dangerous_enabled()
        if not dangerous:
            continue
        found = True
        print(f"  {pid:>6}  {state.name:<28} {', '.join(sorted(dangerous))}")
    if not found:
        print("  none visible from this token")

    print("\n=== UAC policy ===")
    policy = uac.read_policy()
    label, why = policy.predict_prompt(3)
    print(f"  EnableLUA={policy.get('EnableLUA')}  "
          f"ConsentPromptBehaviorAdmin={policy.get('ConsentPromptBehaviorAdmin')}  "
          f"PromptOnSecureDesktop={policy.get('PromptOnSecureDesktop')}")
    print(f"  administrators would get: {label}")
    print(f"    {why}")
    for name, actual, expected, consequence in policy.weakened():
        print(f"  [!] {name}={actual} (hardened: {expected}) -- {consequence}")

    print("\n=== Bypass watch ===")
    findings = [f for f in result.bypass_findings if f.severity != "info"]
    if not findings:
        print("  no registry hijack points present, nothing unexplained")
    for finding in findings:
        print(f"  [{finding.severity}] {finding.title}")
        print(f"      {finding.detail}")
        if finding.evidence:
            print(f"      {finding.evidence}")

    print("\n=== Linked token (what elevation would grant) ===")
    linked = wintoken.read_linked_token()
    own = wintoken.probe_current_process()
    if linked is None:
        print("  no linked token: standard user, or UAC filtering disabled")
    else:
        gained, _, _, _ = model.diff_privileges(own.privileges, linked.privileges)
        print(f"  integrity {model.integrity_name(own.integrity_rid)} -> "
              f"{model.integrity_name(linked.integrity_rid)}, "
              f"{len(gained)} privileges gained")
        for name in sorted(gained):
            note = model.DANGEROUS_PRIVILEGES.get(name, "")
            print(f"    + {name}" + (f"  <- {note}" if note else ""))
    return 0


def run_console(interval):
    """Tail the transition stream. Ctrl+C to stop."""
    # Python block-buffers stdout when it is a pipe or a file, which turns a
    # live event tail into nothing at all until the process exits.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass
    scanner = collector_module.Collector(interval=interval)
    scanner.start()
    print(f"scanning every {scanner.interval:.2f}s -- Ctrl+C to stop\n")
    try:
        while True:
            result = scanner.results.get()
            if result.error:
                print(f"scan error: {result.error}")
                continue
            for event in result.events:
                print(event.format_line())
                if event.detail and event.severity != transitions.INFO:
                    for line in event.detail.splitlines():
                        print(f"          {line}")
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        scanner.stop()
    return 0


def run_elevation():
    """The elevation sequence with a scanner running, printed to stdout.

    The scanner has to be running for the PROMPT_TRIGGER step to have anything
    to observe -- consent.exe only exists while the dialog is up.
    """
    scanner = collector_module.Collector()
    scanner.start()
    time.sleep(1.5)      # let the baseline scan land before we trigger anything

    session = elevate.ElevationSession(
        on_step=_print_step, prompt_lookup=scanner.prompts_since)
    try:
        succeeded = session.run()
    finally:
        scanner.stop()
    return 0 if succeeded else 1


def _print_step(step):
    if step.status == elevate.RUNNING and not step.lines:
        print(f"[{step.started.strftime('%H:%M:%S')}] {step.key} -- {step.title}")
        return
    if step.status in (elevate.PENDING, elevate.RUNNING):
        return
    print(step.format_block())
    print()


if __name__ == "__main__":
    sys.exit(main())
