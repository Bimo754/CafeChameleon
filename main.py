#!/usr/bin/env python3
"""
main.py - Entrypoint for CafeChameleon network toolkit.

Subcommands:
  simple     - Hijack sessions using subnet blocks ping scanning
  aggressive - Hijack sessions of Multi-BSSID networks using AP roaming & air target discovery
  wifi       - Hijack session connectivity & hardware properties management
  blacklist  - Permanent MAC address & BSSID blacklist manager
"""

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.utils.state import set_debug, set_quiet, set_verbose, set_launcher_mode, set_use_xterm, set_use_original_mac, get_debug_tracing
from cafe_chameleon.utils.tracing import trace, log_exception_to_trace, get_recent_trace, get_trace_filepath
from cafe_chameleon.utils.signals import restore_and_exit, register_signal_handler
from cafe_chameleon.ui.console import init_xterm
from cafe_chameleon.scanners.detector import check_interface_warning
from cafe_chameleon.ui.colors import BOLD, GREEN, RED, YELLOW, RESET, colorize_brackets


def main():
    register_signal_handler()
    try:
        args = parse_arguments()

        debug_val = getattr(args, "debug", None)
        if debug_val:
            set_debug(debug_val)

        if getattr(args, "original_mac", False):
            set_use_original_mac(True)

        if getattr(args, "quiet", False):
            set_quiet(True)

        if getattr(args, "verbose", False):
            set_verbose(True)

        cmd = getattr(args, "command", "")
        set_launcher_mode(cmd in ("simple", "aggressive"))

        # Check for interface warnings and print in launching terminal
        iface_arg = getattr(args, "interface", None)
        warn_msg = check_interface_warning(iface_arg)
        if warn_msg:
            print(colorize_brackets(f"{YELLOW}[!] {warn_msg}{RESET}"))

        if getattr(args, "no_xterm", False) or cmd in ("wifi", "blacklist"):
            set_use_xterm(False)
        else:
            has_air = getattr(args, "air", None) is not None
            has_air_only = getattr(args, "air_only", None) is not None

            if cmd == "simple":
                active_windows = ["air", "scan", "hijack"] if (has_air or has_air_only) else ["scan", "hijack"]
            elif cmd == "aggressive":
                if has_air_only:
                    active_windows = ["main", "air", "hijack"]
                elif has_air:
                    active_windows = ["main", "air", "scan", "hijack"]
                else:
                    active_windows = ["main", "scan", "hijack"]
            else:
                active_windows = ["main", "air", "scan", "hijack"]

            if init_xterm(active_windows=active_windows):
                count = len(active_windows)
                print(colorize_brackets(f"[+] Multi-Window Xterm UI active ({count} centered window{'s' if count != 1 else ''} spawned)."))

        cmd = getattr(args, "command", "")
        trace(f"[FEATURE] Running subcommand '{cmd}' (Original MAC: {getattr(args, 'original_mac', False)})")
        result = args.func(args)
        if cmd in ("aggressive", "simple"):
            if result:
                print(colorize_brackets(f"\n{BOLD}{GREEN}[+] Operation Complete: Internet Access Granted!{RESET}\n"))
            else:
                print(colorize_brackets(f"\n{BOLD}{RED}[-] Operation Complete: No Internet Access Secured.{RESET}\n"))
                iface_arg = getattr(args, "interface", None)
                prof_arg = getattr(args, "profile", None)
                from cafe_chameleon.network.nmcli import release_interface
                release_interface(interface=iface_arg, profile=prof_arg)

    except KeyboardInterrupt:
        trace("[FEATURE] Process interrupted by user (Ctrl+C).")
        restore_and_exit("Process interrupted by user (Ctrl+C).")
    except Exception as e:
        import traceback
        if get_debug_tracing():
            log_exception_to_trace(e)
            recent_traces = get_recent_trace(12)
            print(f"\n{BOLD}{RED}=== TRACING SUMMARY (Last Operations Before Failure) ==={RESET}")
            for t in recent_traces:
                print(f"  {t}")
            print(f"{BOLD}{RED}Full trace log saved to: {get_trace_filepath()}{RESET}\n")
        print(f"\n{BOLD}{RED}=== UNHANDLED EXCEPTION TRACEBACK ==={RESET}")
        traceback.print_exc()
        print(f"{BOLD}{RED}====================================={RESET}\n")
        restore_and_exit(f"Unhandled error: {e}")


if __name__ == "__main__":
    main()
