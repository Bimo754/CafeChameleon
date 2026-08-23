#!/usr/bin/env python3
"""
cafe_chameleon.ui.animation - Timed ASCII Chameleon Animation with 4 Selectable Cybersecurity Color Themes.
"""

import colorsys
import math
import os
import random
import shutil
import signal
import subprocess
import sys
import time

# --- 4 CURATED CYBERSECURITY COLOR PALETTES ---
PALETTES = {
    1: {
        "name": "Cyberpunk Neon",
        "description": "Electric Cyan -> Vivid Neon Purple",
        "start_hue": 0.51,
        "finish_hue": 0.77,
    },
    2: {
        "name": "Matrix Terminal",
        "description": "Hacker Emerald Green -> Electric Cyber Cyan",
        "start_hue": 0.38,
        "finish_hue": 0.51,
    },
    3: {
        "name": "Solar Flare Ember",
        "description": "Deep Ruby Crimson -> Warm Terracotta Gold",
        "start_hue": 0.96,
        "finish_hue": 0.09,
    },
    4: {
        "name": "Midnight Sapphire",
        "description": "Deep Ocean Blue -> Liquid Platinum Gold",
        "start_hue": 0.60,
        "finish_hue": 0.13,
    },
}

# --- DETAILED ASCII BANNER SEGMENTATION ---
# Format: (left_wordmark, left_stick, cham_part1, mid_stick, cham_part2, right_stick, right_wordmark)
DETAILED_BANNER = [
    ("", "", r"                                       _       _._", "", "", "", ""),
    ("", "", r"                                _,,-''' ''-,_ }'._''.,_.=._", "", "", "", ""),
    ("", "", r"                             ,-'      _ _    '        (  {EYE})'-,", "", "", "", ""),
    ("", "", r"                           ,'  _..==;;::_::'-     __..----'''}", "", "", "", ""),
    ("", "", r"                          :  .'::_;==''       ,'',: : : '' '}", "", "", "", ""),
    ("", "", r"                         }  '::-'            /   },: : : :_,'", "", "", "", ""),
    ("", "", r"                        :  :'     _..,,_    '., '._-,,,--\\'", "", "", r"    _", ""),
    # Line 7 Precision Split: Leg -> Stick "__" -> Claw "\\.\\" -> Stick "_.-'"
    ("", "", "                       :  ;   .-'       :      '-, ';,", "__", "\\.\\", r"_.-'", ""),
    # Line 8 Precision Split: Body -> Stick "___" -> Hind Foot "}^}" -> Stick "_.-'"
    ("", "", r"                      {   '  :    _,,,   :__,,--::',,}", "___", r"}^}", r"_.-'", ""),
    ("", "", r"                      }        _,'__''',  ;", "", "", r"_.-''_.-'", ""),
    ("", "", r"                     :      ,':-''  ';, ;", "", "", r"  ;_..-'", ""),
    ("", r"                 _.-'", r" }    ,',' ,''',  : ^^", "", "", "", ""),
    ("", r"                 _.-''", r"{    { ; ; ,', '  :", "", "", "", ""),
    (r"    ______      ____  ", "", r"}   } :  ;_,' ;  }", "", "", "", r"  ________                         __"),
    (r"   / ____/___ _/ __/__ ", "", r"{   ',',___,'   '", "", "", "", r" / ____/ /_  ____ _____ ___  ___  / /__  ____  ____"),
    (r"  / /   / __ `/ /_/ _ \ ", "", r"',           ,'", "", "", "", r" / /   / __ \/ __ `/ __ `__ \/ _ \/ / _ \/ __ \/ __ \\"),
    (r" / /___/ /_/ / __/  __/   ", "", r"'-,,__,,-'", "", "", "", r"   / /___/ / / / /_/ / / / / / /  __/ /  __/ /_/ / / / /"),
    (r" \____/\__,_/_/  \___/                 ", "", r"", "", "", "", r"\____/_/ /_/\__,_/_/ /_/ /_/\___/_/\___/\____/_/ /_/")
]

# Solid dark wood/bark color for the stick (excluded from cloaking & color-shifts)
STICK_COLOR = "\033[38;2;135;105;85m"
# Authentic Cybersecurity Hexadecimal & Binary Bitmask Tokens
CYBERSEC_TOKENS = ['0', '1', 'x', 'F', 'A', '7', 'E', '9', '#', '%']


def natural_ease(p: float) -> float:
    """Natural organic S-curve easing (smooth acceleration & deceleration)."""
    return (1.0 - math.cos(math.pi * max(0.0, min(1.0, p)))) / 2.0


def get_eye_char(t: float) -> tuple[str, str]:
    """Organic Spaced Eye Blink Timeline."""
    if 0.70 <= t < 0.90:
        p = (t - 0.70) / 0.20
        if p < 0.25:
            return "o", "Blink 1 (Closing)"
        elif p < 0.75:
            return "-", "Blink 1 (Closed)"
        else:
            return "o", "Blink 1 (Opening)"

    elif 1.95 <= t < 2.15:
        p = (t - 1.95) / 0.20
        if p < 0.25:
            return "o", "Blink 2 (Closing)"
        elif p < 0.75:
            return "-", "Blink 2 (Closed)"
        else:
            return "o", "Blink 2 (Opening)"

    elif 2.40 <= t < 2.60:
        p = (t - 2.40) / 0.20
        if p < 0.25:
            return "o", "Blink 3 (Closing)"
        elif p < 0.75:
            return "-", "Blink 3 (Closed)"
        else:
            return "o", "Blink 3 (Opening)"

    elif 3.70 <= t < 3.90:
        p = (t - 3.70) / 0.20
        if p < 0.25:
            return "o", "Blink 4 (Closing)"
        elif p < 0.75:
            return "-", "Blink 4 (Closed)"
        else:
            return "o", "Blink 4 (Opening)"

    return "@", "Open"


def get_pigment_correction_state(elapsed: float) -> tuple[str, float]:
    """Pigment Correction Timeline."""
    if 3.50 <= elapsed < 3.65:
        return "imperfection", 1.0
    elif 3.65 <= elapsed < 3.85:
        p = (elapsed - 3.65) / 0.20
        intensity = math.sin(math.pi * p)
        return "correction_1", intensity
    elif 3.90 <= elapsed < 4.05:
        p = (elapsed - 3.90) / 0.15
        intensity = math.sin(math.pi * p)
        return "correction_2", intensity
    elif elapsed >= 4.05:
        return "pristine", 0.0

    return "normal", 0.0


def render_subtle_energy_wordmark(
    text: str, elapsed: float, start_hue: float = 0.38, finish_hue: float = 0.09
) -> str:
    """Wordmark Animation (Ultra-Fast 300ms Single-Character Cyber Glitch)."""
    if not text:
        return ""

    if elapsed < 4.100:
        r, g, b = colorsys.hls_to_rgb(start_hue, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"
        return f"{base_color}{text}\033[0m"

    non_space_indices = [i for i, c in enumerate(text) if c != ' ']
    if not non_space_indices:
        r, g, b = colorsys.hls_to_rgb(start_hue, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"
        return f"{base_color}{text}\033[0m"

    if 4.100 <= elapsed < 4.200:
        p_burst = (elapsed - 4.100) / 0.100
        current_hue = start_hue + 0.50 * p_burst * (finish_hue - start_hue)
        r, g, b = colorsys.hls_to_rgb(current_hue % 1.0, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"

        seed = int(elapsed * 100)
        target_idx = non_space_indices[(hash(seed) % len(non_space_indices))]

        res = []
        for idx, ch in enumerate(text):
            if idx == target_idx:
                glitch_char = random.choice(CYBERSEC_TOKENS)
                res.append(f"\033[38;5;226;1m{glitch_char}{base_color}")
            else:
                res.append(ch)
        return f"{base_color}{''.join(res)}\033[0m"

    elif 4.200 <= elapsed < 4.230:
        current_hue = start_hue + 0.50 * (finish_hue - start_hue)
        r, g, b = colorsys.hls_to_rgb(current_hue % 1.0, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"
        return f"{base_color}{text}\033[0m"

    elif 4.230 <= elapsed < 4.300:
        p_burst = (elapsed - 4.230) / 0.070
        current_hue = start_hue + (0.50 + 0.35 * p_burst) * (finish_hue - start_hue)
        r, g, b = colorsys.hls_to_rgb(current_hue % 1.0, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"

        seed = int(elapsed * 100)
        target_idx = non_space_indices[(hash(seed) % len(non_space_indices))]

        res = []
        for idx, ch in enumerate(text):
            if idx == target_idx:
                glitch_char = random.choice(CYBERSEC_TOKENS)
                res.append(f"\033[38;5;51;1m{glitch_char}{base_color}")
            else:
                res.append(ch)
        return f"{base_color}{''.join(res)}\033[0m"

    elif 4.300 <= elapsed < 4.330:
        current_hue = start_hue + 0.85 * (finish_hue - start_hue)
        r, g, b = colorsys.hls_to_rgb(current_hue % 1.0, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"
        return f"{base_color}{text}\033[0m"

    elif 4.330 <= elapsed < 4.400:
        p_burst = (elapsed - 4.330) / 0.070
        current_hue = start_hue + (0.85 + 0.15 * p_burst) * (finish_hue - start_hue)
        r, g, b = colorsys.hls_to_rgb(current_hue % 1.0, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"

        seed = int(elapsed * 100)
        target_idx = non_space_indices[(hash(seed) % len(non_space_indices))]

        res = []
        for idx, ch in enumerate(text):
            if idx == target_idx:
                glitch_char = random.choice(CYBERSEC_TOKENS)
                res.append(f"\033[38;5;230;1m{glitch_char}{base_color}")
            else:
                res.append(ch)
        return f"{base_color}{''.join(res)}\033[0m"

    else:
        r, g, b = colorsys.hls_to_rgb(finish_hue, 0.42, 0.64)
        base_color = f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m"
        return f"{base_color}{text}\033[0m"


def render_cloaked_segment(
    segment_text: str, eye_char: str, elapsed: float, line_idx: int, total_lines: int = 18, start_hue: float = 0.38, finish_hue: float = 0.09
) -> tuple[str, str]:
    """Renders a chameleon body segment."""
    if not segment_text:
        return "", "Empty"

    correction_state, correction_int = get_pigment_correction_state(elapsed)
    is_cloaking = (1.00 <= elapsed <= 3.50)

    if "{EYE}" in segment_text:
        parts = segment_text.split("{EYE}")
        rendered_left, _ = render_cloaked_segment(parts[0], eye_char, elapsed, line_idx, total_lines, start_hue, finish_hue)
        rendered_right, _ = render_cloaked_segment(parts[1], eye_char, elapsed, line_idx, total_lines, start_hue, finish_hue)

        if correction_state in ("correction_1", "correction_2"):
            subtle_hue = (finish_hue + (0.05 * correction_int)) % 1.0
            r_s, g_s, b_s = colorsys.hls_to_rgb(subtle_hue, 0.58, 0.85)
            eye_color = f"\033[38;2;{int(r_s * 255)};{int(g_s * 255)};{int(b_s * 255)}m\033[1m"
        elif is_cloaking:
            p_eye = (elapsed - 1.00) / 2.50
            p_ease = natural_ease(p_eye)
            eye_hue = start_hue + p_ease * (finish_hue - start_hue)
            r_e, g_e, b_e = colorsys.hls_to_rgb(eye_hue, 0.54, 0.80)
            eye_color = f"\033[38;2;{int(r_e * 255)};{int(g_e * 255)};{int(b_e * 255)}m"
        elif elapsed > 3.50:
            r_e, g_e, b_e = colorsys.hls_to_rgb(finish_hue, 0.54, 0.80)
            eye_color = f"\033[38;2;{int(r_e * 255)};{int(g_e * 255)};{int(b_e * 255)}m"
        else:
            r_e, g_e, b_e = colorsys.hls_to_rgb(start_hue, 0.54, 0.80)
            eye_color = f"\033[38;2;{int(r_e * 255)};{int(g_e * 255)};{int(b_e * 255)}m"

        return rendered_left + f"{eye_color}{eye_char}\033[0m" + rendered_right, "Eye Socket"

    if correction_state != "normal" and elapsed >= 3.50:
        res = []
        for col_idx, ch in enumerate(segment_text):
            if ch == ' ':
                res.append(' ')
                continue

            is_primary_mismatch = (hash((col_idx, line_idx)) % 7 == 0)
            is_secondary_mismatch = (hash((col_idx + 3, line_idx)) % 11 == 0)

            if correction_state == "imperfection":
                if is_primary_mismatch:
                    r, g, b = colorsys.hls_to_rgb(start_hue, 0.48, 0.70)
                    res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m\033[1m{ch}\033[0m")
                else:
                    r, g, b = colorsys.hls_to_rgb(finish_hue, 0.42, 0.64)
                    res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m{ch}\033[0m")

            elif correction_state == "correction_1":
                if is_primary_mismatch:
                    current_spot_hue = start_hue + correction_int * (finish_hue - start_hue)
                    r, g, b = colorsys.hls_to_rgb(current_spot_hue % 1.0, 0.52 + 0.15 * correction_int, 0.85)
                    res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m\033[1m{ch}\033[0m")
                else:
                    r, g, b = colorsys.hls_to_rgb(finish_hue, 0.42, 0.64)
                    res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m{ch}\033[0m")

            elif correction_state == "correction_2":
                if is_secondary_mismatch:
                    current_spot_hue = finish_hue + 0.05 * (1.0 - correction_int)
                    r, g, b = colorsys.hls_to_rgb(current_spot_hue % 1.0, 0.50 + 0.10 * correction_int, 0.80)
                    res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m\033[1m{ch}\033[0m")
                else:
                    r, g, b = colorsys.hls_to_rgb(finish_hue, 0.42, 0.64)
                    res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m{ch}\033[0m")

            else:
                r, g, b = colorsys.hls_to_rgb(finish_hue, 0.42, 0.64)
                res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m{ch}\033[0m")

        status_msg = (
            "Pigment Imperfections" if correction_state == "imperfection" else
            "Chromatophore Correction" if correction_state == "correction_1" else
            "Fine-Tuning Pigment Adjustment" if correction_state == "correction_2" else
            "Pristine Adapted Stance"
        )
        return "".join(res), status_msg

    res = []
    v_norm = line_idx / max(1, total_lines - 1)

    for col_idx, ch in enumerate(segment_text):
        if ch == ' ':
            res.append(' ')
            continue

        wave_long = math.sin(line_idx * 0.45 + col_idx * 0.12 + elapsed * 2.5) * 0.035
        wave_trans = math.cos(line_idx * 0.20 - col_idx * 0.30 + elapsed * 1.8) * 0.025
        contour_shift = wave_long + wave_trans

        is_crest = ch in "-^='_."

        if elapsed < 1.00:
            char_hue = (start_hue + contour_shift) % 1.0
            lum = 0.54 if is_crest else 0.42
            r, g, b = colorsys.hls_to_rgb(char_hue, lum, 0.64)
            res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m{ch}\033[0m")

        else:
            h_norm = col_idx / 60.0
            dy = (v_norm - 0.45) / 0.45
            dx = (h_norm - 0.50) / 0.50
            radial_dist = math.sqrt(dx * dx + dy * dy)

            if 1.00 <= elapsed < 1.85:
                p_cloak = (elapsed - 1.00) / 0.85
                wave_front = p_cloak * 1.5
                depth = max(0.0, min(1.0, (wave_front - radial_dist) / 0.3))
                current_hue = start_hue
            elif 1.85 <= elapsed <= 2.65:
                depth = 1.0
                current_hue = start_hue
            else:
                p_reemerge = (elapsed - 2.65) / 0.85
                p_ease = natural_ease(p_reemerge)
                current_hue = start_hue + p_ease * (finish_hue - start_hue)
                wave_front = p_reemerge * 1.5
                depth = max(0.0, min(1.0, 1.0 - ((wave_front - radial_dist) / 0.3)))

            char_hue = (current_hue + contour_shift) % 1.0
            is_wave_edge = (0.35 <= depth <= 0.65)

            if is_wave_edge:
                lum = 0.76 if is_crest else 0.64
                sat = 0.90
                r, g, b = colorsys.hls_to_rgb(char_hue, lum, sat)
                res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m\033[1m{ch}\033[0m")
            else:
                base_l = 0.54 if is_crest else 0.42
                stealth_l = max(0.07, base_l - (0.34 * depth))
                stealth_s = max(0.15, 0.64 - (0.40 * depth))
                r, g, b = colorsys.hls_to_rgb(char_hue, stealth_l, stealth_s)
                res.append(f"\033[38;2;{int(r * 255)};{int(g * 255)};{int(b * 255)}m{ch}\033[0m")

    mode_str = "100% Full Stealth Cloak" if (1.85 <= elapsed <= 2.65) else ("Active Cloak Transition" if (1.00 <= elapsed <= 3.50) else "Standard Stance")
    return "".join(res), mode_str


def cleanup_and_exit(sig=None, frame=None):
    """Clean terminal state on interrupt or exit."""
    try:
        sys.stdout.write("\033[?25h\033[0m\n")  # Restore cursor and text formatting
        sys.stdout.flush()
    except Exception:
        pass
    sys.exit(0)


def run_animation_single(palette_id: int, debug: bool = False):
    """Run a single 6.0s animation cycle for a given palette ID, rendered dead-center."""
    p_info = PALETTES.get(palette_id, PALETTES[1])
    p_name = p_info["name"]
    start_hue = p_info["start_hue"]
    finish_hue = p_info["finish_hue"]

    # Hide cursor
    sys.stdout.write("\033[?25l\033[2J")
    sys.stdout.flush()

    fps_target = 60.0
    frame_time = 1.0 / fps_target
    total_duration = 6.0  # Exactly 6.0 seconds

    # ANSI Formatting
    RESET = "\033[0m"
    CYAN_TITLE = "\033[38;5;73m"
    DIM = "\033[2m"

    t_start = time.monotonic()

    banner_max_width = 89  # Max line width of the ASCII banner
    banner_total_height = len(DETAILED_BANNER) + (3 if debug else 0)

    try:
        while True:
            t_now = time.monotonic()
            elapsed = t_now - t_start

            if elapsed >= total_duration:
                break

            # Query current terminal size for dynamic dead-center alignment
            term_cols, term_rows = shutil.get_terminal_size((100, 35))
            top_padding = max(0, (term_rows - banner_total_height) // 2)
            left_padding = max(0, (term_cols - banner_max_width) // 2)
            left_indent = " " * left_padding

            # Calculate timeline states
            eye_char, eye_label = get_eye_char(elapsed)

            rendered_lines = []
            if debug:
                _, camo_label = render_cloaked_segment("", eye_char, elapsed, line_idx=0, start_hue=start_hue, finish_hue=finish_hue)
                rendered_lines.append(f"{CYAN_TITLE}--- CafeChameleon (Palette {palette_id}: {p_name}) ---{RESET}")
                rendered_lines.append(f"{DIM}Time: {elapsed:4.2f}s / {total_duration:4.2f}s | Eye: '{eye_char}' ({eye_label}) | Status: {camo_label}{RESET}")
                rendered_lines.append("")

            # Render Full Banner
            total_lines = len(DETAILED_BANNER)
            for i, (left_text, left_stick, cham_part1, mid_stick, cham_part2, right_stick, right_text) in enumerate(DETAILED_BANNER):
                rendered_cham1, _ = render_cloaked_segment(
                    cham_part1, eye_char, elapsed, line_idx=i, total_lines=total_lines, start_hue=start_hue, finish_hue=finish_hue
                )
                rendered_cham2, _ = render_cloaked_segment(
                    cham_part2, eye_char, elapsed, line_idx=i, total_lines=total_lines, start_hue=start_hue, finish_hue=finish_hue
                )

                rendered_left_text = render_subtle_energy_wordmark(left_text, elapsed, start_hue=start_hue, finish_hue=finish_hue) if left_text else ""
                rendered_right_text = render_subtle_energy_wordmark(right_text, elapsed, start_hue=start_hue, finish_hue=finish_hue) if right_text else ""

                rendered_left_stick = f"{STICK_COLOR}{left_stick}{RESET}" if left_stick else ""
                rendered_mid_stick = f"{STICK_COLOR}{mid_stick}{RESET}" if mid_stick else ""
                rendered_right_stick = f"{STICK_COLOR}{right_stick}{RESET}" if right_stick else ""

                rendered_lines.append(
                    f"{rendered_left_text}{rendered_left_stick}{rendered_cham1}{rendered_mid_stick}{rendered_cham2}{rendered_right_stick}{rendered_right_text}"
                )

            # Build double-buffered centered frame string
            output_buffer = ["\033[H"]  # Reset cursor to top-left (1,1)
            output_buffer.append("\033[K\n" * top_padding)
            for line in rendered_lines:
                output_buffer.append(f"\033[K{left_indent}{line}\n")
            output_buffer.append("\033[J")

            # Write buffer atomically
            sys.stdout.write("".join(output_buffer))
            sys.stdout.flush()

            # 60 FPS Target Loop Synchronization
            t_exec = time.monotonic() - t_now
            sleep_duration = frame_time - t_exec
            if sleep_duration > 0:
                time.sleep(sleep_duration)

    finally:
        sys.stdout.write("\033[?25h\033[0m\n")
        sys.stdout.flush()


def run_all_palettes(debug: bool = False):
    """Sequentially showcases all 4 cybersecurity color palettes back-to-back!"""
    for pid in range(1, 5):
        run_animation_single(pid, debug=debug)
        time.sleep(0.4)


def run_main_logic():
    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    debug_flag = any(arg in ("--debug", "-d") for arg in sys.argv[1:])
    non_debug_args = [arg for arg in sys.argv[1:] if arg not in ("--debug", "-d")]

    # Check CLI Arguments
    if non_debug_args:
        arg = non_debug_args[0].lower().strip()
        if arg in ("all", "a"):
            run_all_palettes(debug=debug_flag)
            return
        elif arg in ("random", "r"):
            run_animation_single(random.choice(list(PALETTES.keys())), debug=debug_flag)
            return
        elif arg.isdigit() and int(arg) in PALETTES:
            run_animation_single(int(arg), debug=debug_flag)
            return

    # Interactive Terminal Selection Menu
    sys.stdout.write("\033[2J\033[H")
    print("\033[38;5;73;1m=== CafeChameleon Cybersecurity Color Theme Picker ===\033[0m\n")
    for pid, p in PALETTES.items():
        print(f"  \033[1m[{pid}]\033[0m {p['name']:20s} - {p['description']}")
    print("  \033[1m[R]\033[0m Play RANDOM Theme")
    print("  \033[1m[A]\033[0m Showcase ALL 4 Themes (Play back-to-back)")
    print("\n\033[2mSelect an option (1-4, R, or A): \033[0m", end="", flush=True)

    try:
        choice = sys.stdin.readline().strip().lower()
        if choice in ("a", "all"):
            run_all_palettes(debug=debug_flag)
        elif choice in ("r", "random"):
            run_animation_single(random.choice(list(PALETTES.keys())), debug=debug_flag)
        elif choice.isdigit() and int(choice) in PALETTES:
            run_animation_single(int(choice), debug=debug_flag)
        else:
            print("\033[31mInvalid choice. Running random option...\033[0m")
            time.sleep(1)
            run_animation_single(random.choice(list(PALETTES.keys())), debug=debug_flag)
    except Exception:
        run_animation_single(random.choice(list(PALETTES.keys())), debug=debug_flag)


def spawn_xterm_and_run():
    """Spawns dedicated xterm window matching tool styling to run animation."""
    from cafe_chameleon.ui.xterm.screen import get_screen_resolution
    sw, sh = get_screen_resolution()

    target_w = int(sw * 0.70)
    target_h = int(sh * 0.70)
    cols = max(100, int(target_w / 9.6))
    rows = max(34, int(target_h / 19.0))
    x_offset = max(0, (sw - target_w) // 2)
    y_offset = max(0, (sh - target_h) // 2)

    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    env = dict(os.environ)
    existing_ppath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{repo_dir}:{existing_ppath}" if existing_ppath else repo_dir
    env["CAFE_ANIMATION_XTERM"] = "1"

    args_list = sys.argv[1:]
    cmd_args = " ".join([f"'{a}'" if " " in a else a for a in args_list])
    inner_cmd = f"CAFE_ANIMATION_XTERM=1 PYTHONPATH='{env['PYTHONPATH']}' {sys.executable} -m cafe_chameleon.ui.animation {cmd_args}"

    xterm_cmd = [
        "xterm",
        "-title", "Captive Network Toolkit - Chameleon Animation",
        "-geometry", f"{cols}x{rows}+{x_offset}+{y_offset}",
        "-bg", "#000000",
        "-fg", "#00ffc8",
        "-fa", "Monospace",
        "-fs", "11",
        "-tn", "xterm-256color",
        "-e", f"sh -c '{inner_cmd}'"
    ]

    try:
        subprocess.run(xterm_cmd, env=env)
    except Exception:
        run_main_logic()


def main():
    already_in_xterm = os.environ.get("CAFE_ANIMATION_XTERM") == "1"
    can_launch_xterm = (
        bool(os.environ.get("DISPLAY"))
        and bool(shutil.which("xterm"))
    )

    if not already_in_xterm and can_launch_xterm:
        spawn_xterm_and_run()
    else:
        run_main_logic()


def run_animation_subcommand(args):
    """Hidden subcommand handler for running test animation through main.py."""
    palette_arg = getattr(args, "palette", "random")
    debug_flag = bool(getattr(args, "debug", False) or getattr(args, "debug_short", False))

    new_argv = [sys.argv[0], palette_arg]
    if debug_flag:
        new_argv.append("--debug")
    sys.argv = new_argv

    main()
    return True


if __name__ == "__main__":
    main()
