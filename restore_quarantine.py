"""
restore_quarantine.py  —  Smart Quarantine Restore Tool
────────────────────────────────────────────────────────
Works even when NO manifest exists (old quarantine runs).

Discovery strategies (tried in order per file):
  1. quarantine_manifest.json  — exact original path recorded by new engine
  2. Windows registry / PATH   — `where` command + KnownDLLs registry key
  3. Drive-wide name search    — finds folders already containing same filename
  4. Extension heuristics      — known default locations per file type
  5. Manual fallback           — asks you if all four above fail
"""

import os
import sys
import re
import json
import shutil
import platform
import subprocess
import time
from datetime import datetime


IS_WINDOWS = platform.system() == "Windows"

# Timestamp prefix the AV engine stamps onto quarantined filenames
_STAMP = re.compile(r"^\d{8}_\d{6}_\d+_")

# Extension → ordered list of most-likely parent directories
EXTENSION_HINTS = {
    ".dll":  ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Windows"],
    ".sys":  ["C:\\Windows\\System32\\drivers", "C:\\Windows\\SysWOW64\\drivers"],
    ".exe":  ["C:\\Windows\\System32", "C:\\Windows", "C:\\Program Files",
               "C:\\Program Files (x86)"],
    ".ocx":  ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
    ".cpl":  ["C:\\Windows\\System32"],
    ".msc":  ["C:\\Windows\\System32"],
    ".drv":  ["C:\\Windows\\System32"],
    ".bat":  ["C:\\Windows\\System32", "C:\\Windows"],
    ".ps1":  ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0"],
    ".inf":  ["C:\\Windows\\INF"],
    ".so":   ["/usr/lib", "/usr/local/lib", "/lib"],
    ".sh":   ["/usr/local/bin", "/usr/bin", "/bin"],
}

# Directories to never descend into during the drive-wide search
SEARCH_SKIP_BASENAMES = {
    "system volume information", "$recycle.bin",
    "$windows.~bt", "$windows.~ws", "winsxs", "servicing",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_qname(qname):
    """
    Strip timestamp prefix + .quarantine suffix → original filename.
    '20250601_142310_123456_kernel32.dll.quarantine' → 'kernel32.dll'
    Returns None if it doesn't look like a quarantine file.
    """
    if not qname.endswith(".quarantine"):
        return None
    return _STAMP.sub("", qname[:-len(".quarantine")]) or None


def get_search_roots():
    """All real drives / mount points on this machine."""
    if IS_WINDOWS:
        import string
        return [f"{l}:\\" for l in string.ascii_uppercase
                if os.path.exists(f"{l}:\\")]
    try:
        import psutil
        return [p.mountpoint for p in psutil.disk_partitions(all=False)
                if p.fstype not in ("tmpfs","devtmpfs","proc","sysfs",
                                    "cgroup","devpts","squashfs")]
    except Exception:
        return ["/"]


# ── Discovery strategies ──────────────────────────────────────────────────────

def strategy_manifest(manifest, qname):
    """Strategy 1 — look up exact original path in the manifest JSON."""
    return manifest.get(qname)


def strategy_windows_lookup(filename):
    """
    Strategy 2 — ask Windows where this file lives.
    Uses `where` (searches PATH) and the KnownDLLs registry key.
    Returns the best matching directory, or None.
    """
    if not IS_WINDOWS:
        return None
    # `where` searches every directory on %PATH%
    try:
        out = subprocess.check_output(
            ["where", filename], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.strip().splitlines():
            d = os.path.dirname(line.strip())
            if d and os.path.isdir(d):
                return d
    except Exception:
        pass
    # KnownDLLs registry — lists DLLs Windows loads from System32
    try:
        import winreg
        key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            i = 0
            while True:
                try:
                    _, val, _ = winreg.EnumValue(key, i)
                    if val.lower() == filename.lower():
                        sys32 = os.path.join(
                            os.environ.get("SystemRoot", "C:\\Windows"), "System32")
                        return sys32
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return None


def strategy_drive_search(filename, search_roots):
    """
    Strategy 3 — walk all drives looking for a folder that already contains
    a file with this exact name.  Returns the best directory found, or None.
    Displays a live counter so the user knows it's working.
    """
    name_lower  = filename.lower()
    matches     = []
    scanned     = [0]

    sys.stdout.write(f"    🔍 Searching drives for '{filename}' ")
    sys.stdout.flush()
    last_tick = [time.time()]

    for root in search_roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(
                root, topdown=True, onerror=lambda e: None, followlinks=False):

            # Prune dirs we should never enter
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in SEARCH_SKIP_BASENAMES
            ]

            scanned[0] += len(filenames)
            if time.time() - last_tick[0] > 0.5:
                sys.stdout.write(".")
                sys.stdout.flush()
                last_tick[0] = time.time()

            for fname in filenames:
                if fname.lower() == name_lower:
                    matches.append(os.path.abspath(dirpath))

    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

    if not matches:
        return None

    # Prefer System32 / SysWOW64 for system-looking files
    if IS_WINDOWS:
        sys_root = os.environ.get("SystemRoot", "C:\\Windows").lower()
        sys_hits = [d for d in matches if d.lower().startswith(sys_root)]
        if sys_hits:
            return sys_hits[0]

    return matches[0]


def strategy_heuristic(filename):
    """
    Strategy 4 — return the best-guess directory based on file extension.
    Only returns paths that actually exist on this machine.
    """
    ext = os.path.splitext(filename)[1].lower()
    for path in EXTENSION_HINTS.get(ext, []):
        if os.path.isdir(path):
            return path
    return None


def find_original_dir(qname, original_name, manifest, search_roots):
    """
    Run all four strategies and return (directory, confidence_label).
    confidence_label is shown to the user so they know how certain we are.
    """
    # 1 — manifest (exact record)
    recorded = strategy_manifest(manifest, qname)
    if recorded:
        d = os.path.dirname(recorded)
        if d:
            return d, "✅ Exact  (manifest record)"

    # 2 — Windows registry / PATH
    d = strategy_windows_lookup(original_name)
    if d:
        return d, "✅ Certain  (Windows registry / PATH)"

    # 3 — drive-wide search
    d = strategy_drive_search(original_name, search_roots)
    if d:
        return d, "🟢 Likely  (found matching file on drive)"

    # 4 — heuristic
    d = strategy_heuristic(original_name)
    if d:
        return d, "🟡 Estimated  (extension heuristic)"

    return None, "❓ Unknown"


# ── Restore logic ─────────────────────────────────────────────────────────────

def restore_file(src, dest_dir, original_name):
    """Move src → dest_dir/original_name with permissions restored."""
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, original_name)

    # Avoid silently overwriting — stamp a suffix if the file already exists
    if os.path.exists(dest):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(original_name)
        dest = os.path.join(dest_dir, f"{name}_restored_{stamp}{ext}")

    try:
        try:
            os.chmod(src, 0o755 if not IS_WINDOWS else 0o644)
        except Exception:
            pass
        shutil.move(src, dest)
        return True, dest
    except PermissionError:
        return False, "access denied — run as Administrator"
    except Exception as e:
        return False, str(e)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║   🛡️   MINI-AV  ·  SMART QUARANTINE RESTORE TOOL    ║")
    print("╚══════════════════════════════════════════════════════╝\n")
    print("  This tool recovers quarantined files even without a manifest.")
    print("  It tries 4 automatic strategies before asking you anything.\n")

    # ── Step 1: Quarantine folder ─────────────────────────────────────────────
    default_dir = os.path.abspath("./av_quarantine")
    print(f"  Default quarantine folder: {default_dir}")
    raw = input("  Press ENTER to use it, or type a different path: ").strip()
    quarantine_dir = os.path.abspath(raw) if raw else default_dir

    if not os.path.isdir(quarantine_dir):
        print(f"\n  ❌  Folder not found: {quarantine_dir}")
        sys.exit(1)

    # ── Step 2: Load manifest if it exists ───────────────────────────────────
    manifest_path = os.path.join(quarantine_dir, "quarantine_manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            print(f"\n  📋  Manifest found — {len(manifest)} record(s) loaded.")
        except Exception:
            print("\n  ⚠️   Manifest found but could not be read — will use other strategies.")
    else:
        print("\n  ℹ️   No manifest found — will use automatic discovery strategies.")

    # ── Step 3: Collect quarantine files ─────────────────────────────────────
    entries = []
    for fname in sorted(os.listdir(quarantine_dir)):
        fpath = os.path.join(quarantine_dir, fname)
        if not os.path.isfile(fpath) or fname == "quarantine_manifest.json":
            continue
        original = parse_qname(fname)
        if original:
            entries.append((fpath, fname, original))

    if not entries:
        print("\n  ℹ️   No .quarantine files found.")
        sys.exit(0)

    print(f"\n  Found {len(entries)} quarantined file(s):\n")
    print(f"  {'#':<5}  {'Original filename':<40}")
    print(f"  {'─'*5}  {'─'*40}")
    for i, (_, _, original) in enumerate(entries, 1):
        print(f"  {i:<5}  {original}")

    # ── Step 4: Scope selection ───────────────────────────────────────────────
    print("\n  Restore scope:")
    print("  A  — Restore ALL files automatically")
    print("  S  — Select specific files by number")
    print("  Q  — Quit")
    scope = input("\n  Choice (A/S/Q): ").strip().upper()

    if scope == "Q":
        sys.exit(0)
    elif scope == "S":
        raw_nums = input("  File numbers (e.g. 1 3 5): ").strip()
        try:
            chosen = {int(x) for x in raw_nums.split()}
        except ValueError:
            print("  ❌  Invalid input.")
            sys.exit(1)
        selected = [(qp, qn, orig) for i, (qp, qn, orig) in enumerate(entries, 1)
                    if i in chosen]
    else:
        selected = entries

    if not selected:
        print("  No files selected.")
        sys.exit(0)

    # ── Step 5: Discover & restore ────────────────────────────────────────────
    search_roots = get_search_roots()

    print(f"\n{'═'*60}")
    print(f"  Processing {len(selected)} file(s)…")
    print(f"{'═'*60}\n")

    restored = skipped = failed = 0

    for qpath, qname, original_name in selected:
        print(f"  📄  {original_name}")

        dest_dir, confidence = find_original_dir(
            qname, original_name, manifest, search_roots)

        if dest_dir:
            print(f"    Destination : {dest_dir}")
            print(f"    Confidence  : {confidence}")

            # For heuristic guesses, let the user confirm or override
            if "Estimated" in confidence or "Unknown" in confidence:
                override = input(
                    "    Press ENTER to accept, or type a different path: "
                ).strip()
                if override:
                    dest_dir = os.path.abspath(override)

            ok, detail = restore_file(qpath, dest_dir, original_name)
            if ok:
                print(f"    ✅  Restored → {detail}")
                # Remove from manifest once done
                if qname in manifest:
                    manifest.pop(qname)
                    try:
                        with open(manifest_path, "w", encoding="utf-8") as f:
                            json.dump(manifest, f, indent=2)
                    except Exception:
                        pass
                restored += 1
            else:
                print(f"    ❌  Failed: {detail}")
                failed += 1

        else:
            # All four strategies failed — ask manually as last resort
            print("    ⚠️   Could not determine original location automatically.")
            manual = input("    Enter destination folder (or ENTER to skip): ").strip()
            if not manual:
                print("    ⏭️   Skipped.")
                skipped += 1
            else:
                ok, detail = restore_file(qpath, os.path.abspath(manual), original_name)
                if ok:
                    print(f"    ✅  Restored → {detail}")
                    restored += 1
                else:
                    print(f"    ❌  Failed: {detail}")
                    failed += 1

        print()

    # ── Step 6: Summary ───────────────────────────────────────────────────────
    print(f"{'═'*60}")
    print(f"  RESTORE COMPLETE")
    print(f"{'═'*60}")
    print(f"  ✅  Restored : {restored}")
    print(f"  ⏭️   Skipped  : {skipped}")
    print(f"  ❌  Failed   : {failed}")
    print(f"{'═'*60}\n")

    if restored > 0 and IS_WINDOWS:
        print("  💡  Run the following in an elevated Command Prompt to let")
        print("      Windows verify all restored system files are intact:\n")
        print("          sfc /scannow\n")


if __name__ == "__main__":
    main()
