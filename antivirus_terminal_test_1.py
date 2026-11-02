import os
import sys
import hashlib
import math
import shutil
import psutil
import platform
import string
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_all_drives():
    """
    Cross-platform drive/root discovery.
    - Windows: returns all lettered drives present (C:\\, D:\\, etc.)
    - Linux/macOS: returns filesystem mount points via psutil, falling back to '/'
    """
    system = platform.system()
    drives = []

    if system == "Windows":
        # Check every possible drive letter
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)

    else:  # Linux / macOS
        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                # Skip pseudo-filesystems and optical drives
                if p.fstype and p.fstype not in ('tmpfs', 'devtmpfs', 'squashfs',
                                                   'overlay', 'proc', 'sysfs',
                                                   'cgroup', 'cgroup2', 'pstore',
                                                   'debugfs', 'tracefs', 'hugetlbfs',
                                                   'mqueue', 'udev', 'devpts'):
                    drives.append(p.mountpoint)
        except Exception:
            drives.append("/")  # Safe fallback

    return drives if drives else ["/"]


class ProgressTracker:
    """Thread-safe, live progress display for long-running scans."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_found = 0
        self.scanned = 0
        self.flagged = 0
        self._active = False
        self._thread = None

    def start(self):
        self._active = True
        self._thread = threading.Thread(target=self._ticker, daemon=True)
        self._thread.start()

    def stop(self):
        self._active = False
        if self._thread:
            self._thread.join(timeout=2)
        # Clear the progress line
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def _ticker(self):
        while self._active:
            with self._lock:
                s = self.scanned
                f = self.flagged
            sys.stdout.write(f"\r  ⏳ Scanned: {s:>7,}  |  Flagged: {f:>5,}   ")
            sys.stdout.flush()
            time.sleep(0.4)

    def increment(self, flagged=False):
        with self._lock:
            self.scanned += 1
            if flagged:
                self.flagged += 1


class RealAVEngine:
    def __init__(self, quarantine_dir="./av_quarantine", max_workers=4):
        # ── Signature Database ────────────────────────────────────────────────
        self.known_malware_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test_Empty_File_Malware_Sig",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Mock_Password_Malware",
        }

        self.quick_scan_targets = {'.exe', '.bat', '.ps1', '.vbs', '.cmd',
                                    '.dll', '.scr', '.sh', '.msi', '.jar',
                                    '.hta', '.wsf', '.jse', '.vbe'}

        # ── Static Analysis Config ────────────────────────────────────────────
        self.suspicious_extensions = {'.vbs', '.bat', '.ps1', '.exe', '.cmd',
                                       '.scr', '.hta', '.wsf', '.jse', '.vbe'}
        self.malicious_keywords = [
            b"WScript.Shell", b"Shell.Application", b"powershell -nop",
            b"downloadstring", b"reg add", b"reg delete", b"shadowcopy delete",
            b"rmdir /s", b"bypass -w hidden", b"Invoke-Expression", b"IEX",
            b"net user /add", b"attrib +h +s", b"schtasks /create",
        ]

        # ── Runtime Config ────────────────────────────────────────────────────
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.max_workers = max_workers          # parallel file threads
        self._results_lock = threading.Lock()

        # ── Metrics ───────────────────────────────────────────────────────────
        self.scanned_count = 0
        self.killed_processes_count = 0
        self.quarantined_files_count = 0
        self.flagged_files = []                 # list of (filepath, decision, score, reasons)

        # ── Paths to always skip ──────────────────────────────────────────────
        # Only skip directories that are:
        #   (a) Windows OS internals that are ALWAYS access-denied, or
        #   (b) Linux pseudo-filesystems that aren't real files.
        # User-space paths (Downloads, AppData, Program Files, etc.) are
        # intentionally NOT skipped — those are exactly where malware hides.
        win = os.environ.get("SystemRoot", "C:\\Windows")  # respects non-C installs

        # ── Directories the walker must NEVER enter ───────────────────────────
        # Everything under C:\Windows is skipped completely — not scanned,
        # not reported, not touched. This prevents WinError 5 noise and
        # protects system stability. Malware doesn't live in Windows internals;
        # it lives in user-space paths which are still fully scanned.
        self.skip_dirs = {
            os.path.abspath(self.quarantine_dir),

            # ── Entire Windows OS tree ────────────────────────────────────────
            win,                                        # C:\Windows and everything under it

            # ── Linux / macOS OS trees ────────────────────────────────────────
            "/proc", "/sys", "/dev", "/run",
            "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/usr/lib", "/lib", "/lib64",
            "/boot", "/etc",
        }

        # Normalise to lowercase for case-insensitive matching on Windows
        self.skip_dirs = {os.path.normcase(p) for p in self.skip_dirs}

        # Directory basenames that appear on every drive and must always be skipped
        self._skip_dirnames_lower = {
            "system volume information",
            "$recycle.bin",
            "$windows.~bt",
            "$windows.~ws",
        }

        os.makedirs(self.quarantine_dir, exist_ok=True)

        # ── Access-denied log (written at end of scan) ─────────────────────
        self.access_denied_paths = []

    # ── Low-level helpers ─────────────────────────────────────────────────────

    def get_sha256(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def calculate_entropy(self, filepath):
        """Shannon entropy — values near 8.0 suggest packing/encryption."""
        try:
            with open(filepath, "rb") as f:
                data = f.read(512_000)
            if not data:
                return 0.0
            total = len(data)
            entropy = 0.0
            for x in range(256):
                p = data.count(x) / total
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    def scan_file_content(self, filepath):
        matched = []
        try:
            with open(filepath, "rb") as f:
                content = f.read(102_400)
            for kw in self.malicious_keywords:
                if kw in content:
                    matched.append(kw.decode("utf-8", errors="ignore"))
        except Exception:
            pass
        return matched

    def kill_associated_process(self, target_path):
        target_abs = os.path.abspath(target_path)
        killed = False
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if proc.info["exe"] and os.path.abspath(proc.info["exe"]) == target_abs:
                    print(f"\n    ⚠️  [ALERT] Active process PID {proc.info['pid']} — terminating…")
                    p = psutil.Process(proc.info["pid"])
                    p.terminate()
                    p.wait(timeout=3)
                    killed = True
                    with self._results_lock:
                        self.killed_processes_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                try:
                    p.kill()
                    killed = True
                    with self._results_lock:
                        self.killed_processes_count += 1
                except Exception:
                    pass
            except Exception:
                pass
        return killed

    def quarantine_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            # Stamp the filename to avoid collisions across drives
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            dest = os.path.join(self.quarantine_dir, f"{stamp}_{filename}.quarantine")
            shutil.move(filepath, dest)
            os.chmod(dest, 0o400)
            with self._results_lock:
                self.quarantined_files_count += 1
            return True
        except Exception:
            # Silently fail — no error messages printed to keep output clean.
            return False

    # ── Per-file pipeline ─────────────────────────────────────────────────────

    def process_pipeline(self, filepath):
        file_ext = os.path.splitext(filepath)[1].lower()
        heuristic_score = 0
        reasons = []

        # Step 1 — Signature check
        file_hash = self.get_sha256(filepath)
        if not file_hash:
            return "SKIPPED", 0, ["Unreadable / locked by OS"]

        if file_hash in self.known_malware_hashes:
            heuristic_score += 100
            reasons.append(f"Exact signature match: [{self.known_malware_hashes[file_hash]}]")

        # Step 2 — Static extension + keyword analysis
        if file_ext in self.suspicious_extensions:
            heuristic_score += 25
            reasons.append(f"Suspicious extension ({file_ext})")

        found_kw = self.scan_file_content(filepath)
        if found_kw:
            heuristic_score += len(found_kw) * 20
            reasons.append(f"Malicious strings found: {found_kw}")

        # Step 3 — Entropy heuristic
        entropy = self.calculate_entropy(filepath)
        if entropy > 7.2 and file_ext in {".exe", ".dll", ".scr"}:
            heuristic_score += 35
            reasons.append(f"High entropy ({entropy:.2f}) — packed/encrypted binary")
        elif entropy > 6.0 and file_ext in {".vbs", ".bat", ".ps1"}:
            heuristic_score += 30
            reasons.append(f"Elevated script entropy ({entropy:.2f}) — possible obfuscation")

        heuristic_score = min(heuristic_score, 100)

        # Step 5/7 — Decision
        if heuristic_score >= 50:
            decision = "MALICIOUS / QUARANTINED"
            self.kill_associated_process(filepath)
            self.quarantine_file(filepath)
        elif heuristic_score >= 26:
            decision = "SUSPICIOUS"
        else:
            decision = "SAFE"

        return decision, heuristic_score, reasons

    # ── Directory / Drive scanner ─────────────────────────────────────────────

    def _should_skip(self, abs_path):
        """
        Return True if this path should be excluded from scanning.
        Uses os.path.normcase so matching is case-insensitive on Windows
        (C:/WINDOWS == C:/Windows == c:/windows).
        """
        norm = os.path.normcase(abs_path)
        sep  = os.path.normcase(os.sep)
        for skip in self.skip_dirs:
            if norm == skip or norm.startswith(skip + sep):
                return True
        if os.path.basename(norm) in self._skip_dirnames_lower:
            return True
        return False

    def _collect_files(self, root_path, mode):
        """Walk the tree and yield file paths that pass the mode filter."""
        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True,
                                                     onerror=None, followlinks=False):
            abs_dir = os.path.abspath(dirpath)

            # Prune directories we never want to descend into
            dirnames[:] = [
                d for d in dirnames
                if not self._should_skip(os.path.join(abs_dir, d))
            ]

            if self._should_skip(abs_dir):
                continue

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if mode == "quick":
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in self.quick_scan_targets:
                        continue
                yield filepath

    def _scan_one(self, filepath, progress):
        """Worker function: scan a single file and record results."""
        try:
            decision, score, reasons = self.process_pipeline(filepath)
            # Only track files scoring above 25 — SAFE files are never shown.
            flagged = score > 25
            with self._results_lock:
                self.scanned_count += 1
                if flagged:
                    self.flagged_files.append((filepath, decision, score, reasons))
            progress.increment(flagged=flagged)
        except PermissionError:
            # WinError 5 / EACCES — file locked by OS or needs elevation.
            with self._results_lock:
                self.scanned_count += 1
                self.access_denied_paths.append(filepath)
            progress.increment()
        except Exception:
            with self._results_lock:
                self.scanned_count += 1
            progress.increment()

    def scan_targets(self, targets, mode="full"):
        """
        Scan one or more directories / drive roots in parallel.

        Parameters
        ----------
        targets : list[str]
            Paths to scan — can be specific directories or full drive roots.
        mode : str
            "quick" (executables/scripts only) or "full" (every file).
        """
        print(f"\n{'='*60}")
        print(f"🛡️   MINI-AV ENGINE  ·  {mode.upper()} SCAN")
        print(f"{'='*60}")
        print(f"  Targets   : {', '.join(targets)}")
        print(f"  Threads   : {self.max_workers}")
        print(f"  Quarantine: {self.quarantine_dir}")
        print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        # Validate targets
        valid_targets = []
        for t in targets:
            if os.path.exists(t):
                valid_targets.append(t)
            else:
                print(f"  ⚠️  Target not found, skipping: {t}")

        if not valid_targets:
            print("❌  No valid targets to scan.")
            return

        progress = ProgressTracker()
        progress.start()

        start_time = time.time()

        # Collect all files first so we can feed the thread pool efficiently
        all_files = []
        for target in valid_targets:
            for fp in self._collect_files(target, mode):
                all_files.append(fp)

        progress.stop()
        print(f"  📂 Files discovered: {len(all_files):,}  — beginning analysis…\n")
        progress.start()

        # Parallel scan
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_one, fp, progress): fp
                       for fp in all_files}
            for _ in as_completed(futures):
                pass  # progress is updated inside _scan_one

        progress.stop()
        elapsed = time.time() - start_time

        # Sort flagged files by path so numbering is identical on every run,
        # regardless of which thread finished first.
        with self._results_lock:
            self.flagged_files.sort(key=lambda e: e[0].lower())

        # ── Results Report ────────────────────────────────────────────────────
        print(f"\n{'='*60}")
        print(f"🏁  SCAN COMPLETE  —  {elapsed:.1f}s elapsed")
        print(f"{'='*60}")
        print(f"  Files evaluated         : {self.scanned_count:>10,}")
        print(f"  Processes terminated    : {self.killed_processes_count:>10,}")
        print(f"  Files quarantined       : {self.quarantined_files_count:>10,}")
        print(f"  Flagged (threats)       : {len(self.flagged_files):>10,}")
        print(f"{'='*60}")

        if not self.flagged_files:
            print("\n  ✅  No threats detected.")
        else:
            self._interactive_report()

        print(f"\n{'='*60}\n")

    # ── Post-scan report & automatic bulk move ───────────────────────────────

    def _interactive_report(self):
        """
        1. Print a full summary of every flagged file.
        2. Ask the user for ONE safe folder path.
        3. Automatically move every flagged file there — no per-file prompting.

        MALICIOUS files are already sitting in the quarantine folder under a
        timestamped name; we locate them via _find_in_quarantine and move them.
        SUSPICIOUS files are still at their original path; we move them directly.
        """
        # Sort: malicious first, then by descending score
        def sort_key(entry):
            _, decision, score, _ = entry
            order = 0 if "MALICIOUS / QUARANTINED" in decision else 1
            return (order, -score)

        sorted_files = sorted(self.flagged_files, key=sort_key)

        # ── Step 1: Print full results table ─────────────────────────────────
        print(f"\n{'═'*60}")
        print(f"  ⚠️   SCAN RESULTS  —  {len(sorted_files)} file(s) flagged")
        print(f"{'═'*60}")
        print("  🔴 MALICIOUS / QUARANTINED  — moved to quarantine during scan")
        print("  🟡 SUSPICIOUS               — still at original location")
        print(f"{'─'*60}\n")

        for idx, (fp, decision, score, reasons) in enumerate(sorted_files, 1):
            label = "🔴 MALICIOUS / QUARANTINED" if "MALICIOUS" in decision else "🟡 SUSPICIOUS"
            print(f"  [{idx}/{len(sorted_files)}]  {label}  (Score: {score}/100)")
            print(f"  Path   : {fp}")
            for r in reasons:
                print(f"    └── {r}")
            print()

        # ── Step 2: Ask for destination once ─────────────────────────────────
        print(f"{'─'*60}")
        print("  All flagged files above will be moved to a safe folder.")
        print("  Enter the destination path below (it will be created if needed).")
        print(f"{'─'*60}")

        while True:
            safe_dir = input("  Safe folder path: ").strip()
            if safe_dir:
                safe_dir = os.path.abspath(safe_dir)
                break
            print("  ⚠️   Path cannot be empty. Please enter a destination folder.")

        try:
            os.makedirs(safe_dir, exist_ok=True)
        except Exception as e:
            print(f"  ❌  Could not create destination folder: {e}")
            print("  ⏭️   No files were moved.")
            return

        # ── Step 3: Automatically move every flagged file ─────────────────────
        print(f"\n  📦  Moving {len(sorted_files)} file(s) to: {safe_dir}\n")

        moved  = 0
        failed = 0

        for fp, decision, score, _ in sorted_files:
            filename = os.path.basename(fp)

            # MALICIOUS files are already in quarantine under a timestamped name.
            # Locate the actual quarantine file, then move it using the
            # original filename (without the timestamp) so it's readable.
            if "MALICIOUS" in decision:
                src = self._find_in_quarantine(filename)
                if not src:
                    print(f"  ⚠️   Could not locate quarantine file for: {filename}")
                    failed += 1
                    continue
            else:
                # SUSPICIOUS — still at original path
                src = fp
                if not os.path.exists(src):
                    print(f"  ⚠️   Source no longer exists: {src}")
                    failed += 1
                    continue

            dest_path = os.path.join(safe_dir, filename)

            # If a file with the same name already exists, append the score
            # to avoid silent overwrites (e.g. two different "setup.exe" files)
            if os.path.exists(dest_path):
                name, ext = os.path.splitext(filename)
                dest_path = os.path.join(safe_dir, f"{name}_score{score}{ext}")

            try:
                try:
                    os.chmod(src, 0o644)
                except Exception:
                    pass
                shutil.move(src, dest_path)
                print(f"  ✅  {filename}  →  {dest_path}")
                moved += 1
            except PermissionError:
                print(f"  ❌  {filename}  —  access denied (run as Administrator)")
                failed += 1
            except Exception as e:
                print(f"  ❌  {filename}  —  {e}")
                failed += 1

        # ── Step 4: Move summary ──────────────────────────────────────────────
        print(f"\n{'─'*60}")
        print(f"  ✅  Moved successfully : {moved}")
        print(f"  ❌  Failed             : {failed}")
        print(f"{'─'*60}")

    def _find_in_quarantine(self, original_basename):
        """
        Find the timestamped quarantine file that corresponds to original_basename.
        e.g. searching for 'malware.exe' finds '20250601_142310_123456_malware.exe.quarantine'
        """
        import re
        # Matches the AV engine's quarantine stamp: YYYYMMDD_HHMMSS_microseconds_
        _STAMP = re.compile(r"^\d{8}_\d{6}_\d+_")
        try:
            for fname in os.listdir(self.quarantine_dir):
                if not fname.endswith(".quarantine"):
                    continue
                # Remove .quarantine suffix, then strip the timestamp prefix
                stripped = _STAMP.sub("", fname[:-len(".quarantine")])
                if stripped.lower() == original_basename.lower():
                    return os.path.join(self.quarantine_dir, fname)
        except Exception:
            pass
        return None

    def _move_to_safe(self, src_path, dest_dir, filename):
        """Move src_path into dest_dir/filename with normal permissions restored."""
        try:
            os.makedirs(dest_dir, exist_ok=True)
            dest_path = os.path.join(dest_dir, filename)
            if os.path.exists(dest_path):
                confirm = input(f"  ⚠️   {filename} already exists there. Overwrite? (yes/no): ").strip().lower()
                if confirm != "yes":
                    print("  ⏭️   Skipped.")
                    return
            try:
                os.chmod(src_path, 0o644)
            except Exception:
                pass
            shutil.move(src_path, dest_path)
            print(f"  📦  Moved → {dest_path}")
        except PermissionError:
            print("  ❌  Access denied. Run as Administrator.")
        except Exception as e:
            print(f"  ❌  Move failed: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

def prompt_targets():
    """Interactive menu: choose specific path, full drive, or all drives."""
    print("\n╔══════════════════════════════════════════╗")
    print("║       🛡️   MINI-AV ENGINE  🛡️            ║")
    print("╚══════════════════════════════════════════╝\n")

    print("Scan scope:")
    print("  1. Specific directory path")
    print("  2. Select a single drive / mount point")
    print("  3. Scan ALL detected drives  ⚠️  (may take a long time)")
    scope = input("\nChoice (1/2/3): ").strip()

    targets = []

    if scope == "1":
        path = input("Enter directory path (default ./): ").strip() or "./"
        targets = [path]

    elif scope == "2":
        drives = get_all_drives()
        print("\nDetected drives / mount points:")
        for i, d in enumerate(drives, 1):
            print(f"  {i}. {d}")
        choice = input("Select number: ").strip()
        try:
            targets = [drives[int(choice) - 1]]
        except (ValueError, IndexError):
            print("Invalid choice — defaulting to current directory.")
            targets = ["./"]

    elif scope == "3":
        targets = get_all_drives()
        print(f"\n  Drives queued: {', '.join(targets)}")
        confirm = input("  Type YES to proceed: ").strip()
        if confirm.upper() != "YES":
            print("Aborted.")
            sys.exit(0)

    else:
        print("Invalid choice — defaulting to current directory.")
        targets = ["./"]

    return targets


def prompt_mode():
    print("\nScan depth:")
    print("  1. Quick  — executables & scripts only  (fast)")
    print("  2. Full   — every file                  (thorough, slower)")
    choice = input("Choice (1/2): ").strip()
    return "quick" if choice == "1" else "full"


def prompt_threads():
    cpu = os.cpu_count() or 2
    default = max(2, cpu // 2)
    raw = input(f"\nParallel threads (default {default}, max {cpu}): ").strip()
    try:
        n = int(raw)
        return max(1, min(n, cpu))
    except ValueError:
        return default


if __name__ == "__main__":
    targets = prompt_targets()
    mode    = prompt_mode()
    workers = prompt_threads()

    engine = RealAVEngine(max_workers=workers)
    engine.scan_targets(targets, mode=mode)
