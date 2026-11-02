"""
av_gui.py  —  Antivirus Engine with Dark Aesthetic GUI
Run:  python av_gui.py
Opens a browser at http://localhost:7474 automatically.
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import os, sys, json, hashlib, math, shutil, psutil, platform
import string, time, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re as _re

try:
    import webview
except ImportError:
    print("\n  ❌  pywebview is not installed.")
    print("      Run:  pip install pywebview")
    print("      Then re-run this script.\n")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  ENGINE  (your experiment.py logic, unchanged)
# ══════════════════════════════════════════════════════════════════════════════

def get_all_drives():
    system = platform.system()
    drives = []
    if system == "Windows":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    else:
        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                if p.fstype and p.fstype not in (
                    'tmpfs','devtmpfs','squashfs','overlay','proc','sysfs',
                    'cgroup','cgroup2','pstore','debugfs','tracefs',
                    'hugetlbfs','mqueue','udev','devpts'):
                    drives.append(p.mountpoint)
        except Exception:
            drives.append("/")
    return drives if drives else ["/"]


class RealAVEngine:
    def __init__(self, quarantine_dir="./av_quarantine", max_workers=4):
        self.known_malware_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test_Empty_File_Malware_Sig",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Mock_Password_Malware",
        }
        self.quick_scan_targets = {'.exe','.bat','.ps1','.vbs','.cmd',
                                    '.dll','.scr','.sh','.msi','.jar',
                                    '.hta','.wsf','.jse','.vbe'}
        self.suspicious_extensions = {'.vbs','.bat','.ps1','.exe','.cmd',
                                       '.scr','.hta','.wsf','.jse','.vbe'}
        self.malicious_keywords = [
            b"WScript.Shell", b"Shell.Application", b"powershell -nop",
            b"downloadstring", b"reg add", b"reg delete", b"shadowcopy delete",
            b"rmdir /s", b"bypass -w hidden", b"Invoke-Expression", b"IEX",
            b"net user /add", b"attrib +h +s", b"schtasks /create",
        ]
        self.quarantine_dir  = os.path.abspath(quarantine_dir)
        self.max_workers     = max_workers
        self._results_lock   = threading.Lock()
        self.scanned_count   = 0
        self.killed_processes_count   = 0
        self.quarantined_files_count  = 0
        self.flagged_files   = []
        self.access_denied_paths = []
        self._progress       = {"scanned": 0, "flagged": 0, "total": 0, "phase": "idle"}

        win = os.environ.get("SystemRoot", "C:\\Windows")
        self.skip_dirs = {os.path.normcase(p) for p in {
            os.path.abspath(self.quarantine_dir), win,
            "/proc","/sys","/dev","/run",
            "/bin","/sbin","/usr/bin","/usr/sbin",
            "/usr/lib","/lib","/lib64","/boot","/etc",
        }}
        self._skip_dirnames_lower = {
            "system volume information","$recycle.bin",
            "$windows.~bt","$windows.~ws",
        }
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self._manifest_path = os.path.join(self.quarantine_dir, "manifest.json")

    # ── manifest ──────────────────────────────────────────────────────────────
    def _load_manifest(self):
        if os.path.exists(self._manifest_path):
            try:
                with open(self._manifest_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"quarantined": {}, "suspicious": {}}

    def _save_manifest(self, data):
        try:
            with open(self._manifest_path, "w") as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    def _log_quarantine(self, q_name, original_path):
        with self._results_lock:
            data = self._load_manifest()
            data.setdefault("quarantined", {})[q_name] = {
                "original_path": original_path, "safe_path": None}
            self._save_manifest(data)

    def _update_safe_path(self, q_name, safe_path):
        with self._results_lock:
            data = self._load_manifest()
            if q_name in data.get("quarantined", {}):
                data["quarantined"][q_name]["safe_path"] = safe_path
            self._save_manifest(data)

    def _log_suspicious(self, safe_path, original_path):
        with self._results_lock:
            data = self._load_manifest()
            data.setdefault("suspicious", {})[safe_path] = {"original_path": original_path}
            self._save_manifest(data)

    # ── file analysis ─────────────────────────────────────────────────────────
    def get_sha256(self, filepath):
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def calculate_entropy(self, filepath):
        try:
            with open(filepath, "rb") as f:
                data = f.read(512_000)
            if not data: return 0.0
            total = len(data)
            e = 0.0
            for x in range(256):
                p = data.count(x) / total
                if p > 0: e -= p * math.log2(p)
            return e
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
        for proc in psutil.process_iter(["pid","name","exe"]):
            try:
                if proc.info["exe"] and os.path.abspath(proc.info["exe"]) == target_abs:
                    p = psutil.Process(proc.info["pid"])
                    p.terminate()
                    try: p.wait(timeout=3)
                    except Exception:
                        try: p.kill()
                        except Exception: pass
                    with self._results_lock:
                        self.killed_processes_count += 1
            except Exception:
                pass

    def quarantine_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            original = os.path.abspath(filepath)
            stamp  = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            q_name = f"{stamp}_{filename}.quarantine"
            dest   = os.path.join(self.quarantine_dir, q_name)
            shutil.move(filepath, dest)
            os.chmod(dest, 0o400)
            self._log_quarantine(q_name, original)
            with self._results_lock:
                self.quarantined_files_count += 1
            return True, q_name
        except Exception:
            return False, None

    def process_pipeline(self, filepath):
        file_ext = os.path.splitext(filepath)[1].lower()
        score = 0
        reasons = []

        fhash = self.get_sha256(filepath)
        if not fhash:
            return "SKIPPED", 0, []

        if fhash in self.known_malware_hashes:
            score += 100
            reasons.append(f"Exact signature match: {self.known_malware_hashes[fhash]}")

        if file_ext in self.suspicious_extensions:
            score += 25
            reasons.append(f"Suspicious extension ({file_ext})")

        found_kw = self.scan_file_content(filepath)
        if found_kw:
            score += len(found_kw) * 20
            reasons.append(f"Malicious strings: {', '.join(found_kw)}")

        entropy = self.calculate_entropy(filepath)
        if entropy > 7.2 and file_ext in {".exe",".dll",".scr"}:
            score += 35
            reasons.append(f"High entropy ({entropy:.2f}) — packed/encrypted binary")
        elif entropy > 6.0 and file_ext in {".vbs",".bat",".ps1"}:
            score += 30
            reasons.append(f"Elevated entropy ({entropy:.2f}) — possible obfuscation")

        score = min(score, 100)

        if score >= 50:
            self.kill_associated_process(filepath)
            ok, q_name = self.quarantine_file(filepath)
            decision = "MALICIOUS"
        elif score >= 26:
            decision = "SUSPICIOUS"
        else:
            decision = "SAFE"

        return decision, score, reasons

    # ── walker ────────────────────────────────────────────────────────────────
    def _should_skip(self, abs_path):
        norm = os.path.normcase(abs_path)
        sep  = os.path.normcase(os.sep)
        for skip in self.skip_dirs:
            if norm == skip or norm.startswith(skip + sep):
                return True
        if os.path.basename(norm) in self._skip_dirnames_lower:
            return True
        return False

    def _collect_files(self, root_path, mode):
        for dirpath, dirnames, filenames in os.walk(
                root_path, topdown=True, onerror=None, followlinks=False):
            abs_dir = os.path.abspath(dirpath)
            dirnames[:] = [d for d in dirnames
                           if not self._should_skip(os.path.join(abs_dir, d))]
            if self._should_skip(abs_dir):
                continue
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if mode == "quick":
                    if os.path.splitext(filename)[1].lower() not in self.quick_scan_targets:
                        continue
                yield filepath

    def _scan_one(self, filepath):
        try:
            decision, score, reasons = self.process_pipeline(filepath)
            flagged = score > 25
            with self._results_lock:
                self.scanned_count += 1
                self._progress["scanned"] = self.scanned_count
                if flagged:
                    self.flagged_files.append({
                        "path": filepath,
                        "decision": decision,
                        "score": score,
                        "percent": score,   # score IS already 0-100
                        "reasons": reasons,
                    })
                    self._progress["flagged"] = len(self.flagged_files)
        except PermissionError:
            with self._results_lock:
                self.scanned_count += 1
                self._progress["scanned"] = self.scanned_count
                self.access_denied_paths.append(filepath)
        except Exception:
            with self._results_lock:
                self.scanned_count += 1
                self._progress["scanned"] = self.scanned_count

    def run_scan(self, targets, mode, safe_dir):
        """Called in a background thread by the HTTP server."""
        self._progress = {"scanned": 0, "flagged": 0, "total": 0,
                          "phase": "collecting", "done": False, "error": None}
        self.scanned_count = 0
        self.killed_processes_count = 0
        self.quarantined_files_count = 0
        self.flagged_files = []
        self.access_denied_paths = []

        valid = [t for t in targets if os.path.exists(t)]
        if not valid:
            self._progress["error"] = "No valid targets found."
            self._progress["done"]  = True
            return

        all_files = []
        for t in valid:
            for fp in self._collect_files(t, mode):
                all_files.append(fp)

        self._progress["total"] = len(all_files)
        self._progress["phase"] = "scanning"

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = {ex.submit(self._scan_one, fp): fp for fp in all_files}
            for _ in as_completed(futs):
                pass

        self.flagged_files.sort(key=lambda e: e["path"].lower())
        self._progress["phase"] = "moving"

        # Auto-move all flagged to safe_dir
        moved = failed = 0
        _STAMP = _re.compile(r"^\d{8}_\d{6}_\d+_")
        if self.flagged_files and safe_dir:
            os.makedirs(safe_dir, exist_ok=True)
            for entry in self.flagged_files:
                fp       = entry["path"]
                decision = entry["decision"]
                score    = entry["score"]
                filename = os.path.basename(fp)

                if decision == "MALICIOUS":
                    # find in quarantine
                    src = None
                    try:
                        for fname in os.listdir(self.quarantine_dir):
                            if fname.endswith(".quarantine"):
                                stripped = _STAMP.sub("", fname[:-len(".quarantine")])
                                if stripped.lower() == filename.lower():
                                    src = os.path.join(self.quarantine_dir, fname)
                                    break
                    except Exception:
                        pass
                    if not src:
                        entry["move_status"] = "not_found"
                        failed += 1
                        continue
                    q_name = os.path.basename(src)
                else:
                    src = fp
                    q_name = None
                    if not os.path.exists(src):
                        entry["move_status"] = "not_found"
                        failed += 1
                        continue

                dest_path = os.path.join(safe_dir, filename)
                if os.path.exists(dest_path):
                    name, ext = os.path.splitext(filename)
                    dest_path = os.path.join(safe_dir, f"{name}_score{score}{ext}")

                try:
                    try: os.chmod(src, 0o644)
                    except Exception: pass
                    shutil.move(src, dest_path)
                    entry["move_status"] = "moved"
                    entry["dest_path"]   = dest_path
                    moved += 1
                    if q_name:
                        self._update_safe_path(q_name, dest_path)
                    else:
                        self._log_suspicious(dest_path, os.path.abspath(fp))
                except Exception as ex_e:
                    entry["move_status"] = str(ex_e)
                    failed += 1

        self._progress.update({
            "phase": "done", "done": True,
            "elapsed": 0,
            "stats": {
                "scanned": self.scanned_count,
                "flagged": len(self.flagged_files),
                "quarantined": self.quarantined_files_count,
                "killed": self.killed_processes_count,
                "moved": moved,
                "failed_move": failed,
            },
            "results": self.flagged_files,
        })

    def restore_all(self):
        """Restore every entry in the manifest back to its original path."""
        data     = self._load_manifest()
        q_items  = list(data.get("quarantined", {}).items())
        s_items  = list(data.get("suspicious",  {}).items())
        restored = failed = 0
        log      = []

        for q_name, info in q_items:
            safe_path = info.get("safe_path")
            orig_path = info.get("original_path")
            src = safe_path if (safe_path and os.path.exists(safe_path)) else \
                  os.path.join(self.quarantine_dir, q_name)
            if os.path.exists(src):
                try:
                    os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                    try: os.chmod(src, 0o644)
                    except Exception: pass
                    shutil.move(src, orig_path)
                    log.append({"file": os.path.basename(orig_path),
                                "dest": orig_path, "ok": True})
                    restored += 1
                    with self._results_lock:
                        d = self._load_manifest()
                        d.get("quarantined", {}).pop(q_name, None)
                        self._save_manifest(d)
                except Exception as e:
                    log.append({"file": os.path.basename(orig_path),
                                "dest": orig_path, "ok": False, "err": str(e)})
                    failed += 1
            else:
                log.append({"file": q_name, "dest": orig_path,
                            "ok": False, "err": "source not found"})
                failed += 1

        for safe_path, info in s_items:
            orig_path = info.get("original_path")
            if os.path.exists(safe_path):
                try:
                    os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                    shutil.move(safe_path, orig_path)
                    log.append({"file": os.path.basename(orig_path),
                                "dest": orig_path, "ok": True})
                    restored += 1
                    with self._results_lock:
                        d = self._load_manifest()
                        d.get("suspicious", {}).pop(safe_path, None)
                        self._save_manifest(d)
                except Exception as e:
                    log.append({"file": os.path.basename(orig_path),
                                "dest": orig_path, "ok": False, "err": str(e)})
                    failed += 1

        return {"restored": restored, "failed": failed, "log": log}


# ══════════════════════════════════════════════════════════════════════════════
#  NATIVE API  (called by JS via window.pywebview.api.<method>)
# ══════════════════════════════════════════════════════════════════════════════

engine = RealAVEngine()
_scan_thread = None


class API:
    """Exposed to the frontend via pywebview's JS bridge."""

    def get_drives(self):
        return {"drives": get_all_drives()}

    def get_progress(self):
        return engine._progress

    def get_manifest(self):
        return engine._load_manifest()

    def start_scan(self, targets, mode, threads, quarantine_dir, safe_dir):
        global _scan_thread, engine
        engine = RealAVEngine(
            quarantine_dir=quarantine_dir or "./av_quarantine",
            max_workers=int(threads or 4),
        )
        _scan_thread = threading.Thread(
            target=engine.run_scan,
            args=(targets, mode, safe_dir),
            daemon=True,
        )
        _scan_thread.start()
        return {"status": "started"}

    def restore_all(self):
        return engine.restore_all()

    def pick_folder(self):
        """Open a native OS folder-picker dialog."""
        result = window.create_file_dialog(webview.FOLDER_DIALOG)
        if result and len(result) > 0:
            return result[0]
        return ""

_api = API()


# ══════════════════════════════════════════════════════════════════════════════
#  HTML / CSS / JS  — single-file dark aesthetic GUI
# ══════════════════════════════════════════════════════════════════════════════

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ShieldScan AV</title>
<style>
  /* ── Tokens ── */
  :root{
    --bg:        #0d0f14;
    --surface:   #13161e;
    --card:      #181c26;
    --border:    #252a38;
    --accent:    #4f8ef7;
    --accent2:   #7c6af7;
    --green:     #3dd68c;
    --yellow:    #f7c94f;
    --red:       #f7524f;
    --text:      #e2e6f0;
    --muted:     #6b7494;
    --font-mono: "JetBrains Mono","Fira Mono","Consolas",monospace;
    --font-ui:   "Inter","Segoe UI",sans-serif;
    --radius:    10px;
    --radius-lg: 16px;
  }

  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%;background:var(--bg);color:var(--text);
            font-family:var(--font-ui);font-size:14px;line-height:1.6}

  /* ── Layout ── */
  .shell{display:grid;grid-template-columns:260px 1fr;height:100vh;overflow:hidden}

  /* ── Sidebar ── */
  .sidebar{background:var(--surface);border-right:1px solid var(--border);
           display:flex;flex-direction:column;padding:28px 20px;gap:6px;overflow-y:auto}

  .brand{display:flex;align-items:center;gap:10px;padding:0 4px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
  .brand-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent2));
              border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
  .brand-name{font-size:15px;font-weight:700;letter-spacing:.5px}
  .brand-sub{font-size:11px;color:var(--muted);letter-spacing:1.5px;text-transform:uppercase}

  .nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:8px;
            cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;transition:all .15s}
  .nav-item:hover{background:var(--card);color:var(--text)}
  .nav-item.active{background:rgba(79,142,247,.12);color:var(--accent)}
  .nav-icon{font-size:16px;width:20px;text-align:center}

  .sidebar-footer{margin-top:auto;padding-top:20px;border-top:1px solid var(--border);
                  font-size:11px;color:var(--muted);line-height:1.8}

  /* ── Main ── */
  .main{overflow-y:auto;padding:36px 40px}

  /* ── Pages ── */
  .page{display:none}.page.active{display:block}

  /* ── Section headings ── */
  .page-title{font-size:22px;font-weight:700;margin-bottom:4px}
  .page-sub{color:var(--muted);font-size:13px;margin-bottom:28px}

  /* ── Cards ── */
  .card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;margin-bottom:20px}
  .card-title{font-size:12px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;
              color:var(--muted);margin-bottom:16px}

  /* ── Form elements ── */
  .field{margin-bottom:16px}
  .field label{display:block;font-size:12px;font-weight:600;color:var(--muted);
               letter-spacing:.8px;text-transform:uppercase;margin-bottom:8px}
  .field input,.field select{width:100%;background:var(--surface);border:1px solid var(--border);
    border-radius:8px;padding:10px 14px;color:var(--text);font-family:var(--font-ui);
    font-size:13px;outline:none;transition:border-color .15s}
  .field input:focus,.field select:focus{border-color:var(--accent)}
  .field input::placeholder{color:var(--muted)}
  .field select option{background:var(--surface)}

  /* ── Segmented ── */
  .seg{display:flex;gap:6px;background:var(--surface);border:1px solid var(--border);
       border-radius:8px;padding:4px}
  .seg-btn{flex:1;padding:8px;border:none;border-radius:6px;background:transparent;
           color:var(--muted);font-size:12px;font-weight:600;cursor:pointer;transition:all .15s}
  .seg-btn.on{background:var(--accent);color:#fff}

  /* ── Drive pills ── */
  .drives-wrap{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
  .drive-pill{padding:6px 14px;border-radius:6px;border:1px solid var(--border);
              background:var(--surface);color:var(--muted);font-size:12px;font-weight:600;
              cursor:pointer;transition:all .15s;font-family:var(--font-mono)}
  .drive-pill.sel{border-color:var(--accent);background:rgba(79,142,247,.12);color:var(--accent)}

  /* ── Buttons ── */
  .btn{display:inline-flex;align-items:center;gap:8px;padding:11px 22px;border-radius:8px;
       border:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s}
  .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
  .btn-primary:hover{opacity:.88;transform:translateY(-1px)}
  .btn-primary:disabled{opacity:.4;cursor:not-allowed;transform:none}
  .btn-ghost{background:transparent;border:1px solid var(--border);color:var(--muted)}
  .btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
  .btn-green{background:rgba(61,214,140,.12);border:1px solid var(--green);color:var(--green)}
  .btn-green:hover{background:rgba(61,214,140,.22)}
  .btn-red{background:rgba(247,82,79,.12);border:1px solid var(--red);color:var(--red)}

  /* ── Progress bar ── */
  .prog-wrap{background:var(--surface);border-radius:99px;height:6px;overflow:hidden;margin:12px 0}
  .prog-bar{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));
            border-radius:99px;transition:width .3s;width:0%}
  .prog-bar.pulse{animation:pulse 1.5s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}

  /* ── Stats row ── */
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:14px;margin-bottom:20px}
  .stat-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
            padding:16px;text-align:center}
  .stat-num{font-size:26px;font-weight:700;font-family:var(--font-mono)}
  .stat-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-top:2px}

  /* ── Score ring ── */
  .score-ring{display:inline-flex;align-items:center;justify-content:center;
              position:relative;width:52px;height:52px;flex-shrink:0}
  .score-ring svg{position:absolute;top:0;left:0;transform:rotate(-90deg)}
  .score-ring .val{font-family:var(--font-mono);font-size:13px;font-weight:700;position:relative;z-index:1}

  /* ── Result items ── */
  .result-list{display:flex;flex-direction:column;gap:10px}
  .result-item{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
               padding:16px;display:grid;grid-template-columns:56px 1fr auto;gap:14px;align-items:start}
  .result-item.malicious{border-left:3px solid var(--red)}
  .result-item.suspicious{border-left:3px solid var(--yellow)}

  .result-badge{display:inline-block;padding:3px 9px;border-radius:5px;font-size:11px;font-weight:700;
                letter-spacing:.6px;text-transform:uppercase}
  .badge-mal{background:rgba(247,82,79,.15);color:var(--red)}
  .badge-sus{background:rgba(247,201,79,.15);color:var(--yellow)}

  .result-path{font-family:var(--font-mono);font-size:11px;color:var(--muted);
               word-break:break-all;margin-top:4px}
  .result-reasons{margin-top:8px;display:flex;flex-direction:column;gap:4px}
  .reason-tag{font-size:11px;color:var(--muted);padding:3px 8px;
              background:var(--card);border-radius:5px;display:inline-block}
  .result-dest{font-family:var(--font-mono);font-size:10px;color:var(--green);margin-top:6px}

  /* ── Restore log ── */
  .restore-row{display:flex;align-items:center;gap:10px;padding:10px 0;
               border-bottom:1px solid var(--border);font-size:12px}
  .restore-row:last-child{border-bottom:none}
  .restore-ok{color:var(--green)}
  .restore-fail{color:var(--red)}

  /* ── Toast ── */
  #toast{position:fixed;bottom:28px;right:28px;background:var(--card);border:1px solid var(--border);
         border-radius:10px;padding:12px 20px;font-size:13px;opacity:0;transition:opacity .25s;
         pointer-events:none;z-index:999}
  #toast.show{opacity:1}

  /* ── Empty state ── */
  .empty{text-align:center;padding:60px 20px;color:var(--muted)}
  .empty-icon{font-size:48px;margin-bottom:12px}
  .empty-text{font-size:14px}

  /* ── Spinner ── */
  .spin{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.3);
        border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}

  /* ── Live log ── */
  .live-log{font-family:var(--font-mono);font-size:11px;color:var(--muted);
            background:var(--surface);border:1px solid var(--border);border-radius:8px;
            padding:14px;max-height:120px;overflow-y:auto;margin-top:14px;line-height:2}

  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
  .dot-green{background:var(--green)}
  .dot-yellow{background:var(--yellow)}
  .dot-red{background:var(--red)}
  .dot-blue{background:var(--accent)}
</style>
</head>
<body>

<div class="shell">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-icon">🛡</div>
      <div>
        <div class="brand-name">ShieldScan</div>
        <div class="brand-sub">AV Engine</div>
      </div>
    </div>

    <div class="nav-item active" onclick="nav('scan')">
      <span class="nav-icon">🔍</span> Scan
    </div>
    <div class="nav-item" onclick="nav('results')">
      <span class="nav-icon">📋</span> Results
    </div>
    <div class="nav-item" onclick="nav('restore')">
      <span class="nav-icon">🔁</span> Restore Files
    </div>
    <div class="nav-item" onclick="nav('about')">
      <span class="nav-icon">ℹ️</span> About
    </div>

    <div class="sidebar-footer">
      ShieldScan AV &nbsp;·&nbsp; Educational Build<br>
      Heuristic + Signature Engine<br>
      Skips Windows system paths
    </div>
  </aside>

  <!-- Main -->
  <main class="main">

    <!-- ── SCAN PAGE ── -->
    <div id="page-scan" class="page active">
      <div class="page-title">Run a Scan</div>
      <div class="page-sub">Configure your scan target, depth, and safe folder below.</div>

      <!-- Scope -->
      <div class="card">
        <div class="card-title">Scan Scope</div>
        <div style="margin-bottom:14px">
          <div class="seg" id="scope-seg">
            <button class="seg-btn on" onclick="setScope('path',this)">Specific Path</button>
            <button class="seg-btn"    onclick="setScope('drive',this)">Drive</button>
            <button class="seg-btn"    onclick="setScope('all',this)">All Drives</button>
          </div>
        </div>

        <div id="scope-path">
          <div class="field">
            <label>Directory Path</label>
            <div style="display:flex;gap:8px">
              <input id="inp-path" type="text" placeholder="e.g. C:\Users\ASUS\Downloads" value="./" style="flex:1"/>
              <button class="btn btn-ghost" style="padding:10px 14px;white-space:nowrap" onclick="pickFolder('inp-path')">📁 Browse</button>
            </div>
          </div>
        </div>

        <div id="scope-drive" style="display:none">
          <div class="field">
            <label>Choose a Drive</label>
            <div class="drives-wrap" id="drives-wrap">
              <span style="color:var(--muted);font-size:12px">Loading drives…</span>
            </div>
          </div>
        </div>

        <div id="scope-all" style="display:none">
          <div style="background:rgba(247,201,79,.08);border:1px solid rgba(247,201,79,.3);
               border-radius:8px;padding:14px;font-size:13px;color:var(--yellow)">
            ⚠️ All detected drives will be scanned. This may take a long time.
          </div>
        </div>
      </div>

      <!-- Options -->
      <div class="card">
        <div class="card-title">Scan Options</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div class="field">
            <label>Scan Depth</label>
            <div class="seg">
              <button class="seg-btn on" id="mode-quick" onclick="setMode('quick',this)">Quick</button>
              <button class="seg-btn"    id="mode-full"  onclick="setMode('full',this)">Full</button>
            </div>
          </div>
          <div class="field">
            <label>Parallel Threads</label>
            <input id="inp-threads" type="number" min="1" max="32" value="4"/>
          </div>
        </div>
        <div class="field">
          <label>Quarantine Folder</label>
          <div style="display:flex;gap:8px">
            <input id="inp-qdir" type="text" placeholder="./av_quarantine" value="./av_quarantine" style="flex:1"/>
            <button class="btn btn-ghost" style="padding:10px 14px;white-space:nowrap" onclick="pickFolder('inp-qdir')">📁 Browse</button>
          </div>
        </div>
        <div class="field">
          <label>Safe Destination Folder <span style="color:var(--muted);font-weight:400">(flagged files moved here)</span></label>
          <div style="display:flex;gap:8px">
            <input id="inp-safedir" type="text" placeholder="e.g. C:\SafeZone" style="flex:1"/>
            <button class="btn btn-ghost" style="padding:10px 14px;white-space:nowrap" onclick="pickFolder('inp-safedir')">📁 Browse</button>
          </div>
        </div>
      </div>

      <!-- Launch -->
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-primary" id="btn-scan" onclick="startScan()">
          <span>🚀</span> Start Scan
        </button>
        <div id="scan-status" style="color:var(--muted);font-size:13px"></div>
      </div>

      <!-- Progress card (hidden until scan starts) -->
      <div class="card" id="prog-card" style="display:none;margin-top:24px">
        <div class="card-title">Scan Progress</div>
        <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:4px">
          <span id="prog-phase">Initialising…</span>
          <span id="prog-nums">0 / 0</span>
        </div>
        <div class="prog-wrap"><div class="prog-bar pulse" id="prog-bar"></div></div>
        <div class="live-log" id="live-log">Preparing scan…</div>
      </div>
    </div>

    <!-- ── RESULTS PAGE ── -->
    <div id="page-results" class="page">
      <div class="page-title">Scan Results</div>
      <div class="page-sub">All files scoring above 25 are listed below.</div>

      <div id="results-empty" class="empty">
        <div class="empty-icon">📭</div>
        <div class="empty-text">No scan results yet. Run a scan first.</div>
      </div>

      <div id="results-content" style="display:none">
        <div class="stats-grid" id="stats-grid"></div>
        <div class="card">
          <div class="card-title">Flagged Files</div>
          <div class="result-list" id="result-list"></div>
        </div>
      </div>
    </div>

    <!-- ── RESTORE PAGE ── -->
    <div id="page-restore" class="page">
      <div class="page-title">Restore Files</div>
      <div class="page-sub">Move all quarantined and suspicious files back to their original locations.</div>

      <div class="card">
        <div class="card-title">Manifest Status</div>
        <div id="manifest-info" style="color:var(--muted);font-size:13px">Loading…</div>
        <div style="margin-top:16px;display:flex;gap:10px">
          <button class="btn btn-green" onclick="doRestore()">🔁 Restore All Files</button>
          <button class="btn btn-ghost" onclick="loadManifest()">↻ Refresh</button>
        </div>
      </div>

      <div class="card" id="restore-log-card" style="display:none">
        <div class="card-title">Restore Log</div>
        <div id="restore-log"></div>
      </div>
    </div>

    <!-- ── ABOUT PAGE ── -->
    <div id="page-about" class="page">
      <div class="page-title">About ShieldScan</div>
      <div class="page-sub">Educational antivirus demonstration project.</div>

      <div class="card">
        <div class="card-title">Detection Layers</div>
        <div style="display:flex;flex-direction:column;gap:14px">

          <div style="display:flex;gap:14px;align-items:flex-start">
            <div style="width:36px;height:36px;background:rgba(79,142,247,.12);border-radius:8px;
                 display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">🔐</div>
            <div>
              <div style="font-weight:600;margin-bottom:2px">SHA-256 Signature Match</div>
              <div style="color:var(--muted);font-size:12px">Compares file hash against known malware database. Exact match = +100 score.</div>
            </div>
          </div>

          <div style="display:flex;gap:14px;align-items:flex-start">
            <div style="width:36px;height:36px;background:rgba(124,106,247,.12);border-radius:8px;
                 display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">🔎</div>
            <div>
              <div style="font-weight:600;margin-bottom:2px">Static Extension Analysis</div>
              <div style="color:var(--muted);font-size:12px">Flags suspicious extensions (.vbs, .bat, .ps1, .exe…) — +25 score.</div>
            </div>
          </div>

          <div style="display:flex;gap:14px;align-items:flex-start">
            <div style="width:36px;height:36px;background:rgba(247,82,79,.12);border-radius:8px;
                 display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">🧬</div>
            <div>
              <div style="font-weight:600;margin-bottom:2px">Keyword / Content Scan</div>
              <div style="color:var(--muted);font-size:12px">Searches binary content for shell commands, download strings, registry edits. +20 per keyword.</div>
            </div>
          </div>

          <div style="display:flex;gap:14px;align-items:flex-start">
            <div style="width:36px;height:36px;background:rgba(61,214,140,.12);border-radius:8px;
                 display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">📊</div>
            <div>
              <div style="font-weight:600;margin-bottom:2px">Shannon Entropy Heuristic</div>
              <div style="color:var(--muted);font-size:12px">High entropy (>7.2 for EXE/DLL, >6.0 for scripts) suggests packing or obfuscation. +30–35 score.</div>
            </div>
          </div>

        </div>
      </div>

      <div class="card">
        <div class="card-title">Heuristic Score Scale</div>
        <div style="display:flex;flex-direction:column;gap:10px">
          <div style="display:flex;align-items:center;gap:12px">
            <div class="dot dot-green"></div><span style="font-size:13px"><strong>0 – 25</strong> — Safe, not reported</span>
          </div>
          <div style="display:flex;align-items:center;gap:12px">
            <div class="dot dot-yellow"></div><span style="font-size:13px"><strong>26 – 49</strong> — Suspicious, flagged for review</span>
          </div>
          <div style="display:flex;align-items:center;gap:12px">
            <div class="dot dot-red"></div><span style="font-size:13px"><strong>50 – 100</strong> — Malicious, process killed + quarantined</span>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>

<div id="toast"></div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let currentScope = 'path';
let currentMode  = 'quick';
let selectedDrive = null;
let allDrives = [];
let pollTimer = null;
let lastResults = null;

// ── Navigation ────────────────────────────────────────────────────────────────
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  event.currentTarget.classList.add('active');
  if (page === 'restore') loadManifest();
  if (page === 'results') renderResults();
}

// ── Scope ────────────────────────────────────────────────────────────────────
function setScope(scope, btn) {
  currentScope = scope;
  document.querySelectorAll('#scope-seg .seg-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  ['path','drive','all'].forEach(s =>
    document.getElementById('scope-' + s).style.display = s === scope ? '' : 'none');
  if (scope === 'drive' && allDrives.length === 0) loadDrives();
}

function setMode(mode, btn) {
  currentMode = mode;
  document.querySelectorAll('#page-scan .seg-btn[id^=mode]').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
}

// ── Drives ───────────────────────────────────────────────────────────────────
async function loadDrives() {
  const d = await window.pywebview.api.get_drives();
  allDrives = d.drives;
  const wrap = document.getElementById('drives-wrap');
  wrap.innerHTML = '';
  allDrives.forEach(drive => {
    const p = document.createElement('div');
    p.className = 'drive-pill';
    p.textContent = drive;
    p.onclick = () => {
      document.querySelectorAll('.drive-pill').forEach(x => x.classList.remove('sel'));
      p.classList.add('sel');
      selectedDrive = drive;
    };
    wrap.appendChild(p);
  });
}

// ── Scan ─────────────────────────────────────────────────────────────────────
async function startScan() {
  let targets = [];
  if (currentScope === 'path') {
    const v = document.getElementById('inp-path').value.trim();
    targets = [v || './'];
  } else if (currentScope === 'drive') {
    if (!selectedDrive) { toast('Please select a drive first.'); return; }
    targets = [selectedDrive];
  } else {
    targets = allDrives.length ? allDrives : (await window.pywebview.api.get_drives()).drives;
  }

  const payload = {
    targets,
    mode: currentMode,
    threads: parseInt(document.getElementById('inp-threads').value) || 4,
    quarantine_dir: document.getElementById('inp-qdir').value.trim() || './av_quarantine',
    safe_dir: document.getElementById('inp-safedir').value.trim(),
  };

  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Scanning…';

  document.getElementById('prog-card').style.display = '';
  document.getElementById('live-log').textContent = 'Starting…';
  setProgBar(0, true);

  await window.pywebview.api.start_scan(
    payload.targets, payload.mode, payload.threads,
    payload.quarantine_dir, payload.safe_dir);

  pollTimer = setInterval(pollProgress, 600);
}

async function pollProgress() {
  const p = await window.pywebview.api.get_progress();

  const phase = p.phase || 'idle';
  const scanned = p.scanned || 0;
  const total   = p.total   || 0;
  const flagged = p.flagged || 0;

  const pct = total > 0 ? Math.min(100, Math.round(scanned / total * 100)) : 0;

  document.getElementById('prog-phase').textContent =
    phase === 'collecting' ? 'Collecting files…' :
    phase === 'scanning'   ? `Analysing files…` :
    phase === 'moving'     ? 'Moving flagged files…' :
    phase === 'done'       ? 'Complete!' : 'Initialising…';

  document.getElementById('prog-nums').textContent =
    `${scanned.toLocaleString()} / ${total.toLocaleString()} scanned  ·  ${flagged} flagged`;

  setProgBar(pct, phase !== 'done');

  const log = document.getElementById('live-log');
  log.textContent = phase === 'collecting'
    ? `Walking directories…`
    : phase === 'scanning'
    ? `${scanned.toLocaleString()} files analysed · ${flagged} threats found`
    : phase === 'moving'
    ? `Moving ${flagged} flagged files to safe folder…`
    : `Scan complete — ${flagged} files flagged.`;

  if (p.done) {
    clearInterval(pollTimer);
    setProgBar(100, false);
    document.getElementById('btn-scan').disabled = false;
    document.getElementById('btn-scan').innerHTML = '<span>🚀</span> Start Scan';

    lastResults = p;
    toast(`✅ Scan done — ${(p.stats||{}).flagged||0} files flagged`);
  }
}

function setProgBar(pct, pulse) {
  const bar = document.getElementById('prog-bar');
  bar.style.width = pct + '%';
  bar.classList.toggle('pulse', pulse);
}

// ── Results ───────────────────────────────────────────────────────────────────
function renderResults() {
  if (!lastResults || !lastResults.results) {
    document.getElementById('results-empty').style.display = '';
    document.getElementById('results-content').style.display = 'none';
    return;
  }
  document.getElementById('results-empty').style.display = 'none';
  document.getElementById('results-content').style.display = '';

  const s = lastResults.stats || {};
  document.getElementById('stats-grid').innerHTML = [
    [s.scanned   || 0, 'Files Scanned',    'var(--accent)'],
    [s.flagged   || 0, 'Flagged',          'var(--yellow)'],
    [s.quarantined||0, 'Quarantined',      'var(--red)'],
    [s.killed    || 0, 'Processes Killed', 'var(--red)'],
    [s.moved     || 0, 'Moved to Safe',    'var(--green)'],
  ].map(([n,l,c]) => `
    <div class="stat-box">
      <div class="stat-num" style="color:${c}">${n.toLocaleString()}</div>
      <div class="stat-lbl">${l}</div>
    </div>`).join('');

  const list = document.getElementById('result-list');
  const results = lastResults.results || [];
  if (results.length === 0) {
    list.innerHTML = '<div class="empty"><div class="empty-icon">✅</div><div class="empty-text">No threats detected.</div></div>';
    return;
  }

  list.innerHTML = results.map(f => {
    const isMal = f.decision === 'MALICIOUS';
    const pct   = f.percent || f.score || 0;
    const col   = isMal ? 'var(--red)' : 'var(--yellow)';
    const circ  = scoreRing(pct, col);

    const badge = isMal
      ? `<span class="result-badge badge-mal">Malicious</span>`
      : `<span class="result-badge badge-sus">Suspicious</span>`;

    const reasons = (f.reasons||[]).map(r =>
      `<span class="reason-tag">${r}</span>`).join('');

    const dest = f.dest_path
      ? `<div class="result-dest">→ Moved to: ${f.dest_path}</div>` : '';

    // Score bar
    const barCol = pct >= 50 ? 'var(--red)' : 'var(--yellow)';
    const scoreBar = `
      <div style="margin-top:8px">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:4px">
          <span>Heuristic Score</span>
          <span style="color:${barCol};font-weight:700;font-family:var(--font-mono)">${pct}/100 &nbsp;(${pct}%)</span>
        </div>
        <div style="background:var(--border);border-radius:99px;height:5px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${barCol};border-radius:99px"></div>
        </div>
      </div>`;

    return `
      <div class="result-item ${isMal?'malicious':'suspicious'}">
        ${circ}
        <div>
          ${badge}
          <div class="result-path">${f.path}</div>
          <div class="result-reasons">${reasons}</div>
          ${scoreBar}
          ${dest}
        </div>
        <div></div>
      </div>`;
  }).join('');
}

function scoreRing(pct, col) {
  const r = 22, cx = 26, cy = 26;
  const circ = 2 * Math.PI * r;
  const dash = circ * pct / 100;
  return `
    <div class="score-ring">
      <svg width="52" height="52" viewBox="0 0 52 52">
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--border)" stroke-width="4"/>
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${col}" stroke-width="4"
          stroke-dasharray="${dash} ${circ}" stroke-linecap="round"/>
      </svg>
      <span class="val" style="color:${col}">${pct}</span>
    </div>`;
}

// ── Restore ───────────────────────────────────────────────────────────────────
async function loadManifest() {
  const d = await window.pywebview.api.get_manifest();
  const q = Object.keys(d.quarantined || {}).length;
  const s = Object.keys(d.suspicious  || {}).length;
  const info = document.getElementById('manifest-info');
  if (q === 0 && s === 0) {
    info.innerHTML = '<span style="color:var(--green)">✅ No files pending restore.</span>';
  } else {
    info.innerHTML = `
      <div style="display:flex;gap:20px;margin-bottom:8px">
        <div><span style="color:var(--red);font-weight:700;font-size:18px;font-family:var(--font-mono)">${q}</span>
             <span style="color:var(--muted);font-size:12px"> quarantined</span></div>
        <div><span style="color:var(--yellow);font-weight:700;font-size:18px;font-family:var(--font-mono)">${s}</span>
             <span style="color:var(--muted);font-size:12px"> suspicious</span></div>
      </div>
      <div style="font-size:12px;color:var(--muted)">
        Clicking <strong>Restore All</strong> will move every file back to its original path.
      </div>`;
  }
}

async function doRestore() {
  toast('⏳ Restoring…');
  const d = await window.pywebview.api.restore_all();

  document.getElementById('restore-log-card').style.display = '';
  const log = document.getElementById('restore-log');
  if (!d.log || d.log.length === 0) {
    log.innerHTML = '<div style="color:var(--muted);font-size:13px">Nothing to restore.</div>';
  } else {
    log.innerHTML = d.log.map(row => `
      <div class="restore-row">
        <span class="${row.ok ? 'restore-ok' : 'restore-fail'}">${row.ok ? '✅' : '❌'}</span>
        <span style="font-family:var(--font-mono);font-size:12px;flex:1">${row.file}</span>
        <span style="color:var(--muted);font-size:11px;font-family:var(--font-mono)">${row.dest}</span>
        ${!row.ok ? `<span style="color:var(--red);font-size:11px">${row.err||''}</span>` : ''}
      </div>`).join('');
  }
  toast(`✅ ${d.restored} restored · ${d.failed} failed`);
  loadManifest();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Folder picker ────────────────────────────────────────────────────────────
async function pickFolder(inputId) {
  const path = await window.pywebview.api.pick_folder();
  if (path) document.getElementById(inputId).value = path;
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.addEventListener('pywebviewready', () => { loadDrives(); });
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  LAUNCH
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n  🛡️  ShieldScan AV — launching desktop window…\n")
    window = webview.create_window(
        title      = "ShieldScan AV",
        html       = HTML,
        js_api     = _api,
        width      = 1100,
        height     = 720,
        min_size   = (800, 560),
        background_color = "#0d0f14",
    )
    # expose window reference so pick_folder can use it
    _api_ref = _api
    def _set_window(w):
        global window
        # window already set above; bind to api for dialog access
        _api.pick_folder = lambda: (
            w.create_file_dialog(webview.FOLDER_DIALOG) or [""]
        )[0]
    webview.start(_set_window, window, private_mode=False)



####### Add these features:
#1. More good Frontend UI (logos of scanning, antivirus logo and so on and so forth)
#2. Integrate firewall too
#3. Deletion of The Malicious Files
#4. Cloud Scanning 
#5. Web-based protection.
#6. Sand-box Execution.