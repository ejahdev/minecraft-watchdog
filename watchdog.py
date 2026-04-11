import os, time, subprocess, shutil, datetime, threading, re, secrets, json, hashlib, hmac as _hmac, zipfile, concurrent.futures
from functools import wraps
from mcstatus import JavaServer
import psutil
from flask import Flask, jsonify, render_template_string, request, session, redirect, send_file

# ── Logging ────────────────────────────────────────────────────────────────────
CONFIG_FILE  = "watchdog_config.json"
WATCHDOG_LOG = "watchdog.log"

def log_event(kind, msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(WATCHDOG_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{kind}] {msg}\n")
    except Exception: pass

# ── Password helpers ───────────────────────────────────────────────────────────
def _hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 600_000).hex()
    return f"pbkdf2:{salt}:{h}"

def _check_password(pw, stored):
    if not str(stored).startswith("pbkdf2:"):
        return _hmac.compare_digest(pw, stored)
    try:
        _, salt, h = stored.split(":", 2)
        candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 600_000).hex()
        return _hmac.compare_digest(candidate, h)
    except Exception:
        return False

# ── Config ─────────────────────────────────────────────────────────────────────
DEFAULT_SERVER_CFG = {
    "name":             "My Server",
    "server_dir":       ".",
    "java_args":        ["java","@user_jvm_args.txt","@libraries/net/neoforged/neoforge/21.1.224/win_args.txt","nogui"],
    "server_ip":        "127.0.0.1",
    "server_port":      25565,
    "check_interval":   5,
    "max_startup_wait": 300,
    "backup_interval":  1800,
    "restart_interval": 21600,
    "restart_warning_times": [600, 300, 60],
    "max_crashes":      5,
    "crash_window":     300,
    "world_dir":        "world",
    "backup_dir":       "backups",
    "backups_enabled":  True,
    "users":            [],
}

DEFAULT_CONFIG = {
    "port":        5000,
    "server_name": "Minecraft Watchdog",
    "users":       [],
    "servers":     [],
}

def _get_user(username):
    for u in cfg.get("users", []):
        if u.get("username") == username:
            return u
    return None

def _get_server_role(username, srv):
    """Returns the user's role on this server, or None if no access."""
    user = _get_user(username)
    if user and user.get("role") == "owner":
        return "owner"
    for u in srv.scfg.get("users", []):
        if u.get("username") == username:
            return u.get("role")
    return None

def load_config():
    c = {**DEFAULT_CONFIG}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                c.update(json.load(f))
        except Exception as e:
            log_event("ERROR", f"Config read failed ({e}); using defaults")
    if not c.get("secret_key"):
        c["secret_key"] = secrets.token_hex(32)
    # Migrate old flat single-server config to servers list
    if not c.get("servers"):
        scfg = {k: c.pop(k, DEFAULT_SERVER_CFG[k]) for k in DEFAULT_SERVER_CFG}
        scfg["name"] = "My Server"
        scfg.setdefault("server_dir", ".")
        c["servers"] = [scfg]
        log_event("CONFIG", "Migrated to multi-server config format")
    # Ensure every server entry has all required keys
    for s in c["servers"]:
        for k, v in DEFAULT_SERVER_CFG.items():
            s.setdefault(k, v)
    # Migrate old single-password field to users list
    if not c.get("users"):
        old_pw   = c.get("password", "changeme")
        is_fresh = old_pw == "changeme"
        if not str(old_pw).startswith("pbkdf2:"):
            old_pw = _hash_password(old_pw)
        c["users"] = [{"username": "admin", "password": old_pw, "role": "owner"}]
        c.pop("password", None)
        if is_fresh:
            print("\n" + "="*54)
            print(f"  {c.get('server_name') or 'Minecraft Watchdog'} first run — default login credentials:")
            print("    Username : admin")
            print("    Password : changeme")
            print("  Change your password after logging in!")
            print("="*54 + "\n")
            log_event("SETUP", "Default credentials: admin / changeme — change immediately")
        else:
            log_event("SECURITY", "Migrated to multi-user config. Login: admin / previous password")
    if c.get("users") and not any(u.get("role") == "owner" for u in c["users"]):
        c["users"][0]["role"] = "owner"
        log_event("SECURITY", f"Promoted '{c['users'][0]['username']}' to owner (migration)")
    for u in c.get("users", []):
        if u.get("password") and not str(u["password"]).startswith("pbkdf2:"):
            u["password"] = _hash_password(u["password"])
            log_event("SECURITY", f"Hashed password for user '{u['username']}'")
    save_config(c)
    return c

def save_config(c):
    tmp = CONFIG_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(c, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
    except Exception as e:
        log_event("ERROR", f"Config save failed: {e}")
        try: os.remove(tmp)
        except Exception: pass

cfg = load_config()

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = cfg["secret_key"]
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(hours=12)

# ── Regex ──────────────────────────────────────────────────────────────────────
CHAT_RE         = re.compile(r'\[.+?/INFO\].*?:\s<(.+?)>\s(.+)')
DONE_RE         = re.compile(r'Done \(')
ANSI_RE         = re.compile(r'\x1b\[[0-9;]*m')
MOTD_RE         = re.compile(r'\u00a7.')
CANT_KEEP_UP_RE = re.compile(r"Can't keep up!.*?Running \d+ms or (\d+) ticks behind")
EVENT_RE = re.compile(
    r'\[.+?/INFO\].*?:\s'
    r'(?:\[.*?\]\s)*(?P<player>\w+)\s(?P<msg>'
    r'(?:was (?:slain|shot|blown up|killed|struck|burned|suffocated|drowned|pricked|squashed|starved|impaled|frozen|hit|fireballed|pummeled|finished off|obliterated|skewered|poked|squished|smashed|speared|stung).+'
    r'|drowned(?:\s.+)?'
    r'|died(?:\s.+)?'
    r'|experienced kinetic energy(?:\s.+)?'
    r'|blew up(?:\s.+)?'
    r'|hit the ground too hard(?:\s.+)?'
    r'|fell (?:from a high place|out of the world)(?:\s.+)?'
    r'|went up in flames(?:\s.+)?'
    r'|burned to death(?:\s.+)?'
    r'|tried to swim in lava(?:\s.+)?'
    r'|discovered the floor was lava(?:\s.+)?'
    r'|froze to death(?:\s.+)?'
    r'|left the confines of this world(?:\s.+)?'
    r'|withered away(?:\s.+)?'
    r'|starved to death(?:\s.+)?'
    r'|walked into a cactus.+'
    r'|has made the advancement \[.+?\]'
    r'|has completed the challenge \[.+?\]'
    r'|has reached the goal \[.+?\]'
    r'|joined the game'
    r'|left the game'
    r'|lost connection.+))'
)

# ── Auth ───────────────────────────────────────────────────────────────────────
def _auth_check():
    if not session.get("authenticated"):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"error": "unauthorized"}), 401
        return redirect("/login"), None
    return None, None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        resp, _ = _auth_check()
        if resp: return resp
        return f(*args, **kwargs)
    return decorated

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("authenticated"):
                if request.path.startswith("/api") or request.is_json:
                    return jsonify({"error": "unauthorized"}), 401
                return redirect("/login")
            if session.get("role") not in roles:
                if request.path.startswith("/api") or request.is_json:
                    return jsonify({"error": "forbidden"}), 403
                return redirect("/")
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── ServerInstance ─────────────────────────────────────────────────────────────
class ServerInstance:
    def __init__(self, idx, scfg):
        self.idx         = idx
        self.scfg        = scfg
        self.name        = scfg.get("name", f"Server {idx}")
        self.server_dir  = os.path.abspath(scfg.get("server_dir", "."))
        self.state = {
            "status":        "offline",
            "players":       0,
            "max_players":   20,
            "player_list":   [],
            "cpu":           0,
            "ram":           0,
            "latency":       0,
            "tps":           20,
            "history":       [],
            "cpu_history":   [],
            "ram_history":   [],
            "uptime":        0,
            "chat":          [],
            "events":        [],
            "log":           [],
            "backups_enabled": scfg.get("backups_enabled", True),
            "crash_count":   0,
            "motd":          "",
            "version":       "",
        }
        self.state_lock       = threading.Lock()
        self.proc             = None
        self.start_time       = None
        self.ready_event      = threading.Event()
        self.restart_event    = threading.Event()
        self.crash_times      = []
        self.last_backup_time = time.time()
        self.save_done_event  = threading.Event()
        self._last_cmd_time   = 0.0
        self._mc_server       = None
        self._last_lag_time   = 0.0
        self._last_ticks_behind = 0

    @property
    def mc_server(self):
        if self._mc_server is None:
            self._mc_server = JavaServer.lookup(f"{self.scfg['server_ip']}:{self.scfg['server_port']}")
        return self._mc_server

    def _log(self, kind, msg):
        log_event(kind, f"[{self.name}] {msg}")

    def _resolve_neoforge_args(self, args):
        import glob as _glob
        resolved = []
        for arg in args:
            stripped = arg.lstrip("@")
            if stripped.startswith("libraries/net/neoforged/neoforge/") and stripped.endswith("_args.txt"):
                filename = os.path.basename(stripped)
                pattern  = os.path.join(self.server_dir, "libraries", "net", "neoforged", "neoforge", "*", filename)
                matches  = _glob.glob(pattern)
                if matches:
                    def _ver_key(p):
                        try: return tuple(int(x) for x in os.path.basename(os.path.dirname(p)).split("."))
                        except: return (0,)
                    matches.sort(key=_ver_key)
                    rel   = os.path.relpath(matches[-1], self.server_dir).replace("\\", "/")
                    found = "@" + rel
                    if found != arg:
                        self._log("CONFIG", f"NeoForge args auto-resolved: {arg} -> {found}")
                    resolved.append(found)
                    continue
            resolved.append(arg)
        return resolved

    def read_output(self):
        for raw in self.proc.stdout:
            try: line = ANSI_RE.sub("", raw.decode("utf-8", "replace").rstrip())
            except Exception: continue
            if DONE_RE.search(line):
                self.ready_event.set()
            if "Saved the game" in line:
                self.save_done_event.set()
            with self.state_lock:
                self.state["log"].append(line)
                if len(self.state["log"]) > 500: self.state["log"].pop(0)
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            m  = CHAT_RE.search(line)
            if m:
                with self.state_lock:
                    self.state["chat"].append({"time": ts, "player": m.group(1), "msg": m.group(2)})
                    if len(self.state["chat"]) > 100: self.state["chat"].pop(0)
            e = EVENT_RE.search(line)
            if e:
                with self.state_lock:
                    self.state["events"].append({"time": ts, "player": e.group("player"), "msg": e.group("msg")})
                    if len(self.state["events"]) > 200: self.state["events"].pop(0)
            lag = CANT_KEEP_UP_RE.search(line)
            if lag:
                self._last_lag_time    = time.time()
                self._last_ticks_behind = int(lag.group(1))

    def start(self):
        self.ready_event.clear()
        launch_args = self._resolve_neoforge_args(self.scfg["java_args"])
        self.proc = subprocess.Popen(
            launch_args, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=self.server_dir
        )
        threading.Thread(target=self.read_output, daemon=True).start()

    def stop(self):
        self._log("STOP", "Stop requested")
        try:
            self.proc.stdin.write(b"stop\n"); self.proc.stdin.flush()
            self.proc.wait(timeout=30)
        except Exception:
            self.proc.kill()

    def backup(self):
        backup_dir = os.path.join(self.server_dir, self.scfg["backup_dir"])
        world_dir  = os.path.join(self.server_dir, self.scfg["world_dir"])
        os.makedirs(backup_dir, exist_ok=True)
        ts       = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fname    = f"world_{ts}.zip"
        zip_path = os.path.join(backup_dir, fname)

        server_running = self.state.get("status") == "online" and self.proc and self.proc.poll() is None
        if server_running:
            try:
                self.save_done_event.clear()
                self.proc.stdin.write(b"save-off\n"); self.proc.stdin.flush()
                self.proc.stdin.write(b"save-all flush\n"); self.proc.stdin.flush()
                if not self.save_done_event.wait(timeout=30):
                    self._log("BACKUP", "Warning: save confirmation timed out, proceeding anyway")
            except Exception:
                pass

        skipped = 0
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for root, dirs, files in os.walk(world_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname   = os.path.relpath(file_path, world_dir)
                        try:
                            zf.write(file_path, arcname)
                        except (PermissionError, OSError):
                            skipped += 1
            self.last_backup_time = time.time()
            msg = f"{fname} created"
            if skipped:
                msg += f" ({skipped} locked file(s) skipped)"
            self._log("BACKUP", msg)
        except Exception:
            if os.path.exists(zip_path):
                try: os.remove(zip_path)
                except Exception: pass
            raise
        finally:
            if server_running:
                try:
                    self.proc.stdin.write(b"save-on\n"); self.proc.stdin.flush()
                except Exception:
                    pass

    def backup_scheduler(self):
        while True:
            time.sleep(self.scfg["backup_interval"])
            if self.state["backups_enabled"] and self.state["status"] == "online":
                self.backup()

    def send_command(self, cmd):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.stdin.write((cmd + "\n").encode())
                self.proc.stdin.flush()
                return True
        except Exception as e:
            self._log("COMMAND", f"Failed to send command '{cmd}': {e}")
        return False

    def bossbar_warning(self, seconds_left):
        title = f"Server restarting in {seconds_left} seconds"
        progress = max(0.0, min(1.0, seconds_left / max(self.scfg["restart_warning_times"])))
        self.send_command('bossbar add watchdog:restart {"text":"Server Restart","color":"red"}')
        self.send_command(f'bossbar set watchdog:restart name {{"text":"{title}","color":"red"}}')
        self.send_command("bossbar set watchdog:restart color red")
        self.send_command("bossbar set watchdog:restart style progress")
        self.send_command("bossbar set watchdog:restart max 100")
        self.send_command(f"bossbar set watchdog:restart value {int(progress * 100)}")
        self.send_command("bossbar set watchdog:restart players @a")
        self.send_command(f'tellraw @a {{"text":"[Watchdog] {title}","color":"gold"}}')

    def clear_restart_bossbar(self):
        self.send_command("bossbar remove watchdog:restart")

    def restart_scheduler(self):
        interval     = self.scfg.get("restart_interval", 21600)
        warning_times = sorted(self.scfg.get("restart_warning_times", [600, 300, 60]), reverse=True)
        max_warning  = warning_times[0] if warning_times else 0

        # Sleep until the first warning window begins
        time.sleep(max(0, interval - max_warning))

        while True:
            self._log("RESTART_SCHED", "Scheduled restart warning sequence started")

            # Send bossbar updates at each configured warning time
            prev_seconds = max_warning
            for seconds in warning_times:
                gap = prev_seconds - seconds
                if gap > 0:
                    time.sleep(gap)
                if self.state["status"] == "online":
                    self.bossbar_warning(seconds)
                prev_seconds = seconds

            # Sleep the remaining gap to reach t=0
            if prev_seconds > 0:
                time.sleep(prev_seconds)

            self.clear_restart_bossbar()
            if self.state["status"] == "online":
                self.send_command('tellraw @a {"text":"[Watchdog] Server is restarting now!","color":"red"}')

            if self.proc and self.proc.poll() is None:
                self._log("RESTART_SCHED", "Performing scheduled restart")
                threading.Thread(target=self.stop, daemon=True).start()

            # Sleep until next warning window
            time.sleep(max(0, interval - max_warning))

    def monitor(self):
        self._log("WATCHDOG", "Watchdog started")
        while True:
            now = time.time()
            with self.state_lock:
                self.crash_times[:] = [t for t in self.crash_times if now - t < self.scfg["crash_window"]]
                self.state["crash_count"] = len(self.crash_times)

            if len(self.crash_times) >= self.scfg["max_crashes"]:
                self.state["status"] = "crashed"
                self._log("CRASH_LOOP", f"Max crashes reached, pausing {self.scfg['crash_window']}s")
                self.restart_event.wait(timeout=self.scfg["crash_window"])
                self.restart_event.clear()
                with self.state_lock:
                    self.crash_times.clear()
                    self.state["crash_count"] = 0
                continue

            self.state["status"] = "starting"
            self._log("START", "Starting server process")
            self.start()
            self.start_time = time.time()

            if not self.ready_event.wait(timeout=self.scfg["max_startup_wait"]):
                self.proc.kill()
                self.state["status"] = "offline"
                self._log("CRASH", "Server did not start within timeout")
                with self.state_lock: self.crash_times.append(time.time())
                self.restart_event.wait(timeout=5)
                self.restart_event.clear()
                continue

            self._log("ONLINE", "Server is online")
            failures = 0
            psproc   = psutil.Process(self.proc.pid)
            psproc.cpu_percent()

            while self.proc.poll() is None:
                self._log("POLL_DEBUG", f"loop tick — failures={failures}")
                time.sleep(self.scfg["check_interval"])
                self._log("POLL_DEBUG", f"after sleep — attempting status check")
                self.state["uptime"] = int(time.time() - self.start_time) if self.start_time else 0
                _result  = [None]
                _exc     = [None]
                def _do_status():
                    try:
                        _result[0] = self.mc_server.status()
                    except Exception as e:
                        _exc[0] = e
                _t = threading.Thread(target=_do_status, daemon=True)
                _t.start()
                _t.join(timeout=self.scfg["check_interval"])
                self._log("POLL_DEBUG", f"status thread alive={_t.is_alive()} exc={_exc[0]}")
                try:
                    if _t.is_alive() or _exc[0] is not None:
                        raise Exception(f"status timeout or error: {_exc[0]}")
                    s = _result[0]
                    self.state["status"]      = "online"
                    self.state["players"]     = s.players.online
                    self.state["max_players"] = s.players.max
                    self.state["player_list"] = [p.name for p in s.players.sample] if s.players.sample else []
                    self.state["latency"]     = round(s.latency, 1)
                    self.state["version"]     = s.version.name if s.version else ""
                    self.state["motd"]        = MOTD_RE.sub("", str(s.description)).strip()
                    lag_age = time.time() - self._last_lag_time
                    if lag_age < self.scfg["check_interval"] * 2:
                        tps = max(0.0, min(20.0, 20.0 - (self._last_ticks_behind / self.scfg["check_interval"])))
                    else:
                        tps = 20.0
                    self.state["tps"] = round(tps, 2)
                    with self.state_lock:
                        self.state["history"].append(self.state["tps"])
                        if len(self.state["history"]) > 50: self.state["history"].pop(0)
                    failures = 0
                except Exception as _poll_exc:
                    failures += 1
                    self._log("POLL_FAIL", f"Status check failed (failures={failures}): {type(_poll_exc).__name__}: {_poll_exc}")
                    if failures >= 3: self.state["status"] = "offline"
                    if failures >= 5:
                        self._log("CRASH", "Server stopped responding")
                        self.proc.kill(); break

                try:
                    cpu = round(psproc.cpu_percent(), 1)
                    ram = round(psproc.memory_info().rss / (1024 ** 3), 2)
                    self.state["cpu"] = cpu
                    self.state["ram"] = ram
                    with self.state_lock:
                        self.state["cpu_history"].append(cpu)
                        if len(self.state["cpu_history"]) > 50: self.state["cpu_history"].pop(0)
                        self.state["ram_history"].append(ram)
                        if len(self.state["ram_history"]) > 50: self.state["ram_history"].pop(0)
                except Exception: pass

            self.state["status"]      = "offline"
            self.state["player_list"] = []
            self._log("OFFLINE", "Server process ended")
            with self.state_lock: self.crash_times.append(time.time())
            self.restart_event.wait(timeout=5)
            self.restart_event.clear()

# ── Server registry ────────────────────────────────────────────────────────────
servers = []  # populated in __main__

def _get_server(sid):
    try:
        idx = int(sid)
        if 0 <= idx < len(servers):
            return servers[idx], None
    except (ValueError, TypeError):
        pass
    return None, (jsonify({"error": "Server not found"}), 404)

_login_attempts = {}  # ip -> [count, lockout_until]

# ── Shared HTML fragments ──────────────────────────────────────────────────────
_HEAD_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
header{background:#161b22;border-bottom:1px solid #30363d;padding:14px 28px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.logo{font-size:1.1rem;font-weight:700;color:#58a6ff;letter-spacing:.02em;flex-shrink:0}
.header-right{display:flex;align-items:center;gap:10px}
.status-pill{display:flex;align-items:center;gap:8px;background:#21262d;border:1px solid #30363d;border-radius:20px;padding:6px 14px;font-size:.8rem;font-weight:500}
.dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.dot.online{background:#3fb950;animation:pulse 2s infinite}
.dot.offline{background:#f85149}
.dot.starting{background:#e3b341;animation:pulse .8s infinite}
.dot.crashed{background:#bc8cff}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.btn-sm{padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:.78rem;font-weight:500;transition:opacity .15s}
.btn-sm:hover{opacity:.8}
.btn-logout{background:#21262d;border:1px solid #30363d;color:#8b949e}
nav{display:flex;gap:2px}
.nav-link{padding:6px 14px;border-radius:6px;font-size:.82rem;color:#8b949e;text-decoration:none;transition:all .15s}
.nav-link:hover{color:#e6edf3;background:#21262d}
.nav-link.active{color:#e6edf3;background:#21262d}
.srv-bar{background:#161b22;border-bottom:1px solid #30363d;padding:0 28px;display:flex;gap:4px;flex-wrap:wrap}
.srv-tab{padding:7px 16px;border:none;background:transparent;color:#8b949e;font-size:.8rem;cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .15s;border-bottom:2px solid transparent;margin-bottom:-1px}
.srv-tab:hover{color:#e6edf3}
.srv-tab.active{color:#e6edf3;border-bottom-color:#58a6ff}
.toasts{position:fixed;bottom:20px;right:20px;display:flex;flex-direction:column;gap:8px;z-index:999}
.toast{background:#161b22;border:1px solid #30363d;border-radius:7px;padding:11px 16px;font-size:.82rem;min-width:210px;animation:slidein .25s ease}
.toast.ok{border-left:3px solid #3fb950}.toast.err{border-left:3px solid #f85149}.toast.info{border-left:3px solid #58a6ff}
@keyframes slidein{from{transform:translateX(110%);opacity:0}to{transform:translateX(0);opacity:1}}
"""

_HEADER_HTML = """
<header>
  <div class="logo">&#9729; ATMons</div>
  <nav>
    <a class="nav-link{dash_active}" href="/">Overview</a>
    <a class="nav-link{con_active}" href="/console" id="conLink">Console</a>
    <a class="nav-link{adm_active}" href="/admin" id="adminLink" style="display:none">Users</a>
  </nav>
  <div class="header-right">
    <span id="userBadge" style="font-size:.76rem;color:#8b949e;padding:0 4px"></span>
    <div class="status-pill">
      <div class="dot offline" id="dot"></div>
      <span id="statusText">Connecting&hellip;</span>
    </div>
    <button class="btn-sm btn-logout" onclick="changePassword()">Change PW</button>
    <a href="/logout"><button class="btn-sm btn-logout">Sign out</button></a>
  </div>
</header>
<div class="srv-bar" id="serverBar"></div>
"""

_TOAST_JS = """
function toast(msg,type='ok'){
  const c=document.getElementById('toasts');
  const t=document.createElement('div');
  t.className='toast '+type; t.textContent=msg;
  c.appendChild(t); setTimeout(()=>t.remove(),3500);
}
"""

_STATUS_JS = """
let lastStatus=null;
function notify(title,body){
  try{if(typeof Notification!=='undefined'&&Notification.permission==='granted')new Notification(title,{body});}catch(e){}
}
function updateStatus(st){
  const dot=document.getElementById('dot');
  if(dot) dot.className='dot '+st;
  const labels={online:'Online',offline:'Offline',starting:'Starting\u2026',crashed:'Crashed'};
  const el=document.getElementById('statusText');
  if(el) el.textContent=labels[st]||st;
  if(lastStatus!==null&&lastStatus!==st){
    const msgs={online:'Server is now online.',offline:'Server has gone offline.',
                crashed:'Server has crashed and stopped restarting.',starting:'Server is starting up.'};
    if(msgs[st]) notify('ATMons',msgs[st]);
  }
  lastStatus=st;
}
try{if(typeof Notification!=='undefined'&&Notification.permission==='default')Notification.requestPermission();}catch(e){}
async function changePassword(){
  const cur=prompt('Current password:');
  if(!cur)return;
  const nw=prompt('New password:');
  if(!nw)return;
  if(prompt('Confirm new password:')!==nw){alert('Passwords do not match.');return;}
  try{
    const r=await fetch('/api/me/password',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current:cur,new_password:nw})}).then(r=>r.json());
    if(r.ok)alert('Password changed. Please log in again.');
    else alert('Error: '+r.error);
  }catch(e){alert('Failed to change password.');}
}
"""

_SERVER_BAR_JS = """
let currentSid=0;
let _serverRoles={};
async function loadServerBar(){
  try{
    const list=await fetch('/api/servers').then(r=>r.json());
    const bar=document.getElementById('serverBar');
    if(!bar)return;
    list.forEach(function(s){ _serverRoles[s.id]=s.role; });
    if(list.length>0) currentSid=list[0].id;
    if(list.length<=1){bar.style.display='none';}
    else{
      bar.innerHTML=list.map(function(s){
        return '<button class="srv-tab'+(s.id===currentSid?' active':'')+'" onclick="selectServer('+s.id+')" id="srvTab'+s.id+'">'
          +'<span class="dot '+s.status+'" style="width:7px;height:7px;display:inline-block"></span> '+s.name+'</button>';
      }).join('');
    }
    if(typeof _applyServerRole==='function') _applyServerRole(currentSid);
  }catch(e){}
}
function _updateServerTabDots(list){
  list.forEach(function(s){
    const tab=document.getElementById('srvTab'+s.id);
    if(!tab)return;
    const dot=tab.querySelector('.dot');
    if(dot) dot.className='dot '+s.status;
  });
}
async function refreshServerBar(){
  try{
    const list=await fetch('/api/servers').then(r=>r.json());
    _updateServerTabDots(list);
  }catch(e){}
}
"""

# ── Login page ─────────────────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ATMons &mdash; Login</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='50' fill='%2358a6ff'/%3E%3Ctext x='50' y='68' font-size='58' text-anchor='middle' fill='white' font-family='sans-serif' font-weight='bold'%3EA%3C/text%3E%3C/svg%3E">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:36px 32px;width:100%;max-width:360px}
h1{font-size:1.1rem;font-weight:700;color:#58a6ff;margin-bottom:24px;text-align:center}
label{font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.07em;display:block;margin-bottom:6px}
input[type=password]{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 12px;color:#e6edf3;font-size:.9rem;outline:none;transition:border-color .15s;margin-bottom:16px}
input[type=password]:focus{border-color:#58a6ff}
button{width:100%;background:#238636;border:none;border-radius:6px;color:#fff;padding:10px;font-size:.9rem;font-weight:500;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}
.err{color:#f85149;font-size:.82rem;margin-bottom:12px;text-align:center}
</style>
</head>
<body>
<div class="box">
  <h1>&#9729; ATMons Dashboard</h1>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="post">
    <label>Username</label>
    <input type="text" name="username" autofocus autocomplete="username" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 12px;color:#e6edf3;font-size:.9rem;outline:none;margin-bottom:16px">
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password">
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>"""

# ── Dashboard ──────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATMons &mdash; Overview</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2020/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='50' fill='%2358a6ff'/%3E%3Ctext x='50' y='68' font-size='58' text-anchor='middle' fill='white' font-family='sans-serif' font-weight='bold'%3EA%3C/text%3E%3C/svg%3E">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
""" + _HEAD_CSS + """
main{max-width:1200px;margin:0 auto;padding:24px}
.server-info{font-size:.8rem;color:#8b949e;margin-bottom:16px;display:none;gap:10px;align-items:center}
.server-info .motd{color:#c9d1d9}
.server-info .sep{color:#30363d}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 20px}
.card-label{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px}
.card-value{font-size:1.75rem;font-weight:700;color:#e6edf3;line-height:1}
.card-unit{font-size:.85rem;color:#8b949e;margin-left:3px;font-weight:400}
.bar{height:4px;background:#21262d;border-radius:2px;margin-top:14px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;transition:width .6s ease}
.bar-blue{background:#58a6ff}.bar-green{background:#3fb950}.bar-orange{background:#f0883e}.bar-purple{background:#bc8cff}
.section{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin-bottom:20px}
.section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.section-title{font-size:.72rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.07em}
.player-list{display:flex;flex-wrap:wrap;gap:8px}
.player-badge{background:#21262d;border:1px solid #30363d;border-radius:20px;padding:4px 12px;font-size:.8rem;color:#c9d1d9}
.empty-note{color:#484f58;font-size:.82rem}
.chart-tabs{display:flex;gap:4px}
.tab-btn{padding:5px 14px;border:1px solid #30363d;border-radius:6px;background:transparent;color:#8b949e;font-size:.78rem;cursor:pointer;transition:all .15s}
.tab-btn.active{background:#21262d;color:#e6edf3;border-color:#58a6ff}
.chart-wrap{position:relative;height:180px}
.chart-pane{display:none}.chart-pane.active{display:block}
.actions{display:flex;gap:10px;flex-wrap:wrap}
.btn{padding:9px 18px;border:none;border-radius:6px;cursor:pointer;font-size:.85rem;font-weight:500;display:inline-flex;align-items:center;gap:7px;transition:opacity .15s,transform .1s}
.btn:hover:not(:disabled){opacity:.85}
.btn:active:not(:disabled){transform:scale(.97)}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-red{background:#da3633;color:#fff}
.btn-green{background:#238636;color:#fff}
.btn-toggle{color:#fff}.btn-toggle.on{background:#238636}.btn-toggle.off{background:#6e7681;border:1px solid #30363d}
.countdown{font-size:.75rem;color:#8b949e}
.countdown.due{color:#e3b341}
.backup-table{width:100%;border-collapse:collapse;font-size:.82rem}
.backup-table th{text-align:left;color:#8b949e;font-weight:500;padding:6px 10px;border-bottom:1px solid #21262d}
.backup-table td{padding:7px 10px;border-bottom:1px solid #0d1117;color:#c9d1d9;vertical-align:middle}
.backup-table tr:last-child td{border-bottom:none}
.backup-dl{color:#58a6ff;text-decoration:none;font-size:.78rem;margin-right:10px}
.backup-dl:hover{text-decoration:underline}
.backup-del{background:none;border:none;color:#f85149;font-size:.78rem;cursor:pointer;padding:0}
.backup-del:hover{text-decoration:underline}
.feed-tabs{display:flex;gap:4px;margin-bottom:10px}
.feed-tab{padding:4px 14px;border:1px solid #30363d;border-radius:6px;background:transparent;color:#8b949e;font-size:.78rem;cursor:pointer;transition:all .15s}
.feed-tab.active{background:#21262d;color:#e6edf3;border-color:#58a6ff}
.feed-pane{display:none}.feed-pane.active{display:block}
#chatLog,#eventLog{font-family:'Consolas','Courier New',monospace;font-size:.82rem;background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:12px;height:200px;overflow-y:auto}
#chatLog:empty::before{content:'No chat messages yet.';color:#484f58}
#eventLog:empty::before{content:'No events yet.';color:#484f58}
.chat-line,.event-line{padding:2px 0;line-height:1.5;display:flex;gap:8px}
.chat-time,.event-time{color:#484f58;flex-shrink:0}
.chat-player{color:#58a6ff;font-weight:600;flex-shrink:0}
.chat-msg{color:#c9d1d9;word-break:break-word}
.event-player{color:#3fb950;font-weight:600;flex-shrink:0}
.event-msg{color:#c9d1d9;word-break:break-word}
#crashBanner{background:#1a0f2e;border:1px solid #bc8cff;border-radius:8px;padding:14px 18px;margin-bottom:20px;display:none;font-size:.85rem;color:#bc8cff}
.footer{text-align:center;font-size:.72rem;color:#484f58;padding:12px}
.uptime-val{font-size:1.2rem}
</style>
</head>
<body>
""" + _HEADER_HTML.replace("{dash_active}", " active").replace("{con_active}", "").replace("{adm_active}", "") + """
<main>
  <div id="crashBanner">&#9888; Server has crashed too many times and stopped restarting. It will retry automatically.</div>
  <div id="errBar" style="display:none;background:#1a0a0a;border:1px solid #f85149;border-radius:8px;padding:14px 18px;margin-bottom:20px;font-size:.85rem;color:#f85149"></div>

  <div class="server-info" id="serverInfo">
    <span class="motd" id="motdText"></span>
    <span class="sep">&bull;</span>
    <span id="versionText"></span>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-label">Players Online</div>
      <div class="card-value" id="players">&mdash;</div>
      <div class="bar"><div class="bar-fill bar-blue" id="playersBar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="card-label">CPU Usage</div>
      <div class="card-value" id="cpu">&mdash;<span class="card-unit">%</span></div>
      <div class="bar"><div class="bar-fill bar-blue" id="cpuBar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="card-label">RAM Usage</div>
      <div class="card-value" id="ram">&mdash;<span class="card-unit">GB</span></div>
      <div class="bar"><div class="bar-fill bar-green" id="ramBar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="card-label">TPS</div>
      <div class="card-value" id="tps">&mdash;<span class="card-unit">/20</span></div>
      <div class="bar"><div class="bar-fill bar-orange" id="tpsBar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="card-label">Latency</div>
      <div class="card-value" id="latency">&mdash;<span class="card-unit">ms</span></div>
      <div class="bar"><div class="bar-fill bar-purple" id="latencyBar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="card-label">Uptime</div>
      <div class="card-value uptime-val" id="uptime">&mdash;</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header"><div class="section-title">Players Online</div></div>
    <div class="player-list" id="playerList"><span class="empty-note">No players online.</span></div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">History</div>
      <div class="chart-tabs">
        <button class="tab-btn active" onclick="switchTab('tps',this)">TPS</button>
        <button class="tab-btn" onclick="switchTab('cpu',this)">CPU</button>
        <button class="tab-btn" onclick="switchTab('ram',this)">RAM</button>
      </div>
    </div>
    <div id="pane-tps" class="chart-pane active"><div class="chart-wrap"><canvas id="chartTps"></canvas></div></div>
    <div id="pane-cpu" class="chart-pane"><div class="chart-wrap"><canvas id="chartCpu"></canvas></div></div>
    <div id="pane-ram" class="chart-pane"><div class="chart-wrap"><canvas id="chartRam"></canvas></div></div>
  </div>

  <div class="section" id="actionsSection">
    <div class="section-header"><div class="section-title">Actions</div></div>
    <div class="actions">
      <button class="btn btn-green"  id="btnStart"   onclick="act('start')"   style="display:none">&#9654; Start</button>
      <button class="btn btn-red"    id="btnRestart" onclick="act('restart')" style="display:none">&#8635; Restart</button>
      <button class="btn btn-red"    id="btnStop"    onclick="act('stop')"    style="display:none">&#9632; Stop</button>
      <button class="btn btn-green"  id="btnBackup"  onclick="act('backup')">&#8659; Backup Now</button>
      <button class="btn btn-toggle on" id="btnToggle" onclick="toggleBackups()">Auto-Backup: ON</button>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">Recent Backups</div>
      <div class="countdown" id="backupCountdown"></div>
    </div>
    <table class="backup-table">
      <thead><tr><th>File</th><th>Size</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody id="backupList"><tr><td colspan="4" style="color:#484f58">Loading&hellip;</td></tr></tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-header"><div class="section-title">Activity</div></div>
    <div class="feed-tabs">
      <button class="feed-tab active" onclick="switchFeed('chat',this)">Chat</button>
      <button class="feed-tab" onclick="switchFeed('events',this)">Events</button>
    </div>
    <div id="feed-chat" class="feed-pane active"><div id="chatLog"></div></div>
    <div id="feed-events" class="feed-pane"><div id="eventLog"></div></div>
  </div>
</main>

<div class="footer">Last updated: <span id="lastUpdate">&mdash;</span></div>
<div class="toasts" id="toasts"></div>

<script>
const MAX_RAM=8;
let charts={}, lastChatLen=0, lastEventLen=0, backupsEnabled=true, lastPollOk=Date.now();
""" + _STATUS_JS + _TOAST_JS + _SERVER_BAR_JS + """
function _applyServerRole(sid){
  const role=_serverRoles[sid];
  const isViewer=(role!=='admin'&&role!=='owner');
  const as=document.getElementById('actionsSection');
  if(as) as.style.display=isViewer?'none':'';
}
function selectServer(sid){
  currentSid=sid;
  lastChatLen=0; lastEventLen=0;
  document.getElementById('chatLog').innerHTML='';
  document.getElementById('eventLog').innerHTML='';
  document.getElementById('playerList').innerHTML='<span class="empty-note">Loading\u2026</span>';
  ['tps','cpu','ram'].forEach(function(k){
    if(charts[k]){charts[k].data.labels=[];charts[k].data.datasets[0].data=[];charts[k].update();}
  });
  document.querySelectorAll('.srv-tab').forEach(function(t){t.classList.toggle('active',t.id==='srvTab'+sid);});
  lastStatus=null;
  _applyServerRole(sid);
  poll(); pollBackups();
}
function mkChart(id,color,yMax,unit){
  return new Chart(document.getElementById(id),{
    type:'line',
    data:{labels:[],datasets:[{data:[],borderColor:color,
      backgroundColor:color.replace(')',',0.12)').replace('rgb','rgba'),
      borderWidth:2,pointRadius:0,fill:true,tension:.35}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,
      scales:{y:{min:0,max:yMax,grid:{color:'#21262d'},ticks:{color:'#8b949e',
        callback:v=>v+unit}},x:{display:false}},
      plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>c.parsed.y+unit}}}}
  });
}
function initCharts(){
  charts.tps=mkChart('chartTps','rgb(240,136,62)',20,'/20');
  charts.cpu=mkChart('chartCpu','rgb(88,166,255)',100,'%');
  charts.ram=mkChart('chartRam','rgb(63,185,80)',MAX_RAM,'GB');
}
function switchTab(name,btn){
  document.querySelectorAll('.chart-pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('pane-'+name).classList.add('active');
  btn.classList.add('active');
  charts[name].resize();
}
function updChart(c,data){if(!c)return;c.data.labels=data.map((_,i)=>i);c.data.datasets[0].data=data;c.update();}
function fmtUptime(s){
  if(!s&&s!==0)return'\u2014';
  const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60),sec=s%60;
  if(d)return d+'d '+h+'h '+m+'m'; if(h)return h+'h '+m+'m '+sec+'s'; return m+'m '+sec+'s';
}
function fmtCountdown(s){
  if(s===null||s===undefined||s<0)return'';
  if(s===0)return'Backup due now';
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  if(h)return'Next backup: '+h+'h '+m+'m';
  if(m)return'Next backup: '+m+'m '+sec+'s';
  return'Next backup: '+sec+'s';
}
function switchFeed(name,btn){
  document.querySelectorAll('.feed-tab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.feed-pane').forEach(p=>p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('feed-'+name).classList.add('active');
}
function renderEvents(events){
  const log=document.getElementById('eventLog');
  if(events.length===lastEventLen)return;
  const atBottom=log.scrollHeight-log.scrollTop<=log.clientHeight+10;
  events.slice(lastEventLen).forEach(function(ev){
    const line=document.createElement('div');line.className='event-line';
    line.innerHTML='<span class="event-time">'+ev.time+'</span>'
      +'<span class="event-player">'+ev.player+'</span>'
      +'<span class="event-msg">'+ev.msg+'</span>';
    log.appendChild(line);
  });
  lastEventLen=events.length;
  if(atBottom)log.scrollTop=log.scrollHeight;
}
function renderPlayers(list,maxP){
  const el=document.getElementById('playerList');
  if(!list||!list.length){el.innerHTML='<span class="empty-note">No players online.</span>';return;}
  el.innerHTML=list.map(n=>'<span class="player-badge">'+n+'</span>').join('');
}
function renderChat(messages){
  const log=document.getElementById('chatLog');
  if(messages.length===lastChatLen)return;
  const atBottom=log.scrollHeight-log.scrollTop<=log.clientHeight+10;
  messages.slice(lastChatLen).forEach(function(m){
    const line=document.createElement('div');line.className='chat-line';
    line.innerHTML='<span class="chat-time">'+m.time+'</span>'
      +'<span class="chat-player">&lt;'+m.player+'&gt;</span>'
      +'<span class="chat-msg">'+m.msg+'</span>';
    log.appendChild(line);
  });
  lastChatLen=messages.length;
  if(atBottom)log.scrollTop=log.scrollHeight;
}
function renderBackups(list){
  const tbody=document.getElementById('backupList');
  if(!list||!list.length){
    tbody.innerHTML='<tr><td colspan="4" style="color:#484f58">No backups found.</td></tr>';return;
  }
  tbody.innerHTML=list.map(function(b){
    return '<tr><td>'+b.name+'</td><td>'+b.size+' MB</td><td>'+b.time+'</td>'
      +'<td><a class="backup-dl" href="/backup/'+currentSid+'/download/'+b.name+'" download>Download</a>'
      +'<button class="backup-del" onclick="deleteBackup(\\''+b.name+'\\')">Delete</button></td></tr>';
  }).join('');
}
async function deleteBackup(name){
  if(!confirm('Delete '+name+'?'))return;
  try{
    const r=await fetch('/backup/'+currentSid+'/delete/'+name,{method:'POST'}).then(r=>r.json());
    if(r.ok){toast('Backup deleted','ok');pollBackups();}
    else toast('Delete failed: '+r.error,'err');
  }catch(e){toast('Delete failed','err');}
}
function showErr(msg){const b=document.getElementById('errBar');if(b){b.style.display='block';b.textContent=msg;}}
function clearErr(){const b=document.getElementById('errBar');if(b)b.style.display='none';}
async function poll(){
  try{
    const r=await fetch('/api/'+currentSid);
    if(r.status===401){window.location='/login';return;}
    if(!r.ok){
      let errText='HTTP '+r.status;
      try{const j=await r.json();if(j.error)errText+=': '+j.error;}catch(_){}
      showErr('API error \u2014 '+errText+'. Check watchdog.log for details.');
      return;
    }
    const data=await r.json();
    if(data.error){showErr('API error: '+data.error);return;}
    clearErr();
    updateStatus(data.status);
    document.getElementById('crashBanner').style.display=data.status==='crashed'?'block':'none';

    const si=document.getElementById('serverInfo');
    if(data.motd||data.version){
      si.style.display='flex';
      document.getElementById('motdText').textContent=data.motd||'';
      document.getElementById('versionText').textContent=data.version?'v'+data.version:'';
    }

    const st=data.status;
    document.getElementById('btnStart').style.display=(st==='offline'||st==='crashed')?'':'none';
    document.getElementById('btnRestart').style.display=(st==='online')?'':'none';
    document.getElementById('btnStop').style.display=(st==='online'||st==='starting')?'':'none';
    document.getElementById('btnBackup').disabled=(st!=='online');

    const maxP=data.max_players||20;
    document.getElementById('players').textContent=data.players!=null?data.players:'\u2014';
    document.getElementById('playersBar').style.width=Math.min((data.players/maxP)*100,100)+'%';
    document.getElementById('cpu').innerHTML=data.cpu+'<span class="card-unit">%</span>';
    document.getElementById('cpuBar').style.width=Math.min(data.cpu,100)+'%';
    document.getElementById('ram').innerHTML=data.ram+'<span class="card-unit">GB</span>';
    document.getElementById('ramBar').style.width=Math.min((data.ram/MAX_RAM)*100,100)+'%';
    document.getElementById('tps').innerHTML=data.tps+'<span class="card-unit">/20</span>';
    document.getElementById('tpsBar').style.width=(data.tps/20)*100+'%';
    document.getElementById('latency').innerHTML=data.latency+'<span class="card-unit">ms</span>';
    document.getElementById('latencyBar').style.width=Math.min((data.latency/200)*100,100)+'%';
    document.getElementById('uptime').textContent=fmtUptime(data.uptime);

    updChart(charts.tps,data.history||[]);
    updChart(charts.cpu,data.cpu_history||[]);
    updChart(charts.ram,data.ram_history||[]);
    renderPlayers(data.player_list||[],maxP);
    renderChat(data.chat||[]);
    renderEvents(data.events||[]);

    backupsEnabled=data.backups_enabled;
    const tb=document.getElementById('btnToggle');
    tb.className='btn btn-toggle '+(backupsEnabled?'on':'off');
    tb.textContent='Auto-Backup: '+(backupsEnabled?'ON':'OFF');

    const cd=document.getElementById('backupCountdown');
    if(data.backups_enabled&&data.next_backup_in!=null){
      cd.textContent=fmtCountdown(data.next_backup_in);
      cd.className='countdown'+(data.next_backup_in===0?' due':'');
    }else{cd.textContent='';cd.className='countdown';}

    lastPollOk=Date.now();
    const lu=document.getElementById('lastUpdate');
    lu.textContent=new Date().toLocaleTimeString();
    lu.style.color='';
  }catch(e){console.error('poll error:',e);showErr('Poll exception: '+e.message);}
}
async function pollBackups(){
  try{renderBackups(await fetch('/api/'+currentSid+'/backups').then(r=>r.json()));}catch(e){}
}
async function act(action){
  if(action==='stop'&&!confirm('Stop the server?'))return;
  if(action==='restart'&&!confirm('Restart the server?'))return;
  const ids={restart:'btnRestart',stop:'btnStop',backup:'btnBackup',start:'btnStart'};
  const btn=document.getElementById(ids[action]);
  if(btn)btn.disabled=true;
  try{
    await fetch('/server/'+currentSid+'/'+action);
    const msgs={restart:'Restarting\u2026',stop:'Stopping\u2026',backup:'Backup started!',start:'Starting\u2026'};
    toast(msgs[action]||'Done','info');
    if(action==='backup')setTimeout(pollBackups,4000);
  }catch(e){toast('Action failed','err');}
  if(btn)setTimeout(()=>btn.disabled=false,5000);
}
async function toggleBackups(){
  try{
    const r=await fetch('/server/'+currentSid+'/toggle_backups').then(r=>r.json());
    toast('Auto-backup '+(r.enabled?'enabled':'disabled'),'info');
  }catch(e){toast('Failed','err');}
}
async function fetchMe(){
  try{
    const d=await fetch('/api/me').then(r=>r.json());
    const ub=document.getElementById('userBadge');
    if(ub) ub.textContent=d.username+(d.role==='owner'?' \u00b7 owner':d.role==='admin'?' \u00b7 admin':'');
    const al=document.getElementById('adminLink');
    if(al&&(d.role==='admin'||d.role==='owner')) al.style.display='';
    // Hide console nav entirely for pure viewers (no admin role on any server)
    if(d.role!=='admin'&&d.role!=='owner'){
      const cl=document.getElementById('conLink');
      if(cl)cl.style.display='none';
    }
  }catch(e){}
}
try{initCharts();}catch(e){console.error('Chart.js unavailable:',e);}
fetchMe(); loadServerBar(); poll(); pollBackups();
setInterval(poll,5000); setInterval(pollBackups,30000); setInterval(refreshServerBar,10000);
setInterval(function(){
  const age=(Date.now()-lastPollOk)/1000;
  const el=document.getElementById('lastUpdate');
  if(!el)return;
  if(age>30)el.style.color='#f85149';
  else if(age>15)el.style.color='#e3b341';
  else el.style.color='';
},5000);
</script>
</body>
</html>"""

# ── Console page ───────────────────────────────────────────────────────────────
CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATMons &mdash; Console</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='50' fill='%2358a6ff'/%3E%3Ctext x='50' y='68' font-size='58' text-anchor='middle' fill='white' font-family='sans-serif' font-weight='bold'%3EA%3C/text%3E%3C/svg%3E">
<style>
""" + _HEAD_CSS + """
body{height:100vh;display:flex;flex-direction:column}
header{flex-shrink:0}
.srv-bar{flex-shrink:0}
.console-wrap{flex:1;display:flex;flex-direction:column;padding:14px 16px;gap:8px;min-height:0;overflow:hidden}
.page-tabs{display:flex;border-bottom:1px solid #30363d;flex-shrink:0;margin-bottom:4px}
.page-tab{padding:8px 18px;border:none;background:transparent;color:#8b949e;font-size:.85rem;cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;margin-bottom:-1px}
.page-tab.active{color:#e6edf3;border-bottom-color:#58a6ff}
.page-tab:hover:not(.active){color:#c9d1d9}
.page-pane{display:none;flex:1;flex-direction:column;gap:8px;min-height:0;overflow:hidden}
.page-pane.active{display:flex}
.toolbar{display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.filter-btns,.toolbar-right{display:flex;gap:4px}
.filter-btn,.tool-btn{padding:4px 12px;border:1px solid #30363d;border-radius:6px;background:transparent;color:#8b949e;font-size:.76rem;cursor:pointer;transition:all .15s}
.filter-btn:hover,.tool-btn:hover{color:#e6edf3;background:#21262d}
.filter-btn.active{background:#21262d;color:#e6edf3;border-color:#58a6ff}
#consoleLog,#watchdogLog{flex:1;font-family:'Consolas','Courier New',monospace;font-size:.8rem;background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;overflow-y:auto;word-break:break-all;min-height:0}
#consoleLog:empty::before{content:'Waiting for server output\2026';color:#484f58}
#watchdogLog:empty::before{content:'No watchdog events yet.';color:#484f58}
.log-line{padding:1px 0;line-height:1.6;white-space:pre-wrap}
.log-line.warn{color:#e3b341}.log-line.err{color:#f85149}.log-line.done{color:#3fb950}.log-line.info{color:#8b949e}
#consoleLog.filter-warn .log-line.info,
#consoleLog.filter-warn .log-line.done{display:none}
#consoleLog.filter-err .log-line.info,
#consoleLog.filter-err .log-line.done,
#consoleLog.filter-err .log-line.warn{display:none}
.wlog-line{padding:2px 0;line-height:1.5;white-space:pre-wrap}
.wlog-line.start,.wlog-line.online,.wlog-line.watchdog{color:#58a6ff}
.wlog-line.backup{color:#3fb950}
.wlog-line.offline,.wlog-line.stop{color:#8b949e}
.wlog-line.crash,.wlog-line.crash-loop{color:#f85149}
.cmd-row{display:flex;align-items:center;gap:8px;flex-shrink:0}
.cmd-prefix{color:#484f58;font-family:monospace;font-size:1.1rem}
.cmd-input{flex:1;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 14px;color:#e6edf3;font-family:'Consolas','Courier New',monospace;font-size:.85rem;outline:none;transition:border-color .15s}
.cmd-input:focus{border-color:#58a6ff}
.btn-send{padding:10px 20px;background:#1f6feb;border:none;border-radius:6px;color:#fff;font-size:.85rem;font-weight:500;cursor:pointer;flex-shrink:0;transition:opacity .15s}
.btn-send:hover:not(:disabled){opacity:.85}
.btn-send:disabled{opacity:.4;cursor:not-allowed}
</style>
</head>
<body>
""" + _HEADER_HTML.replace("{dash_active}", "").replace("{con_active}", " active").replace("{adm_active}", "") + """
<div class="console-wrap">
  <div class="page-tabs">
    <button class="page-tab active" onclick="switchPage('server',this)">Server Log</button>
    <button class="page-tab" onclick="switchPage('watchdog',this)">Watchdog Log</button>
  </div>

  <div id="page-server" class="page-pane active">
    <div class="toolbar">
      <div class="filter-btns">
        <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
        <button class="filter-btn" onclick="setFilter('warn',this)">Warn+</button>
        <button class="filter-btn" onclick="setFilter('err',this)">Error</button>
      </div>
      <div class="toolbar-right">
        <button class="tool-btn" onclick="clearLog()">Clear</button>
        <button class="tool-btn" onclick="exportLog()">Export</button>
      </div>
    </div>
    <div id="consoleLog"></div>
    <div class="cmd-row">
      <span class="cmd-prefix">&gt;</span>
      <input id="cmdInput" class="cmd-input" type="text" placeholder="Type a command\u2026 (\u2191\u2193 for history)" autocomplete="off" spellcheck="false">
      <button class="btn-send" id="btnSend" onclick="sendCmd()">Send</button>
    </div>
  </div>

  <div id="page-watchdog" class="page-pane">
    <div class="toolbar">
      <div></div>
      <div class="toolbar-right">
        <button class="tool-btn" onclick="exportWatchdogLog()">Export</button>
      </div>
    </div>
    <div id="watchdogLog"></div>
  </div>
</div>
<div class="toasts" id="toasts"></div>

<script>
let lastLogLen=0, wlogLen=0, cmdHistory=[], histIdx=-1;
""" + _STATUS_JS + _TOAST_JS + _SERVER_BAR_JS + """
function selectServer(sid){
  currentSid=sid;
  lastLogLen=0;
  document.getElementById('consoleLog').innerHTML='';
  document.querySelectorAll('.srv-tab').forEach(function(t,i){t.classList.toggle('active',i===sid);});
  lastStatus=null;
  poll();
}
function lineClass(line){
  if(/WARN/.test(line))        return 'warn';
  if(/ERROR|FATAL/.test(line)) return 'err';
  if(/Done \\(/.test(line))    return 'done';
  return 'info';
}
function wlogClass(line){
  const m=line.match(/\\[([A-Z_]+)\\]/);
  if(!m) return '';
  return m[1].toLowerCase().replace(/_/g,'-');
}
function renderLog(lines){
  const log=document.getElementById('consoleLog');
  if(lines.length===lastLogLen)return;
  const atBottom=log.scrollHeight-log.scrollTop<=log.clientHeight+10;
  lines.slice(lastLogLen).forEach(function(text){
    const el=document.createElement('div');
    el.className='log-line '+lineClass(text);
    el.textContent=text;
    log.appendChild(el);
  });
  lastLogLen=lines.length;
  if(atBottom)log.scrollTop=log.scrollHeight;
}
function renderWatchdogLog(lines){
  const log=document.getElementById('watchdogLog');
  if(lines.length===wlogLen)return;
  const atBottom=log.scrollHeight-log.scrollTop<=log.clientHeight+10;
  lines.slice(wlogLen).forEach(function(text){
    const el=document.createElement('div');
    el.className='wlog-line '+wlogClass(text);
    el.textContent=text;
    log.appendChild(el);
  });
  wlogLen=lines.length;
  if(atBottom)log.scrollTop=log.scrollHeight;
}
function setFilter(name,btn){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const log=document.getElementById('consoleLog');
  log.classList.remove('filter-warn','filter-err');
  if(name!=='all')log.classList.add('filter-'+name);
}
function clearLog(){document.getElementById('consoleLog').innerHTML='';}
function exportLog(){
  const lines=Array.from(document.getElementById('consoleLog').querySelectorAll('.log-line'))
    .map(el=>el.textContent).join('\\n');
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([lines],{type:'text/plain'}));
  a.download='server-'+new Date().toISOString().slice(0,19).replace(/[:.]/g,'-')+'.log';
  a.click();URL.revokeObjectURL(a.href);
}
function exportWatchdogLog(){
  const lines=Array.from(document.getElementById('watchdogLog').querySelectorAll('.wlog-line'))
    .map(el=>el.textContent).join('\\n');
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([lines],{type:'text/plain'}));
  a.download='watchdog-'+new Date().toISOString().slice(0,10)+'.log';
  a.click();URL.revokeObjectURL(a.href);
}
function switchPage(name,btn){
  document.querySelectorAll('.page-tab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.page-pane').forEach(p=>p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('page-'+name).classList.add('active');
  if(name==='watchdog') pollWatchdogLog();
}
async function poll(){
  try{
    const data=await fetch('/api/'+currentSid+'/log').then(r=>r.json());
    updateStatus(data.status);
    renderLog(data.log||[]);
  }catch(e){}
}
async function pollWatchdogLog(){
  try{
    const data=await fetch('/api/watchdog_log').then(r=>r.json());
    renderWatchdogLog(data.lines||[]);
  }catch(e){}
}
async function sendCmd(){
  const input=document.getElementById('cmdInput');
  const cmd=input.value.trim();
  if(!cmd)return;
  input.value=''; histIdx=-1;
  cmdHistory.push(cmd);
  if(cmdHistory.length>50)cmdHistory.shift();
  const btn=document.getElementById('btnSend');
  btn.disabled=true;
  try{
    const r=await fetch('/server/'+currentSid+'/command',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({cmd})});
    const data=await r.json();
    if(data.ok) toast('Sent: '+cmd,'info');
    else toast('Error: '+data.error,'err');
  }catch(e){toast('Failed to send command.','err');}
  setTimeout(()=>btn.disabled=false,500);
}
document.getElementById('cmdInput').addEventListener('keydown',function(e){
  if(e.key==='Enter'){
    sendCmd();
  }else if(e.key==='ArrowUp'){
    e.preventDefault();
    if(!cmdHistory.length)return;
    histIdx=Math.min(histIdx+1,cmdHistory.length-1);
    this.value=cmdHistory[cmdHistory.length-1-histIdx];
    setTimeout(()=>this.setSelectionRange(this.value.length,this.value.length),0);
  }else if(e.key==='ArrowDown'){
    e.preventDefault();
    if(histIdx<=0){histIdx=-1;this.value='';return;}
    histIdx--;
    this.value=cmdHistory[cmdHistory.length-1-histIdx];
  }
});
async function fetchMe(){
  try{
    const d=await fetch('/api/me').then(r=>r.json());
    const ub=document.getElementById('userBadge');
    if(ub) ub.textContent=d.username+(d.role==='owner'?' \u00b7 owner':d.role==='admin'?' \u00b7 admin':'');
    const al=document.getElementById('adminLink');
    if(al&&(d.role==='admin'||d.role==='owner')) al.style.display='';
  }catch(e){}
}
fetchMe(); loadServerBar(); poll(); setInterval(poll,2000); setInterval(pollWatchdogLog,10000); setInterval(refreshServerBar,10000);
</script>
</body>
</html>"""

# ── Admin page ─────────────────────────────────────────────────────────────────
ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATMons &mdash; Admin</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='50' fill='%2358a6ff'/%3E%3Ctext x='50' y='68' font-size='58' text-anchor='middle' fill='white' font-family='sans-serif' font-weight='bold'%3EA%3C/text%3E%3C/svg%3E">
<style>
""" + _HEAD_CSS + """
main{max-width:900px;margin:0 auto;padding:24px}
.section{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin-bottom:20px}
.section-title{font-size:.72rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.07em;margin-bottom:16px}
.user-table{width:100%;border-collapse:collapse;font-size:.85rem}
.user-table th{text-align:left;color:#8b949e;font-weight:500;padding:8px 10px;border-bottom:1px solid #21262d}
.user-table td{padding:9px 10px;border-bottom:1px solid #0d1117;color:#c9d1d9;vertical-align:middle}
.user-table tr:last-child td{border-bottom:none}
.role-badge{padding:2px 10px;border-radius:20px;font-size:.72rem;font-weight:600}
.role-badge.owner{background:#2d1f00;color:#f0a000;border:1px solid #9e6a03}
.role-badge.admin{background:#1f3a1f;color:#3fb950;border:1px solid #238636}
.role-badge.viewer{background:#1a1f2e;color:#8b949e;border:1px solid #30363d}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-group{display:flex;flex-direction:column;gap:5px;flex:1;min-width:140px}
.form-label{font-size:.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:.07em}
.form-input{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:9px 12px;color:#e6edf3;font-size:.85rem;outline:none;transition:border-color .15s}
.form-input:focus{border-color:#58a6ff}
select.form-input{cursor:pointer}
.btn{padding:9px 18px;border:none;border-radius:6px;cursor:pointer;font-size:.85rem;font-weight:500;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn-green{background:#238636;color:#fff}
.btn-red{background:#da3633;color:#fff}
.btn-sm{padding:5px 12px;border:none;border-radius:6px;cursor:pointer;font-size:.78rem;font-weight:500;transition:opacity .15s}
.btn-sm:hover{opacity:.8}
.btn-sm-red{background:#da3633;color:#fff}
.btn-sm-blue{background:#1f6feb;color:#fff}
.access-tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px}
</style>
</head>
<body>
""" + _HEADER_HTML.replace("{dash_active}", "").replace("{con_active}", "").replace("{adm_active}", " active") + """
<main>

  <!-- Global Accounts — owner only, shown via JS -->
  <div class="section" id="globalSection" style="display:none">
    <div class="section-title">Global Accounts</div>
    <table class="user-table">
      <thead><tr><th>Username</th><th>Global Role</th><th>Actions</th></tr></thead>
      <tbody id="userList"><tr><td colspan="3" style="color:#484f58">Loading&hellip;</td></tr></tbody>
    </table>
  </div>
  <div class="section" id="addUserSection" style="display:none">
    <div class="section-title">Add Account</div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Username</label>
        <input id="newUsername" class="form-input" type="text" placeholder="username" autocomplete="off">
      </div>
      <div class="form-group">
        <label class="form-label">Password</label>
        <input id="newPassword" class="form-input" type="password" placeholder="password">
      </div>
      <div class="form-group" style="max-width:130px">
        <label class="form-label">Global Role</label>
        <select id="newRole" class="form-input">
          <option value="viewer">Viewer</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <button class="btn btn-green" onclick="addUser()">Add Account</button>
    </div>
  </div>

  <!-- Server Access — all admins/owners -->
  <div class="section">
    <div class="section-title">Server Access</div>
    <p style="color:#484f58;font-size:.78rem;margin-bottom:14px">Assign which accounts can access each server and what they can do.</p>
    <div class="access-tabs" id="srvAccessTabs"></div>
    <div id="srvAccessContent"><p style="color:#484f58;font-size:.85rem">Loading&hellip;</p></div>
  </div>

</main>
<div class="toasts" id="toasts"></div>
<script>
""" + _TOAST_JS + _SERVER_BAR_JS + """
function selectServer(sid){ window.location='/'; }
let _me='', _myRole='', _users=[];
async function fetchMe(){
  try{
    const d=await fetch('/api/me').then(r=>r.json());
    _me=d.username; _myRole=d.role;
    const ub=document.getElementById('userBadge');
    if(ub) ub.textContent=_me+(_myRole==='owner'?' \u00b7 owner':' \u00b7 admin');
    const al=document.getElementById('adminLink');
    if(al) al.style.display='';
    if(_myRole==='owner'){
      document.getElementById('globalSection').style.display='';
      document.getElementById('addUserSection').style.display='';
      loadUsers();
    }
    initServerAccess();
  }catch(e){}
}
async function loadUsers(){
  try{
    _users=await fetch('/api/admin/users').then(r=>r.json());
    const tbody=document.getElementById('userList');
    if(!_users.length){tbody.innerHTML='<tr><td colspan="3" style="color:#484f58">No users.</td></tr>';return;}
    tbody.innerHTML=_users.map(function(u,i){
      const isSelf=u.username===_me;
      const isOwner=u.role==='owner';
      const canAct=!isOwner||_myRole==='owner';
      let actions='';
      if(isSelf){
        actions='<span style="color:#484f58;font-size:.75rem">current user</span>';
      }else if(canAct){
        actions+='<button class="btn-sm btn-sm-blue" onclick="resetPassword('+i+')">Reset PW</button> ';
        if(!isOwner) actions+='<button class="btn-sm" style="background:#21262d;border:1px solid #30363d;color:#c9d1d9" onclick="toggleRole('+i+')">'+(u.role==='admin'?'Make Viewer':'Make Admin')+'</button> ';
        actions+='<button class="btn-sm btn-sm-red" onclick="deleteUser('+i+')">Delete</button>';
      }else{
        actions='<span style="color:#484f58;font-size:.75rem">protected</span>';
      }
      return '<tr><td>'+u.username+'</td><td><span class="role-badge '+u.role+'">'+u.role+'</span></td>'
        +'<td style="display:flex;gap:6px;align-items:center">'+actions+'</td></tr>';
    }).join('');
  }catch(e){toast('Failed to load users','err');}
}
async function addUser(){
  const username=document.getElementById('newUsername').value.trim();
  const password=document.getElementById('newPassword').value;
  const role=document.getElementById('newRole').value;
  if(!username||!password){toast('Username and password required','err');return;}
  try{
    const r=await fetch('/api/admin/users/add',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username,password,role})}).then(r=>r.json());
    if(r.ok){toast('Account added','ok');document.getElementById('newUsername').value='';document.getElementById('newPassword').value='';loadUsers();}
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}
async function deleteUser(i){
  const u=_users[i];
  if(!confirm('Delete account '+u.username+'?'))return;
  try{
    const r=await fetch('/api/admin/users/delete',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.username})}).then(r=>r.json());
    if(r.ok){toast('Account deleted','ok');loadUsers();}
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}
async function resetPassword(i){
  const u=_users[i];
  const pw=prompt('New password for '+u.username+':');
  if(!pw)return;
  try{
    const r=await fetch('/api/admin/users/update',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.username,password:pw})}).then(r=>r.json());
    if(r.ok) toast('Password updated','ok');
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}
async function toggleRole(i){
  const u=_users[i];
  const newRole=u.role==='admin'?'viewer':'admin';
  if(!confirm('Change '+u.username+' to '+newRole+'?'))return;
  try{
    const r=await fetch('/api/admin/users/update',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.username,role:newRole})}).then(r=>r.json());
    if(r.ok){toast('Role updated','ok');loadUsers();}
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}

// ── Server Access ──────────────────────────────────────────────────────────────
let _accessServers=[], _currentAccessSid=null, _srvAccessUsers=[];
async function initServerAccess(){
  try{
    const list=await fetch('/api/servers').then(r=>r.json());
    _accessServers=list.filter(function(s){return s.role==='admin'||s.role==='owner';});
    const tabs=document.getElementById('srvAccessTabs');
    if(!_accessServers.length){
      tabs.innerHTML='';
      document.getElementById('srvAccessContent').innerHTML='<p style="color:#484f58;font-size:.85rem">No servers accessible.</p>';
      return;
    }
    tabs.innerHTML=_accessServers.map(function(s,i){
      return '<button class="srv-tab'+(i===0?' active':'')+'" onclick="loadServerAccess('+s.id+')" id="srvAccessTab'+s.id+'">'+s.name+'</button>';
    }).join('');
    loadServerAccess(_accessServers[0].id);
  }catch(e){}
}
async function loadServerAccess(sid){
  _currentAccessSid=sid;
  document.querySelectorAll('#srvAccessTabs .srv-tab').forEach(function(t){
    t.classList.toggle('active',t.id==='srvAccessTab'+sid);
  });
  const content=document.getElementById('srvAccessContent');
  content.innerHTML='<p style="color:#484f58;font-size:.85rem">Loading\u2026</p>';
  try{
    _srvAccessUsers=await fetch('/api/admin/servers/'+sid+'/users').then(r=>r.json());
    renderServerAccess(sid);
  }catch(e){content.innerHTML='<p style="color:#f85149;font-size:.85rem">Failed to load.</p>';}
}
function renderServerAccess(sid){
  const srv=_accessServers.find(function(s){return s.id===sid;});
  const callerRole=srv?srv.role:null;
  const content=document.getElementById('srvAccessContent');
  const assigned=_srvAccessUsers.filter(function(u){return u.server_role!==null;});
  const unassigned=_srvAccessUsers.filter(function(u){return u.server_role===null;});
  let html='';
  const editableAssigned=assigned.filter(function(u){return !u.is_owner;});
  if(assigned.length){
    html+='<table class="user-table"><thead><tr><th>Username</th><th>Role on this server</th><th>Actions</th></tr></thead><tbody>';
    assigned.forEach(function(u){
      if(u.is_owner){
        html+='<tr><td>'+u.username+'</td><td><span class="role-badge owner">owner</span></td>'
          +'<td><span style="color:#484f58;font-size:.75rem">full access</span></td></tr>';
      }else{
        const idx=editableAssigned.indexOf(u);
        let actions='';
        if(callerRole==='owner'){
          const opp=u.server_role==='admin'?'viewer':'admin';
          const oppCap=opp.charAt(0).toUpperCase()+opp.slice(1);
          actions+='<button class="btn-sm btn-sm-blue" onclick="changeServerRole('+sid+','+idx+')">Make '+oppCap+'</button> ';
        }
        actions+='<button class="btn-sm btn-sm-red" onclick="removeServerUser('+sid+','+idx+')">Remove</button>';
        html+='<tr><td>'+u.username+'</td><td><span class="role-badge '+u.server_role+'">'+u.server_role+'</span></td>'
          +'<td style="display:flex;gap:6px;align-items:center">'+actions+'</td></tr>';
      }
    });
    html+='</tbody></table>';
  }else{
    html+='<p style="color:#484f58;font-size:.82rem;margin-bottom:12px">No users assigned to this server yet.</p>';
  }
  if(unassigned.length){
    html+='<div style="margin-top:16px"><div class="section-title" style="margin-bottom:10px">Grant Access</div>'
      +'<div class="form-row">'
      +'<div class="form-group"><label class="form-label">Account</label>'
      +'<select id="assignUser" class="form-input">'
      +unassigned.map(function(u){return '<option value="'+u.username+'">'+u.username+'</option>';}).join('')
      +'</select></div>'
      +'<div class="form-group" style="max-width:130px"><label class="form-label">Role</label>'
      +'<select id="assignRole" class="form-input"><option value="viewer">Viewer</option>'
      +(callerRole==='owner'?'<option value="admin">Admin</option>':'')
      +'</select></div>'
      +'<button class="btn btn-green" onclick="assignServerUser('+sid+')">Grant Access</button>'
      +'</div></div>';
  }
  content.innerHTML=html||'<p style="color:#484f58;font-size:.85rem">All accounts have been assigned.</p>';
}
async function assignServerUser(sid){
  const username=document.getElementById('assignUser').value;
  const role=document.getElementById('assignRole').value;
  try{
    const r=await fetch('/api/admin/servers/'+sid+'/users/assign',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({username,role})}).then(r=>r.json());
    if(r.ok){toast('Access granted','ok');loadServerAccess(sid);}
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}
async function changeServerRole(sid,idx){
  const list=_srvAccessUsers.filter(function(u){return u.server_role!==null&&!u.is_owner;});
  const u=list[idx];
  if(!u)return;
  const role=u.server_role==='admin'?'viewer':'admin';
  try{
    const r=await fetch('/api/admin/servers/'+sid+'/users/assign',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.username,role})}).then(r=>r.json());
    if(r.ok){toast('Role updated','ok');loadServerAccess(sid);}
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}
async function removeServerUser(sid,idx){
  const list=_srvAccessUsers.filter(function(u){return u.server_role!==null&&!u.is_owner;});
  const u=list[idx];
  if(!u)return;
  if(!confirm('Remove '+u.username+' from this server?'))return;
  try{
    const r=await fetch('/api/admin/servers/'+sid+'/users/assign',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.username,role:null})}).then(r=>r.json());
    if(r.ok){toast('Access removed','ok');loadServerAccess(sid);}
    else toast('Error: '+r.error,'err');
  }catch(e){toast('Failed','err');}
}
fetchMe(); loadServerBar();
const _sp=document.querySelector('.status-pill');
if(_sp)_sp.style.display='none';
</script>
</body>
</html>"""

# ── Apply server_name branding ─────────────────────────────────────────────────
_sn = cfg.get("server_name") or "Minecraft Watchdog"
LOGIN_HTML     = LOGIN_HTML    .replace("ATMons", _sn)
DASHBOARD_HTML = DASHBOARD_HTML.replace("ATMons", _sn)
CONSOLE_HTML   = CONSOLE_HTML  .replace("ATMons", _sn)
ADMIN_HTML     = ADMIN_HTML    .replace("ATMons", _sn)

# ── Routes ─────────────────────────────────────────────────────────────────────
_MAX_ATTEMPTS = 5
_LOCKOUT_SECS = 300

@app.route("/login", methods=["GET","POST"])
def login():
    ip    = request.remote_addr
    now   = time.time()
    count, locked_until = _login_attempts.get(ip, [0, 0.0])
    error = ""
    if now < locked_until:
        error = f"Too many failed attempts. Try again in {int(locked_until - now)}s."
        return render_template_string(LOGIN_HTML, error=error)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = _get_user(username)
        if user and _check_password(password, user["password"]):
            _login_attempts.pop(ip, None)
            session.permanent = True
            session["authenticated"] = True
            session["username"] = user["username"]
            # Compute max role: owner beats all; otherwise check per-server assignments
            if user.get("role") == "owner":
                role = "owner"
            else:
                role = "viewer"
                for scfg in cfg.get("servers", []):
                    for su in scfg.get("users", []):
                        if su.get("username") == username and su.get("role") == "admin":
                            role = "admin"
                            break
            session["role"] = role
            return redirect("/")
        count += 1
        locked_until = now + _LOCKOUT_SECS if count >= _MAX_ATTEMPTS else 0.0
        _login_attempts[ip] = [count, locked_until]
        remaining = _MAX_ATTEMPTS - count
        error = (f"Invalid credentials. ({remaining} attempt{'s' if remaining != 1 else ''} left)"
                 if remaining > 0 else f"Locked for {_LOCKOUT_SECS // 60} minutes.")
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@require_auth
def home():
    return DASHBOARD_HTML

@app.route("/console")
@require_role("admin", "owner")
def console():
    return CONSOLE_HTML

@app.route("/admin")
@require_role("admin", "owner")
def admin_page():
    return ADMIN_HTML

# ── API ────────────────────────────────────────────────────────────────────────
def _sanitize(v):
    if isinstance(v, str):  return v.encode("utf-8", "replace").decode("utf-8", "replace")
    if isinstance(v, list): return [_sanitize(i) for i in v]
    if isinstance(v, dict): return {k: _sanitize(val) for k, val in v.items()}
    return v

@app.route("/api/servers")
@require_auth
def api_servers():
    username = session.get("username")
    result = []
    for i, srv in enumerate(servers):
        role = _get_server_role(username, srv)
        if role:
            result.append({"id": i, "name": srv.name, "status": srv.state["status"], "role": role})
    return jsonify(result)

@app.route("/api/<int:sid>")
@require_auth
def api(sid):
    srv, err = _get_server(sid)
    if err: return err
    if not _get_server_role(session.get("username"), srv):
        return jsonify({"error": "forbidden"}), 403
    try:
        with srv.state_lock:
            data = {k: _sanitize(list(v) if isinstance(v, list) else v)
                    for k, v in srv.state.items() if k != "log"}
        bi = srv.scfg["backup_interval"]
        if data.get("backups_enabled") and srv.last_backup_time:
            data["next_backup_in"] = max(0, int(bi - (time.time() - srv.last_backup_time)))
        elif data.get("backups_enabled"):
            data["next_backup_in"] = bi
        else:
            data["next_backup_in"] = None
        return jsonify(data)
    except Exception as e:
        log_event("ERROR", f"/api/{sid} failed: {e}")
        return jsonify({"status": srv.state.get("status", "offline"), "error": str(e)}), 500

@app.route("/api/<int:sid>/log")
@require_auth
def api_log(sid):
    srv, err = _get_server(sid)
    if err: return err
    if not _get_server_role(session.get("username"), srv):
        return jsonify({"error": "forbidden"}), 403
    with srv.state_lock:
        return jsonify({"log": list(srv.state["log"]), "status": srv.state["status"]})

@app.route("/api/watchdog_log")
@require_auth
def api_watchdog_log():
    if not os.path.exists(WATCHDOG_LOG):
        return jsonify({"lines": []})
    try:
        with open(WATCHDOG_LOG, "r", encoding="utf-8") as f:
            lines = [l.rstrip() for l in f.readlines()]
        return jsonify({"lines": lines[-500:]})
    except Exception as e:
        return jsonify({"lines": [], "error": str(e)})

@app.route("/api/<int:sid>/backups")
@require_auth
def list_backups(sid):
    srv, err = _get_server(sid)
    if err: return err
    if not _get_server_role(session.get("username"), srv):
        return jsonify({"error": "forbidden"}), 403
    backup_dir = os.path.join(srv.server_dir, srv.scfg["backup_dir"])
    if not os.path.exists(backup_dir):
        return jsonify([])
    files = []
    for f in sorted(os.listdir(backup_dir), reverse=True):
        if f.endswith(".zip"):
            path = os.path.join(backup_dir, f)
            files.append({
                "name": f,
                "size": round(os.path.getsize(path) / (1024 ** 2), 1),
                "time": datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M"),
            })
    return jsonify(files[:20])

@app.route("/backup/<int:sid>/download/<filename>")
@require_auth
def download_backup(sid, filename):
    srv, err = _get_server(sid)
    if err: return err
    if not _get_server_role(session.get("username"), srv):
        return "Forbidden", 403
    if "/" in filename or "\\" in filename or not filename.endswith(".zip"):
        return "Invalid filename", 400
    path = os.path.join(srv.server_dir, srv.scfg["backup_dir"], filename)
    if not os.path.exists(path):
        return "Not found", 404
    return send_file(os.path.abspath(path), as_attachment=True)

@app.route("/backup/<int:sid>/delete/<filename>", methods=["POST"])
@require_auth
def delete_backup(sid, filename):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    if "/" in filename or "\\" in filename or not filename.endswith(".zip"):
        return jsonify({"ok": False, "error": "Invalid filename"}), 400
    path = os.path.join(srv.server_dir, srv.scfg["backup_dir"], filename)
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "Not found"}), 404
    try:
        os.remove(path)
        srv._log("BACKUP", f"Deleted {filename}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/server/<int:sid>/command", methods=["POST"])
@require_auth
def command(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    now = time.time()
    if now - srv._last_cmd_time < 0.5:
        return jsonify({"ok": False, "error": "Too fast, slow down"}), 429
    srv._last_cmd_time = now
    cmd = request.json.get("cmd", "").strip()
    if not cmd: return jsonify({"ok": False, "error": "Empty command"}), 400
    if not srv.proc or srv.proc.poll() is not None:
        return jsonify({"ok": False, "error": "Server not running"}), 400
    try:
        srv.proc.stdin.write((cmd + "\n").encode()); srv.proc.stdin.flush()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/server/<int:sid>/stop")
@require_auth
def stop_server(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    threading.Thread(target=srv.stop, daemon=True).start()
    return "stopping"

@app.route("/server/<int:sid>/restart")
@require_auth
def restart(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    threading.Thread(target=srv.stop, daemon=True).start()
    return "restarting"

@app.route("/server/<int:sid>/backup")
@require_auth
def do_backup(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    threading.Thread(target=srv.backup, daemon=True).start()
    return "backup started"

@app.route("/server/<int:sid>/toggle_backups")
@require_auth
def toggle_backups(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    srv.state["backups_enabled"] = not srv.state["backups_enabled"]
    srv.scfg["backups_enabled"]  = srv.state["backups_enabled"]
    save_config(cfg)
    return jsonify({"enabled": srv.state["backups_enabled"]})

@app.route("/server/<int:sid>/start")
@require_auth
def start_server(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    if srv.state["status"] in ("online", "starting"):
        return "already running"
    with srv.state_lock:
        srv.crash_times.clear()
        srv.state["crash_count"] = 0
    if srv.proc and srv.proc.poll() is None:
        srv.proc.kill()
    srv.restart_event.set()
    srv._log("START", "Manual start requested from dashboard")
    return "starting"

# ── User / auth API ────────────────────────────────────────────────────────────
@app.route("/api/me")
@require_auth
def api_me():
    return jsonify({"username": session.get("username"), "role": session.get("role")})

@app.route("/api/me/password", methods=["POST"])
@require_auth
def api_change_password():
    data    = request.json or {}
    current = data.get("current", "")
    new_pw  = data.get("new_password", "")
    if not current or not new_pw:
        return jsonify({"ok": False, "error": "Missing fields"}), 400
    if len(new_pw) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters"}), 400
    user = _get_user(session.get("username"))
    if not user or not _check_password(current, user["password"]):
        return jsonify({"ok": False, "error": "Current password is incorrect"}), 403
    user["password"] = _hash_password(new_pw)
    save_config(cfg)
    session.clear()
    log_event("SECURITY", f"Password changed for user '{user['username']}'")
    return jsonify({"ok": True})

@app.route("/api/admin/users")
@require_role("admin", "owner")
def api_admin_users():
    return jsonify([{"username": u["username"], "role": u["role"]} for u in cfg.get("users", [])])

@app.route("/api/admin/users/add", methods=["POST"])
@require_role("admin", "owner")
def api_admin_add_user():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "viewer")
    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required"}), 400
    if role not in ("admin", "viewer"):
        return jsonify({"ok": False, "error": "Role must be admin or viewer"}), 400
    if _get_user(username):
        return jsonify({"ok": False, "error": "Username already exists"}), 409
    cfg["users"].append({"username": username, "password": _hash_password(password), "role": role})
    save_config(cfg)
    log_event("ADMIN", f"User '{username}' ({role}) added by {session.get('username')}")
    return jsonify({"ok": True})

@app.route("/api/admin/users/update", methods=["POST"])
@require_role("admin", "owner")
def api_admin_update_user():
    data     = request.json or {}
    username = data.get("username", "").strip()
    user     = _get_user(username)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if user["role"] == "owner" and session.get("role") != "owner":
        return jsonify({"ok": False, "error": "Only the owner can modify an owner account"}), 403
    if data.get("password"):
        user["password"] = _hash_password(data["password"])
    if data.get("role") in ("admin", "viewer"):
        if user["role"] == "owner":
            return jsonify({"ok": False, "error": "Cannot change role of owner account"}), 403
        user["role"] = data["role"]
    save_config(cfg)
    log_event("ADMIN", f"User '{username}' updated by {session.get('username')}")
    return jsonify({"ok": True})

@app.route("/api/admin/servers/<int:sid>/users")
@require_role("admin", "owner")
def api_admin_server_users(sid):
    srv, err = _get_server(sid)
    if err: return err
    if _get_server_role(session.get("username"), srv) not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    srv_user_map = {u["username"]: u["role"] for u in srv.scfg.get("users", [])}
    result = []
    for u in cfg.get("users", []):
        if u["role"] == "owner":
            result.append({"username": u["username"], "server_role": "owner", "is_owner": True})
        else:
            sr = srv_user_map.get(u["username"])
            result.append({"username": u["username"], "server_role": sr, "is_owner": False})
    return jsonify(result)

@app.route("/api/admin/servers/<int:sid>/users/assign", methods=["POST"])
@require_role("admin", "owner")
def api_admin_server_users_assign(sid):
    srv, err = _get_server(sid)
    if err: return err
    caller_role = _get_server_role(session.get("username"), srv)
    if caller_role not in ("admin", "owner"):
        return jsonify({"error": "forbidden"}), 403
    data     = request.json or {}
    username = data.get("username", "").strip()
    role     = data.get("role")   # "admin", "viewer", or None to remove
    target   = _get_user(username)
    if not target:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if target["role"] == "owner":
        return jsonify({"ok": False, "error": "Cannot assign server role to owner"}), 400
    if role == "admin" and caller_role != "owner":
        return jsonify({"ok": False, "error": "Only the owner can grant admin access"}), 403
    if role not in ("admin", "viewer", None):
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    srv.scfg["users"] = [u for u in srv.scfg.get("users", []) if u["username"] != username]
    if role in ("admin", "viewer"):
        srv.scfg["users"].append({"username": username, "role": role})
    save_config(cfg)
    action = f"set to {role}" if role else "removed"
    log_event("ADMIN", f"Server '{srv.name}': '{username}' server role {action} by {session.get('username')}")
    return jsonify({"ok": True})

@app.route("/api/admin/users/delete", methods=["POST"])
@require_role("admin", "owner")
def api_admin_delete_user():
    data     = request.json or {}
    username = data.get("username", "").strip()
    if username == session.get("username"):
        return jsonify({"ok": False, "error": "Cannot delete your own account"}), 400
    target = _get_user(username)
    if target and target["role"] == "owner" and session.get("role") != "owner":
        return jsonify({"ok": False, "error": "Only the owner can delete an owner account"}), 403
    before = len(cfg["users"])
    cfg["users"] = [u for u in cfg["users"] if u["username"] != username]
    if len(cfg["users"]) == before:
        return jsonify({"ok": False, "error": "User not found"}), 404
    save_config(cfg)
    log_event("ADMIN", f"User '{username}' deleted by {session.get('username')}")
    return jsonify({"ok": True})

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    for i, scfg in enumerate(cfg["servers"]):
        srv = ServerInstance(i, scfg)
        servers.append(srv)
        os.makedirs(os.path.join(srv.server_dir, scfg["backup_dir"]), exist_ok=True)
        threading.Thread(target=srv.monitor,            daemon=True).start()
        threading.Thread(target=srv.backup_scheduler,  daemon=True).start()
        threading.Thread(target=srv.restart_scheduler, daemon=True).start()
        log_event("WATCHDOG", f"[{srv.name}] Instance initialised (dir: {srv.server_dir})")

    sn = cfg.get("server_name") or "Minecraft Watchdog"
    log_event("WATCHDOG", f"{sn} starting up — {len(servers)} server(s)")
    try:
        from waitress import serve
        log_event("WATCHDOG", f"Dashboard running at http://0.0.0.0:{cfg['port']}")
        serve(app, host="0.0.0.0", port=cfg["port"])
    except ImportError:
        app.run(host="0.0.0.0", port=cfg["port"])
