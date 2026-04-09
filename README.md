# ATMons — Minecraft Server Watchdog & Dashboard

A self-hosted watchdog and web dashboard for NeoForge Minecraft servers. Monitors your server, restarts it on crash, manages backups, and provides a live web UI for stats, chat, console access, and server control.

---

## Requirements

- Python 3.8+
- Java (configured for your server)
- The following Python packages:

```
pip install mcstatus psutil flask waitress
```

---

## Setup

1. Place `watchdog.py`, `start.bat` (Windows) or `start.sh` (Linux/Mac) in your server folder alongside `run.bat`, `user_jvm_args.txt`, etc.
2. Run `start.bat` (Windows) or `./start.sh` (Linux/Mac) — this installs dependencies and starts the watchdog
3. On first run, `watchdog_config.json` is created automatically with default settings
4. Log in at `http://localhost:5000/login` with the default credentials printed to the console (`admin` / `changeme`)
5. **Change your password immediately** via the dashboard — go to the account menu or the Admin panel
6. Edit `watchdog_config.json` to customise your server launch command and other settings, then restart the watchdog

---

## Configuration

All settings live in `watchdog_config.json`. Edit and restart the watchdog to apply changes.

| Key | Default | Description |
|-----|---------|-------------|
| `java_args` | NeoForge win_args | Command used to launch the server |
| `server_ip` | `127.0.0.1` | IP the watchdog polls for status |
| `server_port` | `25565` | Port the watchdog polls |
| `check_interval` | `5` | Seconds between health checks |
| `max_startup_wait` | `300` | Seconds to wait for server to finish starting |
| `backup_interval` | `1800` | Seconds between automatic backups (30 min) |
| `max_crashes` | `5` | Crashes allowed before pausing auto-restart |
| `crash_window` | `300` | Time window (seconds) for counting crashes |
| `world_dir` | `world` | Folder to back up |
| `backup_dir` | `backups` | Folder where backups are saved |
| `port` | `5000` | Dashboard web port |
| `server_name` | `ATMons` | Name shown in the dashboard header and page titles |
| `backups_enabled` | `true` | Whether auto-backups are enabled on start |

> **Note:** The default `java_args` references NeoForge version `21.1.224`. Update this to match your actual NeoForge installation.

---

## Features

### Watchdog
- **Smart startup detection** — waits for the server's `Done` message rather than a fixed timer
- **Crash loop protection** — if the server crashes more than `max_crashes` times within `crash_window` seconds, restarts are paused automatically and resume after the window passes
- **Scheduled backups** — world folder is zipped to `backups/` on a configurable interval, only while the server is online
- **Event logging** — all starts, stops, crashes, and backups are timestamped and written to `watchdog.log`

### Dashboard — Overview (`/`)
- Live stats: players online, CPU, RAM, TPS, latency, uptime
- Per-player list with name badges
- TPS / CPU / RAM history charts (tabbed)
- Server info: MOTD and version pulled live from the server
- **Actions:** Restart, Stop, Backup Now, toggle Auto-Backup on/off
- Backup list with file size, timestamp, download and delete buttons
- Next scheduled backup countdown
- Live server chat feed
- Browser notifications on status changes (online / offline / starting / crashed)

### Dashboard — Console (`/console`)
- **Server Log tab** — live stream of all server stdout, colour-coded by severity (INFO / WARN / ERROR). Includes filter buttons (All / Warn+ / Error), Clear, and Export
- **Watchdog Log tab** — timestamped event log from `watchdog.log`, colour-coded by event type
- Command input with **command history** (↑ / ↓ arrow keys)
- 0.5s rate limit on sent commands

### Dashboard — Admin (`/admin`)
- Multi-user management: add, edit, and delete users
- Three roles: **owner** (full access), **admin** (server control + user management), **viewer** (read-only)
- Change your own password via the account menu

### Security
- All dashboard pages and API routes require login
- Passwords hashed with PBKDF2-SHA256 (600,000 iterations)
- Session key is generated once and persisted in `watchdog_config.json` so logins survive restarts
- Backup download/delete routes validate filenames to prevent path traversal
- Login rate limiting to slow brute-force attempts

---

## Files

| File | Description |
|------|-------------|
| `watchdog.py` | Main watchdog + dashboard application |
| `start.bat` | Windows: installs dependencies and starts the watchdog |
| `start.sh` | Linux/Mac: installs dependencies and starts the watchdog |
| `watchdog_config.json` | Auto-generated config (edit to customise) |
| `watchdog.log` | Watchdog event log (auto-created) |
| `backups/` | World backup archives (auto-created) |

> `run.bat`, `user_jvm_args.txt`, and the NeoForge libraries are provided by your NeoForge server installation, not this project.

---

## Dashboard Pages

| URL | Page |
|-----|------|
| `http://localhost:5000/` | Overview — stats, charts, actions, chat |
| `http://localhost:5000/console` | Console — server log, watchdog log, command input |
| `http://localhost:5000/admin` | Admin — user management |
| `http://localhost:5000/login` | Login |
| `http://localhost:5000/logout` | Logout |
