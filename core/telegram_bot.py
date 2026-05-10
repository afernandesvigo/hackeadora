#!/usr/bin/env python3
"""
core/telegram_bot.py — Bot bidireccional para Hackeadora (Variante C).

Long-poll a Telegram. Comandos slash → handlers locales (sqlite/ps).
Mensajes free-form → spawn `claude -p --resume <session>` con contexto del scan.

Coexiste con notifications: el bot solo CONSUME getUpdates; los scans/supervisores
siguen enviando _telegram_send normalmente.

Vars de entorno (config.env):
  TELEGRAM_BOT_TOKEN          token del bot
  TELEGRAM_CHAT_ID            chat principal (también acepta TELEGRAM_AUTHORIZED_CHATS csv)
  TELEGRAM_AUTHORIZED_CHATS   chat_ids permitidos (csv). Default = TELEGRAM_CHAT_ID
  CLAUDE_CMD                  binario claude (default: claude)
  RECONFLOW_DB                path a recon.db (default: data/recon.db)
  HACKEADORA_DIR              path al repo (default: /home/ubuntu/hackeadora)

Comandos:
  /help                listado
  /status              scans activos + último heartbeat
  /active              ps de procesos recon.sh + tiempos
  /findings <dom> [N]  top N findings de un dominio (default 10)
  /last [N]            últimos N findings (cualquier dominio)
  /exploit_chain <dom> findings de mod 98 exploit_chain
  /scope <dom>         dominios scope BBP guardados (data/scopes/)
  /tail <dom> [N]      últimas N líneas del recon.log activo

Mensaje sin / → enviado a Claude via `claude -p --resume <chat_id>`.
"""

import os
import re
import sys
import json
import time
import subprocess
import sqlite3
import signal
from pathlib import Path
from urllib.parse import urlencode
import requests

# ── Config ─────────────────────────────────────────────────────
HACKEADORA_DIR = Path(os.environ.get("HACKEADORA_DIR", "/home/ubuntu/hackeadora"))
DB_PATH = Path(os.environ.get("RECONFLOW_DB", str(HACKEADORA_DIR / "data" / "recon.db")))
CLAUDE_CMD = os.environ.get("CLAUDE_CMD", "claude")

# Cargar config.env
ENV_FILE = HACKEADORA_DIR / "config.env"
if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k.strip(), v)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
DEFAULT_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")
AUTH_CHATS = set(
    [c.strip() for c in os.environ.get("TELEGRAM_AUTHORIZED_CHATS", DEFAULT_CHAT).split(",") if c.strip()]
)
if not BOT_TOKEN:
    print("[bot] ERROR: TELEGRAM_BOT_TOKEN no configurado en config.env", file=sys.stderr)
    sys.exit(1)
if not AUTH_CHATS:
    print("[bot] ERROR: TELEGRAM_AUTHORIZED_CHATS / TELEGRAM_CHAT_ID no configurado", file=sys.stderr)
    sys.exit(1)

API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# Sesión por chat para `claude --resume`
SESSION_DIR = Path("/tmp/hackeadora_bot_sessions")
SESSION_DIR.mkdir(exist_ok=True)


def log(msg):
    print(f"[bot {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Telegram helpers ───────────────────────────────────────────
def tg_send(chat_id, text, parse_mode="Markdown"):
    """Send a message. Splits if >4000 chars."""
    text = str(text)
    if len(text) > 4000:
        # Cortar en chunks
        chunks = []
        while text:
            chunk = text[:3900]
            text = text[3900:]
            chunks.append(chunk)
        for i, c in enumerate(chunks):
            label = f"({i+1}/{len(chunks)}) " if len(chunks) > 1 else ""
            try:
                requests.post(
                    f"{API}/sendMessage",
                    data={"chat_id": chat_id, "text": label + c, "parse_mode": parse_mode},
                    timeout=10,
                )
            except Exception as e:
                log(f"send error: {e}")
        return
    try:
        r = requests.post(
            f"{API}/sendMessage",
            data={"chat_id": chat_id, "text": text, "parse_mode": parse_mode},
            timeout=10,
        )
        if r.status_code != 200:
            # Retry without markdown
            requests.post(
                f"{API}/sendMessage",
                data={"chat_id": chat_id, "text": text},
                timeout=10,
            )
    except Exception as e:
        log(f"send error: {e}")


def tg_typing(chat_id):
    try:
        requests.post(f"{API}/sendChatAction", data={"chat_id": chat_id, "action": "typing"}, timeout=5)
    except Exception:
        pass


# ── DB helpers ─────────────────────────────────────────────────
def db_query(sql, params=()):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows
    except Exception as e:
        log(f"db error: {e}")
        return []


# ── Slash command handlers ─────────────────────────────────────
def cmd_help(chat_id, args):
    tg_send(chat_id, """*Hackeadora Bot — comandos disponibles*

`/status` — scans activos y heartbeat
`/active` — procesos recon.sh corriendo + tiempo
`/findings <dom> [N]` — top N findings de dominio (default 10)
`/last [N]` — últimos N findings cualquier dominio
`/exploit_chain <dom>` — findings de mod 98
`/scope [dom]` — listas scope BBP guardadas
`/tail <dom> [N]` — últimas N líneas del recon.log

Cualquier mensaje sin / → consulta a Claude (con contexto del scan actual).
Ejemplo: _"prioriza los 5 findings más exploitable en generali"_""")


def cmd_status(chat_id, args):
    # ps + heartbeat
    procs = subprocess.run(
        ["ps", "-eo", "pid,etime,args"], capture_output=True, text=True, timeout=5
    ).stdout
    recons = [l for l in procs.splitlines() if "recon.sh" in l and "grep" not in l]
    if not recons:
        tg_send(chat_id, "🟢 *Sin scans activos*")
        return
    msg = f"🔄 *{len(recons)} scan(s) activos:*\n"
    for line in recons[:10]:
        parts = line.split(None, 2)
        if len(parts) >= 3:
            msg += f"  PID `{parts[0]}` (`{parts[1]}`): `{parts[2][:80]}`\n"
    # Stats DB recientes
    rows = db_query("""
        SELECT d.domain, COUNT(*) as n, SUM(CASE WHEN f.confidence='high' THEN 1 ELSE 0 END) as h
        FROM findings f JOIN domains d ON d.id=f.domain_id
        WHERE f.found_at > datetime('now', '-2 hours')
        GROUP BY d.domain ORDER BY n DESC LIMIT 5
    """)
    if rows:
        msg += "\n*Findings últimas 2h:*\n"
        for r in rows:
            msg += f"  `{r['domain']}`: {r['n']} (high-conf: {r['h']})\n"
    tg_send(chat_id, msg)


def cmd_active(chat_id, args):
    procs = subprocess.run(
        ["ps", "-eo", "pid,etime,args"], capture_output=True, text=True, timeout=5
    ).stdout
    items = []
    for line in procs.splitlines():
        if ("recon.sh" in line or "supervisor.sh" in line) and "grep" not in line:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                items.append(f"PID `{parts[0]}` ({parts[1]}): `{parts[2][:70]}`")
    if not items:
        tg_send(chat_id, "🟢 sin procesos activos")
        return
    tg_send(chat_id, "🔄 *Procesos activos:*\n" + "\n".join(items[:15]))


def cmd_findings(chat_id, args):
    if not args:
        tg_send(chat_id, "Uso: `/findings <dominio> [N]`")
        return
    dom = args[0]
    n = int(args[1]) if len(args) > 1 and args[1].isdigit() else 10
    rows = db_query(
        """SELECT severity, confidence, type, target, substr(detail,1,100) as detail
           FROM findings WHERE domain_id=(SELECT id FROM domains WHERE domain=?)
           ORDER BY CASE severity
             WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
             WHEN 'low' THEN 4 ELSE 5 END
           LIMIT ?""", (dom, n)
    )
    if not rows:
        tg_send(chat_id, f"Sin findings para `{dom}`")
        return
    msg = f"*Top {len(rows)} findings de `{dom}`:*\n"
    for r in rows:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(r["severity"], "ℹ️")
        msg += (
            f"\n{emoji} `{r['severity']}/{r['confidence']}` `{r['type']}`\n"
            f"  → `{r['target'][:80]}`\n"
        )
    tg_send(chat_id, msg)


def cmd_last(chat_id, args):
    n = int(args[0]) if args and args[0].isdigit() else 10
    rows = db_query(
        """SELECT d.domain, f.severity, f.confidence, f.type, f.target, f.found_at
           FROM findings f JOIN domains d ON d.id=f.domain_id
           ORDER BY f.id DESC LIMIT ?""", (n,)
    )
    if not rows:
        tg_send(chat_id, "Sin findings")
        return
    msg = f"*Últimos {n} findings:*\n"
    for r in rows:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(r["severity"], "ℹ️")
        msg += f"\n{emoji} `{r['domain']}` `{r['type']}` ({r['severity']}/{r['confidence']})\n  `{r['target'][:80]}`"
    tg_send(chat_id, msg)


def cmd_exploit_chain(chat_id, args):
    if not args:
        tg_send(chat_id, "Uso: `/exploit_chain <dominio>`")
        return
    dom = args[0]
    rows = db_query(
        """SELECT severity, target, template, substr(detail,1,200) as detail
           FROM findings WHERE domain_id=(SELECT id FROM domains WHERE domain=?)
           AND type='exploit_chain'""", (dom,)
    )
    if not rows:
        tg_send(chat_id, f"Sin exploit_chain findings en `{dom}`")
        return
    msg = f"*Exploit chains en `{dom}`:*\n"
    for r in rows:
        msg += f"\n🚨 `{r['severity']}` `{r['template']}`\n  `{r['target'][:80]}`\n  📋 {r['detail'][:200]}\n"
    tg_send(chat_id, msg)


def cmd_scope(chat_id, args):
    scope_dir = HACKEADORA_DIR / "data" / "scopes"
    if not scope_dir.exists():
        tg_send(chat_id, "Sin directorio de scopes")
        return
    if not args:
        files = [f.stem for f in scope_dir.glob("*.txt") if not f.stem.endswith("_excludes")]
        tg_send(chat_id, "*Scopes guardados:*\n" + "\n".join(f"  • `{f}`" for f in files))
        return
    name = args[0]
    f = scope_dir / f"{name}.txt"
    if not f.exists():
        tg_send(chat_id, f"Scope `{name}` no encontrado")
        return
    content = f.read_text().strip()
    lines = content.splitlines()
    tg_send(chat_id, f"*Scope `{name}` ({len(lines)} dominios):*\n```\n{content[:3500]}\n```")


def cmd_tail(chat_id, args):
    if not args:
        tg_send(chat_id, "Uso: `/tail <dominio> [N]`")
        return
    dom = args[0]
    n = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
    out_dir = HACKEADORA_DIR / "output" / dom
    if not out_dir.exists():
        tg_send(chat_id, f"Sin output para `{dom}`")
        return
    latest = sorted(out_dir.glob("*/recon.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not latest:
        tg_send(chat_id, f"Sin recon.log para `{dom}`")
        return
    log_file = latest[0]
    try:
        result = subprocess.run(
            ["tail", "-n", str(n), str(log_file)],
            capture_output=True, text=True, timeout=5
        ).stdout
    except Exception as e:
        result = f"error: {e}"
    # Strip ANSI codes para Telegram
    result = re.sub(r"\x1b\[[0-9;]*m", "", result)
    tg_send(chat_id, f"*Tail `{dom}` ({log_file.parent.name}):*\n```\n{result[:3500]}\n```")


SLASH_HANDLERS = {
    "/help": cmd_help,
    "/start": cmd_help,
    "/status": cmd_status,
    "/active": cmd_active,
    "/findings": cmd_findings,
    "/last": cmd_last,
    "/exploit_chain": cmd_exploit_chain,
    "/scope": cmd_scope,
    "/tail": cmd_tail,
}


# ── Free-form → claude -p ──────────────────────────────────────
def build_context():
    """Empaquetar estado actual del scan para inyectar a Claude."""
    ctx_lines = ["## Hackeadora — estado actual del pipeline"]

    # Scans activos
    procs = subprocess.run(["ps", "-eo", "pid,etime,args"], capture_output=True, text=True, timeout=5).stdout
    actives = [l for l in procs.splitlines() if "recon.sh" in l and "grep" not in l]
    if actives:
        ctx_lines.append("### Scans activos:")
        for line in actives[:10]:
            ctx_lines.append(f"- {line.strip()}")

    # Findings recientes (últimas 2h)
    rows = db_query("""
        SELECT d.domain, f.severity, f.confidence, f.type, f.target, substr(f.detail,1,80) as detail
        FROM findings f JOIN domains d ON d.id=f.domain_id
        WHERE f.found_at > datetime('now', '-2 hours')
        ORDER BY CASE f.severity
          WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
        LIMIT 30
    """)
    if rows:
        ctx_lines.append("\n### Findings últimas 2h:")
        for r in rows:
            ctx_lines.append(
                f"- {r['domain']} | {r['severity']}/{r['confidence']} | {r['type']} | "
                f"{r['target'][:60]} | {r['detail'][:60]}"
            )

    return "\n".join(ctx_lines)


def call_claude(chat_id, user_msg):
    """Spawn `claude -p --resume <session>` con contexto."""
    session_file = SESSION_DIR / f"chat_{chat_id}.session"
    context = build_context()
    prompt = (
        f"{context}\n\n"
        f"## Usuario pregunta:\n{user_msg}\n\n"
        f"Responde de forma concisa para Telegram (max ~1500 chars). "
        f"Si pide datos exactos, lee la DB en {DB_PATH} con sqlite3."
    )

    args = [CLAUDE_CMD, "-p", prompt, "--allowed-tools", "Read,Bash"]
    # Resume si hay sesión previa (TODO: claude -p sessions)
    # Por ahora, fresh per-message — más simple y consistente
    try:
        result = subprocess.run(
            args,
            capture_output=True, text=True, timeout=180,
            cwd=str(HACKEADORA_DIR),
        )
        reply = result.stdout.strip() or result.stderr.strip() or "(sin respuesta)"
        return reply[:3800]
    except subprocess.TimeoutExpired:
        return "⏱️ Timeout (180s) — pregunta más concreta."
    except Exception as e:
        return f"❌ Error: {e}"


# ── Main loop ──────────────────────────────────────────────────
def handle_update(update):
    msg = update.get("message", {})
    chat_id = str(msg.get("chat", {}).get("id", ""))
    text = msg.get("text", "").strip()
    user_id = str(msg.get("from", {}).get("id", ""))
    user_name = msg.get("from", {}).get("username", user_id)

    if not chat_id or not text:
        return

    # Auth
    if chat_id not in AUTH_CHATS:
        log(f"unauthorized chat_id={chat_id} user={user_name}: {text[:50]}")
        return

    log(f"msg from {user_name}: {text[:80]}")

    if text.startswith("/"):
        # Strip @botname si presente
        parts = text.split(maxsplit=1)
        cmd = parts[0].split("@")[0].lower()
        args = parts[1].split() if len(parts) > 1 else []
        handler = SLASH_HANDLERS.get(cmd)
        if handler:
            try:
                handler(chat_id, args)
            except Exception as e:
                log(f"handler error: {e}")
                tg_send(chat_id, f"❌ error en {cmd}: {e}")
        else:
            tg_send(chat_id, f"Comando desconocido `{cmd}`. Usa `/help`")
    else:
        # Free-form → Claude
        tg_typing(chat_id)
        reply = call_claude(chat_id, text)
        tg_send(chat_id, reply)


def main_loop():
    log(f"bot started — auth chats: {AUTH_CHATS}")
    log(f"DB: {DB_PATH}")
    log(f"Claude: {CLAUDE_CMD}")
    offset = 0
    while True:
        try:
            r = requests.get(
                f"{API}/getUpdates",
                params={"offset": offset, "timeout": 30},
                timeout=40,
            )
            if r.status_code != 200:
                log(f"getUpdates {r.status_code}: {r.text[:200]}")
                time.sleep(5)
                continue
            data = r.json()
            for update in data.get("result", []):
                offset = update["update_id"] + 1
                try:
                    handle_update(update)
                except Exception as e:
                    log(f"handle_update error: {e}")
        except requests.exceptions.Timeout:
            continue
        except Exception as e:
            log(f"loop error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    main_loop()
