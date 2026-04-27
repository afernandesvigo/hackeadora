#!/usr/bin/env node
"use strict";
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = require("@modelcontextprotocol/sdk/types.js");
const fs = require("fs");
const path = require("path");

const OUTPUT_DIR = process.env.HACKEADORA_OUTPUT || "/opt/hackeadora/output";
const MAX_BYTES  = 500 * 1024;

const server = new Server(
  { name: "hackeadora-filesystem", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

function latestScan(domain) {
  const d = path.join(OUTPUT_DIR, domain);
  if (!fs.existsSync(d)) return null;
  return fs.readdirSync(d).filter(s =>
    fs.statSync(path.join(d, s)).isDirectory()
  ).sort().reverse()[0] || null;
}

function readSafe(p) {
  if (!fs.existsSync(p)) return null;
  const { size } = fs.statSync(p);
  if (size > MAX_BYTES) {
    const buf = Buffer.alloc(MAX_BYTES);
    const fd  = fs.openSync(p, "r");
    fs.readSync(fd, buf, 0, MAX_BYTES, 0);
    fs.closeSync(fd);
    return buf.toString() + "\n...[truncado]";
  }
  return fs.readFileSync(p, "utf8");
}

function globFiles(dir, re) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => re.test(f)).map(f => path.join(dir, f));
}

function scanDir(domain, scan) {
  return path.join(OUTPUT_DIR, domain, scan || latestScan(domain) || "");
}

const txt = s => ({ content: [{ type: "text", text: typeof s === "string" ? s : JSON.stringify(s, null, 2) }] });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: "list_domains",         description: "Lista dominios escaneados",
    inputSchema: { type: "object", properties: {} } },
  { name: "list_scan_files",      description: "Lista archivos del último scan de un dominio",
    inputSchema: { type: "object", required: ["domain"],
      properties: { domain: { type: "string" }, scan_date: { type: "string" } } } },
  { name: "read_file",            description: "Lee un archivo de output (soporta wildcards)",
    inputSchema: { type: "object", required: ["domain","filename"],
      properties: { domain: { type: "string" }, scan_date: { type: "string" },
                    filename: { type: "string" } } } },
  { name: "read_subdomains",      description: "Subdominios alive del último scan",
    inputSchema: { type: "object", required: ["domain"],
      properties: { domain: { type: "string" } } } },
  { name: "read_nuclei_findings", description: "Findings de nuclei del último scan",
    inputSchema: { type: "object", required: ["domain"],
      properties: { domain: { type: "string" } } } },
  { name: "read_tech_results",    description: "Tech fingerprinting — tecnologías y versiones",
    inputSchema: { type: "object", required: ["domain"],
      properties: { domain: { type: "string" } } } },
  { name: "read_recon_log",       description: "Log del último scan",
    inputSchema: { type: "object", required: ["domain"],
      properties: { domain: { type: "string" } } } },
]}));

server.setRequestHandler(CallToolRequestSchema, async ({ params: { name, arguments: a } }) => {
  try {
    if (name === "list_domains") {
      if (!fs.existsSync(OUTPUT_DIR)) return txt("Sin datos aún");
      return txt(fs.readdirSync(OUTPUT_DIR)
        .filter(d => fs.statSync(path.join(OUTPUT_DIR, d)).isDirectory())
        .map(d => ({ domain: d, latest_scan: latestScan(d) })));
    }
    if (name === "list_scan_files") {
      const sd = scanDir(a.domain, a.scan_date);
      if (!fs.existsSync(sd)) return txt(`Sin scans para ${a.domain}`);
      return txt({ scan: path.basename(sd), files: fs.readdirSync(sd).map(f => {
        const s = fs.statSync(path.join(sd, f));
        return { name: f, size_kb: Math.round(s.size/1024), is_dir: s.isDirectory() };
      })});
    }
    if (name === "read_file") {
      const sd  = scanDir(a.domain, a.scan_date);
      const re  = new RegExp("^" + a.filename.replace(/\./g,"\\.").replace(/\*/g,".*") + "$");
      const hit = globFiles(sd, re)[0];
      if (!hit) return txt(`${a.filename} no encontrado`);
      return txt(readSafe(hit) || "Vacío");
    }
    if (name === "read_subdomains") {
      const c = readSafe(path.join(scanDir(a.domain), "subs_alive.txt"));
      if (!c) return txt("Sin subdominios alive");
      const subs = c.trim().split("\n").filter(Boolean);
      return txt({ count: subs.length, subdomains: subs });
    }
    if (name === "read_nuclei_findings") {
      const files = globFiles(scanDir(a.domain), /nuclei_.*\.json$/);
      if (!files.length) return txt("Sin findings de nuclei");
      const findings = [];
      for (const f of files)
        (readSafe(f)||"").split("\n").filter(Boolean).forEach(l => {
          try { findings.push(JSON.parse(l)); } catch {}
        });
      return txt(findings);
    }
    if (name === "read_tech_results") {
      const files = globFiles(scanDir(a.domain), /tech.*\.json$/);
      if (!files.length) return txt("Sin resultados de tech fingerprinting");
      return txt(readSafe(files[0]) || "Vacío");
    }
    if (name === "read_recon_log") {
      return txt(readSafe(path.join(scanDir(a.domain), "recon.log")) || "Log no encontrado");
    }
    return txt(`Herramienta desconocida: ${name}`);
  } catch (e) { return txt(`Error: ${e.message}`); }
});

(async () => {
  await server.connect(new StdioServerTransport());
  process.stderr.write("hackeadora-mcp-filesystem OK\n");
})();
