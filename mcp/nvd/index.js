#!/usr/bin/env node
"use strict";
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = require("@modelcontextprotocol/sdk/types.js");

// NVD API v2 — gratuita, no requiere auth (con límite de rate)
// API key opcional para más rate: https://nvd.nist.gov/developers/request-an-api-key
const NVD_API_KEY = process.env.NVD_API_KEY || "";
const NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0";

async function nvdFetch(params) {
  const { default: fetch } = await import("node-fetch");
  const qs = new URLSearchParams(params).toString();
  const headers = { "User-Agent": "Hackeadora-MCP/1.0" };
  if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;
  const r = await fetch(`${NVD_BASE}?${qs}`, { headers, timeout: 30000 });
  if (!r.ok) throw new Error(`NVD ${r.status}`);
  return r.json();
}

function parseCVE(item) {
  const cve  = item.cve;
  const id   = cve.id;
  const desc = cve.descriptions?.find(d => d.lang === "en")?.value || "";
  const metrics = cve.metrics?.cvssMetricV31?.[0] ||
                  cve.metrics?.cvssMetricV30?.[0] ||
                  cve.metrics?.cvssMetricV2?.[0];
  const score    = metrics?.cvssData?.baseScore;
  const severity = metrics?.cvssData?.baseSeverity || metrics?.baseSeverity;
  const published= cve.published?.slice(0,10);
  const refs     = (cve.references || []).slice(0,3).map(r => r.url);
  return { id, score, severity, published, description: desc.slice(0,300), refs };
}

const server = new Server(
  { name: "hackeadora-nvd", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const txt = s => ({ content: [{ type: "text", text: typeof s === "string" ? s : JSON.stringify(s, null, 2) }] });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: "search_cves_by_keyword",
    description: "Busca CVEs por nombre de tecnología (ej: 'Apache 2.4.49', 'WordPress 6.4')",
    inputSchema: { type: "object", required: ["keyword"],
      properties: {
        keyword:   { type: "string", description: "Ej: Apache, nginx 1.18, WordPress 6.4" },
        severity:  { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"], description: "Filtrar por severidad" },
        results:   { type: "number", default: 10 },
        days_back: { type: "number", description: "Solo CVEs de los últimos N días", default: 365 },
      } } },
  { name: "get_cve_detail",
    description: "Obtiene detalles completos de un CVE específico",
    inputSchema: { type: "object", required: ["cve_id"],
      properties: { cve_id: { type: "string", description: "Ej: CVE-2021-44228" } } } },
  { name: "check_tech_vulnerabilities",
    description: "Dado un nombre de tecnología y versión, devuelve CVEs aplicables ordenados por severidad",
    inputSchema: { type: "object", required: ["tech_name"],
      properties: {
        tech_name:    { type: "string", description: "Ej: Apache HTTP Server" },
        tech_version: { type: "string", description: "Ej: 2.4.49 (opcional)" },
        results:      { type: "number", default: 10 },
      } } },
  { name: "get_recent_critical_cves",
    description: "Últimos CVEs críticos (CVSS >= 9.0) — útil para saber qué buscar esta semana",
    inputSchema: { type: "object",
      properties: {
        days_back: { type: "number", default: 7 },
        results:   { type: "number", default: 20 },
      } } },
  { name: "check_domain_tech_stack",
    description: "Dado un stack tecnológico detectado por Hackeadora, devuelve CVEs relevantes para cada componente",
    inputSchema: { type: "object", required: ["tech_stack"],
      properties: {
        tech_stack: {
          type: "array",
          items: { type: "object",
            properties: { name: { type: "string" }, version: { type: "string" } } },
          description: "Array de {name, version} — output del módulo 10 de Hackeadora",
        },
      } } },
]}));

server.setRequestHandler(CallToolRequestSchema, async ({ params: { name, arguments: a } }) => {
  try {
    if (name === "search_cves_by_keyword") {
      const params = {
        keywordSearch: a.keyword,
        resultsPerPage: Math.min(a.results || 10, 50),
      };
      if (a.severity) params.cvssV3Severity = a.severity;
      if (a.days_back) {
        const from = new Date(Date.now() - (a.days_back * 86400000));
        params.pubStartDate = from.toISOString().slice(0,19) + ".000";
      }

      await new Promise(r => setTimeout(r, NVD_API_KEY ? 100 : 600)); // rate limit
      const data = await nvdFetch(params);
      const cves = (data.vulnerabilities || []).map(v => parseCVE(v));
      return txt({
        total_results: data.totalResults,
        returned: cves.length,
        cves,
      });
    }

    if (name === "get_cve_detail") {
      await new Promise(r => setTimeout(r, NVD_API_KEY ? 100 : 600));
      const data = await nvdFetch({ cveId: a.cve_id });
      if (!data.vulnerabilities?.length) return txt(`CVE ${a.cve_id} no encontrado`);
      const cve     = data.vulnerabilities[0].cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] ||
                      cve.metrics?.cvssMetricV30?.[0] ||
                      cve.metrics?.cvssMetricV2?.[0];
      return txt({
        id:           cve.id,
        published:    cve.published?.slice(0,10),
        modified:     cve.lastModified?.slice(0,10),
        description:  cve.descriptions?.find(d => d.lang==="en")?.value || "",
        cvss_score:   metrics?.cvssData?.baseScore,
        severity:     metrics?.cvssData?.baseSeverity || metrics?.baseSeverity,
        vector:       metrics?.cvssData?.vectorString,
        cwe:          cve.weaknesses?.[0]?.description?.[0]?.value,
        references:   (cve.references || []).map(r => r.url),
        configurations: cve.configurations?.slice(0,3),
      });
    }

    if (name === "check_tech_vulnerabilities") {
      const keyword = a.tech_version
        ? `${a.tech_name} ${a.tech_version}`
        : a.tech_name;
      await new Promise(r => setTimeout(r, NVD_API_KEY ? 100 : 600));
      const data = await nvdFetch({
        keywordSearch:  keyword,
        resultsPerPage: Math.min(a.results || 10, 50),
      });
      const cves = (data.vulnerabilities || [])
        .map(v => parseCVE(v))
        .sort((a, b) => (b.score || 0) - (a.score || 0));
      return txt({
        tech:    a.tech_name,
        version: a.tech_version || "any",
        total:   data.totalResults,
        cves,
      });
    }

    if (name === "get_recent_critical_cves") {
      const from = new Date(Date.now() - ((a.days_back || 7) * 86400000));
      await new Promise(r => setTimeout(r, NVD_API_KEY ? 100 : 600));
      const data = await nvdFetch({
        cvssV3Severity: "CRITICAL",
        pubStartDate:   from.toISOString().slice(0,19) + ".000",
        resultsPerPage: Math.min(a.results || 20, 50),
      });
      const cves = (data.vulnerabilities || [])
        .map(v => parseCVE(v))
        .sort((a, b) => (b.score || 0) - (a.score || 0));
      return txt({ period_days: a.days_back || 7, total: data.totalResults, cves });
    }

    if (name === "check_domain_tech_stack") {
      const results = [];
      for (const tech of (a.tech_stack || []).slice(0, 10)) {
        if (!tech.name) continue;
        await new Promise(r => setTimeout(r, NVD_API_KEY ? 200 : 1000));
        try {
          const keyword = tech.version ? `${tech.name} ${tech.version}` : tech.name;
          const data = await nvdFetch({
            keywordSearch:  keyword,
            resultsPerPage: 5,
          });
          const cves = (data.vulnerabilities || [])
            .map(v => parseCVE(v))
            .sort((a, b) => (b.score || 0) - (a.score || 0));
          if (cves.length > 0) {
            results.push({
              tech:    tech.name,
              version: tech.version || "unknown",
              cve_count: data.totalResults,
              top_cves:  cves.slice(0, 3),
              max_score: cves[0]?.score || 0,
            });
          }
        } catch {}
      }
      // Ordenar por puntuación máxima
      results.sort((a, b) => b.max_score - a.max_score);
      return txt({ analyzed: a.tech_stack.length, vulnerable_components: results.length, results });
    }

    return txt(`Herramienta desconocida: ${name}`);
  } catch (e) { return txt(`Error NVD: ${e.message}`); }
});

(async () => {
  await server.connect(new StdioServerTransport());
  process.stderr.write("hackeadora-mcp-nvd OK\n");
})();
