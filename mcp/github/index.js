#!/usr/bin/env node
"use strict";
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = require("@modelcontextprotocol/sdk/types.js");

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const BASE = "https://api.github.com";

async function ghFetch(path, params = {}) {
  const { default: fetch } = await import("node-fetch");
  const qs = Object.keys(params).length ? "?" + new URLSearchParams(params) : "";
  const r = await fetch(`${BASE}${path}${qs}`, {
    headers: {
      "Accept":        "application/vnd.github.v3+json",
      "User-Agent":    "Hackeadora-MCP/1.0",
      ...(GITHUB_TOKEN ? { "Authorization": `Bearer ${GITHUB_TOKEN}` } : {}),
    },
  });
  if (!r.ok) throw new Error(`GitHub ${r.status}: ${path}`);
  return r.json();
}

const server = new Server(
  { name: "hackeadora-github", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const txt = s => ({ content: [{ type: "text", text: typeof s === "string" ? s : JSON.stringify(s, null, 2) }] });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: "search_code",
    description: "Busca código en GitHub por dominio/org (secrets, endpoints, configs)",
    inputSchema: { type: "object", required: ["query"],
      properties: { query: { type: "string", description: 'Ej: "empresa.com" password' },
                    per_page: { type: "number", default: 10 } } } },
  { name: "list_org_repos",
    description: "Lista repositorios públicos de una organización",
    inputSchema: { type: "object", required: ["org"],
      properties: { org: { type: "string" }, per_page: { type: "number", default: 30 } } } },
  { name: "read_file_from_repo",
    description: "Lee el contenido de un archivo de un repo público",
    inputSchema: { type: "object", required: ["owner","repo","filepath"],
      properties: { owner: { type: "string" }, repo: { type: "string" },
                    filepath: { type: "string" }, ref: { type: "string", default: "main" } } } },
  { name: "get_recent_commits",
    description: "Últimos commits de un repo — útil para detectar secretos recientes",
    inputSchema: { type: "object", required: ["owner","repo"],
      properties: { owner: { type: "string" }, repo: { type: "string" },
                    per_page: { type: "number", default: 10 } } } },
  { name: "search_secrets_in_repo",
    description: "Busca patrones de secrets en los archivos de un repo",
    inputSchema: { type: "object", required: ["owner","repo"],
      properties: { owner: { type: "string" }, repo: { type: "string" } } } },
]}));

server.setRequestHandler(CallToolRequestSchema, async ({ params: { name, arguments: a } }) => {
  try {
    if (name === "search_code") {
      const data = await ghFetch("/search/code", { q: a.query, per_page: a.per_page || 10 });
      return txt({
        total: data.total_count,
        items: (data.items || []).map(i => ({
          repo:      i.repository.full_name,
          path:      i.path,
          url:       i.html_url,
          sha:       i.sha,
        })),
      });
    }

    if (name === "list_org_repos") {
      const data = await ghFetch(`/orgs/${a.org}/repos`, {
        per_page: a.per_page || 30, sort: "updated", type: "public"
      });
      return txt(data.map(r => ({
        name:        r.name,
        description: r.description,
        url:         r.html_url,
        updated_at:  r.updated_at,
        language:    r.language,
        stars:       r.stargazers_count,
      })));
    }

    if (name === "read_file_from_repo") {
      const data = await ghFetch(
        `/repos/${a.owner}/${a.repo}/contents/${a.filepath}`,
        { ref: a.ref || "main" }
      );
      if (data.encoding === "base64") {
        const content = Buffer.from(data.content, "base64").toString("utf8");
        // Truncar si es muy grande
        return txt(content.length > 50000 ? content.slice(0, 50000) + "\n...[truncado]" : content);
      }
      return txt(data);
    }

    if (name === "get_recent_commits") {
      const data = await ghFetch(`/repos/${a.owner}/${a.repo}/commits`,
        { per_page: a.per_page || 10 });
      return txt(data.map(c => ({
        sha:     c.sha.slice(0, 8),
        message: c.commit.message.split("\n")[0],
        author:  c.commit.author.name,
        date:    c.commit.author.date,
        url:     c.html_url,
      })));
    }

    if (name === "search_secrets_in_repo") {
      // Buscar patrones comunes de secrets en el repo
      const patterns = [
        `"${a.owner}/${a.repo}" password`,
        `"${a.owner}/${a.repo}" api_key`,
        `"${a.owner}/${a.repo}" secret`,
        `"${a.owner}/${a.repo}" token`,
        `"${a.owner}/${a.repo}" .env`,
      ];
      const results = [];
      for (const q of patterns) {
        try {
          const data = await ghFetch("/search/code", { q, per_page: 5 });
          if (data.total_count > 0)
            results.push({ query: q, count: data.total_count,
              files: data.items.map(i => i.path) });
          await new Promise(r => setTimeout(r, 2000)); // rate limit
        } catch {}
      }
      return txt(results);
    }

    return txt(`Herramienta desconocida: ${name}`);
  } catch (e) { return txt(`Error: ${e.message}`); }
});

(async () => {
  await server.connect(new StdioServerTransport());
  process.stderr.write("hackeadora-mcp-github OK\n");
})();
