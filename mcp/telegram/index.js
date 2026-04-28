#!/usr/bin/env node
"use strict";
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = require("@modelcontextprotocol/sdk/types.js");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || "";
const TG_API    = `https://api.telegram.org/bot${BOT_TOKEN}`;

async function tgCall(method, body = {}) {
  const { default: fetch } = await import("node-fetch");
  const r = await fetch(`${TG_API}/${method}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  return r.json();
}

const server = new Server(
  { name: "hackeadora-telegram", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const txt = s => ({ content: [{ type: "text", text: typeof s === "string" ? s : JSON.stringify(s, null, 2) }] });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: "send_message",
    description: "Envía un mensaje de texto al canal de Hackeadora (soporta Markdown)",
    inputSchema: { type: "object", required: ["text"],
      properties: {
        text:        { type: "string" },
        parse_mode:  { type: "string", default: "Markdown" },
        chat_id:     { type: "string", description: "Omitir para usar el canal por defecto" },
      } } },
  { name: "send_finding_report",
    description: "Envía un finding formateado con severidad, URL y recomendación",
    inputSchema: { type: "object", required: ["title","severity","target"],
      properties: {
        title:          { type: "string" },
        severity:       { type: "string", enum: ["critical","high","medium","low","info"] },
        target:         { type: "string" },
        description:    { type: "string" },
        recommendation: { type: "string" },
        domain:         { type: "string" },
        tool:           { type: "string" },
      } } },
  { name: "send_scan_summary",
    description: "Envía un resumen completo de scan al canal",
    inputSchema: { type: "object", required: ["domain"],
      properties: {
        domain:       { type: "string" },
        subdomains:   { type: "number" },
        urls:         { type: "number" },
        findings:     { type: "number" },
        critical:     { type: "number" },
        high:         { type: "number" },
        new_secrets:  { type: "number" },
        duration_min: { type: "number" },
        ai_summary:   { type: "string", description: "Resumen del AI Advisor (opcional)" },
      } } },
  { name: "send_ai_analysis",
    description: "Envía el análisis completo del AI Advisor con chains y recomendaciones",
    inputSchema: { type: "object", required: ["domain","analysis"],
      properties: {
        domain:   { type: "string" },
        analysis: { type: "string" },
        chains:   { type: "string" },
        cost_usd: { type: "number" },
      } } },
  { name: "ask_confirmation",
    description: "Envía un mensaje con botones inline para pedir confirmación",
    inputSchema: { type: "object", required: ["text","options"],
      properties: {
        text:    { type: "string" },
        options: { type: "array", items: { type: "string" },
                   description: "Lista de opciones para los botones" },
        chat_id: { type: "string" },
      } } },
  { name: "get_recent_messages",
    description: "Lee los últimos mensajes/respuestas del canal (para procesar confirmaciones)",
    inputSchema: { type: "object", properties: {
      limit:  { type: "number", default: 5 },
      offset: { type: "number" },
    } } },
]}));

server.setRequestHandler(CallToolRequestSchema, async ({ params: { name, arguments: a } }) => {
  const chat = a.chat_id || CHAT_ID;
  try {
    if (name === "send_message") {
      const r = await tgCall("sendMessage", {
        chat_id:    chat,
        text:       a.text,
        parse_mode: a.parse_mode || "Markdown",
        disable_web_page_preview: true,
      });
      return txt({ sent: r.ok, message_id: r.result?.message_id });
    }

    if (name === "send_finding_report") {
      const icons = { critical:"🔴🔴", high:"🔴", medium:"🟠", low:"🟡", info:"⚪" };
      const icon  = icons[a.severity] || "⚪";
      const msg   = [
        `${icon} *${a.severity?.toUpperCase()} — ${a.title}*`,
        `🌐 Dominio: \`${a.domain || "?"}\``,
        `🎯 Target: \`${a.target}\``,
        a.description    ? `📋 ${a.description.slice(0, 300)}` : "",
        a.recommendation ? `💡 Fix: ${a.recommendation.slice(0, 200)}` : "",
        a.tool           ? `🔧 Herramienta: \`${a.tool}\`` : "",
        `📅 ${new Date().toISOString().slice(0,16)}`,
      ].filter(Boolean).join("\n");

      const r = await tgCall("sendMessage", {
        chat_id: chat, text: msg, parse_mode: "Markdown",
        disable_web_page_preview: true,
      });
      return txt({ sent: r.ok });
    }

    if (name === "send_scan_summary") {
      const msg = [
        `✅ *Scan completado — ${a.domain}*`,
        `🌐 Subdominios: \`${a.subdomains || 0}\``,
        `🔗 URLs: \`${a.urls || 0}\``,
        `⚡ Findings: \`${a.findings || 0}\``,
        (a.critical || a.high) ? `🔴 Critical/High: \`${(a.critical||0) + (a.high||0)}\`` : "",
        a.new_secrets > 0 ? `🔑 Secrets nuevos: \`${a.new_secrets}\`` : "",
        a.duration_min ? `⏱ Duración: \`${a.duration_min} min\`` : "",
        a.ai_summary ? `\n🤖 *AI Summary:*\n${a.ai_summary.slice(0, 400)}` : "",
        `📅 ${new Date().toISOString().slice(0,16)}`,
      ].filter(Boolean).join("\n");

      const r = await tgCall("sendMessage", {
        chat_id: chat, text: msg, parse_mode: "Markdown",
        disable_web_page_preview: true,
      });
      return txt({ sent: r.ok });
    }

    if (name === "send_ai_analysis") {
      // Dividir en mensajes si es muy largo (Telegram max 4096 chars)
      const header = `🤖 *AI Advisor — ${a.domain}*\n💰 Coste: $${(a.cost_usd||0).toFixed(3)}\n\n`;
      const full   = header + (a.analysis || "");
      const chunks = [];
      for (let i = 0; i < full.length; i += 3900)
        chunks.push(full.slice(i, i + 3900));

      for (const chunk of chunks) {
        await tgCall("sendMessage", {
          chat_id: chat, text: chunk, parse_mode: "Markdown",
          disable_web_page_preview: true,
        });
        if (chunks.length > 1) await new Promise(r => setTimeout(r, 500));
      }

      if (a.chains) {
        await tgCall("sendMessage", {
          chat_id: chat,
          text: `🔗 *Vulnerability Chains*\n\n${a.chains.slice(0,3900)}`,
          parse_mode: "Markdown",
        });
      }
      return txt({ sent: true, chunks: chunks.length });
    }

    if (name === "ask_confirmation") {
      const keyboard = {
        inline_keyboard: [
          a.options.map(opt => ({ text: opt, callback_data: opt }))
        ],
      };
      const r = await tgCall("sendMessage", {
        chat_id:      chat,
        text:         a.text,
        parse_mode:   "Markdown",
        reply_markup: keyboard,
      });
      return txt({ sent: r.ok, message_id: r.result?.message_id });
    }

    if (name === "get_recent_messages") {
      const r = await tgCall("getUpdates", {
        limit:   a.limit || 5,
        offset:  a.offset,
        timeout: 0,
      });
      const updates = (r.result || []).map(u => ({
        update_id:    u.update_id,
        text:         u.message?.text || u.callback_query?.data || "",
        from:         u.message?.from?.username || u.callback_query?.from?.username || "?",
        date:         new Date((u.message?.date || 0) * 1000).toISOString(),
        callback_data:u.callback_query?.data || null,
        msg_id:       u.callback_query?.message?.message_id || u.message?.message_id,
      }));
      return txt({ count: updates.length, updates });
    }

    return txt(`Herramienta desconocida: ${name}`);
  } catch (e) { return txt(`Error: ${e.message}`); }
});

(async () => {
  await server.connect(new StdioServerTransport());
  process.stderr.write("hackeadora-mcp-telegram OK\n");
})();
