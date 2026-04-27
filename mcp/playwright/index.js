#!/usr/bin/env node
"use strict";
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = require("@modelcontextprotocol/sdk/types.js");

// Proxy de Caido/Burp para enrutar tráfico
const PROXY_URL = process.env.HACKEADORA_PROXY || "";

const server = new Server(
  { name: "hackeadora-playwright", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const txt = s => ({ content: [{ type: "text", text: typeof s === "string" ? s : JSON.stringify(s, null, 2) }] });

async function getBrowser() {
  const { chromium } = require("playwright");
  const opts = {
    headless: true,
    args: ["--no-sandbox","--disable-setuid-sandbox","--disable-dev-shm-usage"],
  };
  if (PROXY_URL) opts.proxy = { server: PROXY_URL };
  return chromium.launch(opts);
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: "navigate_and_extract",
    description: "Abre una URL con un navegador real y extrae links, formularios y endpoints JS",
    inputSchema: { type: "object", required: ["url"],
      properties: {
        url:     { type: "string" },
        cookies: { type: "string", description: "Cookies de sesión en formato 'name=val; name2=val2'" },
        wait_for:{ type: "string", description: "Selector CSS a esperar antes de extraer" },
      } } },
  { name: "login_and_crawl",
    description: "Hace login en un formulario y crawlea el área autenticada",
    inputSchema: { type: "object", required: ["login_url","username","password"],
      properties: {
        login_url:      { type: "string" },
        username:       { type: "string" },
        password:       { type: "string" },
        username_field: { type: "string", default: "input[type=email],input[name=username],input[name=email]" },
        password_field: { type: "string", default: "input[type=password]" },
        submit_selector:{ type: "string", default: "button[type=submit],input[type=submit]" },
        crawl_depth:    { type: "number", default: 2 },
      } } },
  { name: "screenshot",
    description: "Captura screenshot de una URL (con soporte de autenticación)",
    inputSchema: { type: "object", required: ["url"],
      properties: {
        url:     { type: "string" },
        cookies: { type: "string" },
      } } },
  { name: "extract_api_calls",
    description: "Monitoriza las llamadas XHR/fetch que hace una página (intercepta tráfico de red)",
    inputSchema: { type: "object", required: ["url"],
      properties: {
        url:       { type: "string" },
        cookies:   { type: "string" },
        wait_secs: { type: "number", default: 5 },
      } } },
  { name: "fill_and_submit_form",
    description: "Rellena y envía un formulario en una página",
    inputSchema: { type: "object", required: ["url","fields"],
      properties: {
        url:     { type: "string" },
        cookies: { type: "string" },
        fields:  { type: "object", description: "{ selector: value, ... }" },
        submit:  { type: "string", description: "Selector del botón de envío" },
      } } },
]}));

server.setRequestHandler(CallToolRequestSchema, async ({ params: { name, arguments: a } }) => {
  let browser;
  try {
    if (name === "navigate_and_extract") {
      browser = await getBrowser();
      const ctx  = await browser.newContext();
      if (a.cookies) {
        const url    = new URL(a.url);
        const parsed = a.cookies.split(";").map(c => {
          const [n, ...v] = c.trim().split("=");
          return { name: n.trim(), value: v.join("=").trim(),
                   domain: url.hostname, path: "/" };
        });
        await ctx.addCookies(parsed);
      }
      const page = await ctx.newPage();
      await page.goto(a.url, { waitUntil: "networkidle", timeout: 30000 });
      if (a.wait_for) await page.waitForSelector(a.wait_for, { timeout: 5000 }).catch(() => {});

      const result = await page.evaluate(() => ({
        title: document.title,
        links: [...document.querySelectorAll("a[href]")].map(a => a.href).filter(h => h.startsWith("http")),
        forms: [...document.querySelectorAll("form")].map(f => ({
          action: f.action, method: f.method,
          fields: [...f.querySelectorAll("input,select,textarea")].map(i => ({
            name: i.name, type: i.type, id: i.id
          })),
        })),
        endpoints: [...document.querySelectorAll("script")].map(s => s.src).filter(Boolean),
      }));
      return txt(result);
    }

    if (name === "login_and_crawl") {
      browser = await getBrowser();
      const ctx   = await browser.newContext();
      const page  = await ctx.newPage();
      await page.goto(a.login_url, { waitUntil: "networkidle", timeout: 30000 });

      // Rellenar usuario
      const uField = a.username_field || "input[type=email],input[name=username],input[name=email]";
      await page.fill(uField, a.username);

      // Rellenar password
      const pField = a.password_field || "input[type=password]";
      await page.fill(pField, a.password);

      // Submit
      const sField = a.submit_selector || "button[type=submit],input[type=submit]";
      await Promise.all([
        page.waitForNavigation({ timeout: 15000 }).catch(() => {}),
        page.click(sField),
      ]);

      const loginOk = page.url() !== a.login_url;
      if (!loginOk) return txt({ success: false, message: "Login posiblemente fallido — misma URL tras submit" });

      // Crawl básico
      const visited = new Set([page.url()]);
      const found_urls = [page.url()];
      const depth = Math.min(a.crawl_depth || 2, 3);

      for (let d = 0; d < depth; d++) {
        const links = await page.evaluate(() =>
          [...document.querySelectorAll("a[href]")].map(a => a.href)
        );
        for (const link of links.slice(0, 20)) {
          if (visited.has(link)) continue;
          if (!link.startsWith("http")) continue;
          visited.add(link);
          found_urls.push(link);
          try {
            await page.goto(link, { waitUntil: "domcontentloaded", timeout: 10000 });
          } catch {}
        }
      }

      // Recoger cookies de sesión
      const cookies = await ctx.cookies();

      return txt({
        success:    true,
        urls_found: found_urls.length,
        urls:       found_urls,
        session_cookies: cookies.map(c => `${c.name}=${c.value}`).join("; "),
      });
    }

    if (name === "screenshot") {
      browser = await getBrowser();
      const ctx  = await browser.newContext();
      if (a.cookies) {
        const url    = new URL(a.url);
        const parsed = a.cookies.split(";").map(c => {
          const [n,...v] = c.trim().split("=");
          return { name: n.trim(), value: v.join("=").trim(), domain: url.hostname, path: "/" };
        });
        await ctx.addCookies(parsed);
      }
      const page = await ctx.newPage();
      await page.goto(a.url, { waitUntil: "networkidle", timeout: 30000 });
      const buf = await page.screenshot({ type: "png", fullPage: true });
      return txt(`Screenshot tomado: ${buf.length} bytes (base64: ${buf.toString("base64").slice(0,100)}...)`);
    }

    if (name === "extract_api_calls") {
      browser = await getBrowser();
      const ctx   = await browser.newContext();
      const calls = [];
      if (a.cookies) {
        const url = new URL(a.url);
        const parsed = a.cookies.split(";").map(c => {
          const [n,...v] = c.trim().split("=");
          return { name: n.trim(), value: v.join("=").trim(), domain: url.hostname, path: "/" };
        });
        await ctx.addCookies(parsed);
      }
      const page = await ctx.newPage();
      page.on("request", req => {
        if (["xhr","fetch"].includes(req.resourceType()))
          calls.push({ method: req.method(), url: req.url(),
                       headers: req.headers() });
      });
      await page.goto(a.url, { waitUntil: "networkidle", timeout: 30000 });
      await page.waitForTimeout((a.wait_secs || 5) * 1000);
      return txt({ total: calls.length, api_calls: calls });
    }

    if (name === "fill_and_submit_form") {
      browser = await getBrowser();
      const ctx  = await browser.newContext();
      if (a.cookies) {
        const url = new URL(a.url);
        const parsed = a.cookies.split(";").map(c => {
          const [n,...v] = c.trim().split("=");
          return { name: n.trim(), value: v.join("=").trim(), domain: url.hostname, path: "/" };
        });
        await ctx.addCookies(parsed);
      }
      const page = await ctx.newPage();
      await page.goto(a.url, { waitUntil: "networkidle", timeout: 30000 });
      for (const [selector, value] of Object.entries(a.fields || {}))
        await page.fill(selector, String(value)).catch(() => {});
      if (a.submit) {
        await Promise.all([
          page.waitForNavigation({ timeout: 10000 }).catch(() => {}),
          page.click(a.submit),
        ]);
      }
      return txt({ success: true, final_url: page.url(),
                   title: await page.title() });
    }

    return txt(`Herramienta desconocida: ${name}`);
  } catch (e) {
    return txt(`Error: ${e.message}`);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
});

(async () => {
  await server.connect(new StdioServerTransport());
  process.stderr.write("hackeadora-mcp-playwright OK\n");
})();
