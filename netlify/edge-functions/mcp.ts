import type { Config, Context } from "@netlify/edge-functions";

// ---------------------------------------------------------------------------
// Config - catch all routes
// ---------------------------------------------------------------------------

export const config: Config = { path: "/*" };

// ---------------------------------------------------------------------------
// Env helpers
// ---------------------------------------------------------------------------

const env = (key: string) => Netlify.env.get(key) ?? "";

// ---------------------------------------------------------------------------
// Crypto helpers (stateless HMAC-SHA256 signing)
// ---------------------------------------------------------------------------

async function getKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret + "_signing_key"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await getKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function hmacVerify(data: string, sig: string, secret: string): Promise<boolean> {
  return (await hmacSign(data, secret)) === sig;
}

async function sha256Base64url(input: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ---------------------------------------------------------------------------
// Auth code + token helpers
// ---------------------------------------------------------------------------

async function createCode(codeChallenge: string, secret: string): Promise<string> {
  const payload = btoa(JSON.stringify({ ts: Date.now(), cc: codeChallenge }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const sig = await hmacSign(payload, secret);
  return `${payload}.${sig}`;
}

async function verifyCode(
  code: string,
  secret: string
): Promise<{ cc: string } | null> {
  const parts = code.split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  if (!(await hmacVerify(payload, sig, secret))) return null;
  try {
    const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    if (Date.now() - json.ts > 5 * 60 * 1000) return null;
    return json;
  } catch {
    return null;
  }
}

async function createAccessToken(secret: string): Promise<string> {
  const exp = String(Date.now() + 365 * 24 * 60 * 60 * 1000);
  const sig = await hmacSign(exp, secret);
  return `${exp}.${sig}`;
}

async function verifyAccessToken(token: string, secret: string): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [exp, sig] = parts;
  if (Date.now() > Number(exp)) return false;
  return hmacVerify(exp, sig, secret);
}

// ---------------------------------------------------------------------------
// Supabase query helper (REST API, no client library needed)
// ---------------------------------------------------------------------------

async function supabaseSelect(
  table: string,
  params: Record<string, string> = {},
  select = "*"
): Promise<unknown[]> {
  const SUPABASE_URL = env("SUPABASE_URL");
  const SUPABASE_KEY = env("SUPABASE_SERVICE_KEY");

  const url = new URL(`${SUPABASE_URL}/rest/v1/${table}`);
  url.searchParams.set("select", select);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const res = await fetch(url.toString(), {
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Supabase error ${res.status}: ${text}`);
  }

  return res.json();
}

// ---------------------------------------------------------------------------
// MCP tool definitions
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: "list_available_periods",
    description:
      "List all available report periods, types, and classes stored in the K&D QBO database. Use this first to understand what data is available before querying.",
    inputSchema: {
      type: "object",
      properties: {
        report_type: {
          type: "string",
          description:
            "Optional filter by report type (e.g. ProfitAndLoss, BalanceSheet, AgedReceivables)",
        },
      },
    },
  },
  {
    name: "get_profit_and_loss",
    description:
      "Get a Profit & Loss report for a specific period and optional class. Returns the full QBO P&L payload including revenue, COGS, gross profit, and expenses. Call list_available_periods first to confirm valid period/class combinations.",
    inputSchema: {
      type: "object",
      properties: {
        period_start: {
          type: "string",
          description: "Report start date in YYYY-MM-DD format (e.g. 2025-01-01)",
        },
        period_end: {
          type: "string",
          description: "Report end date in YYYY-MM-DD format (e.g. 2025-03-31)",
        },
        class_name: {
          type: "string",
          description:
            "Optional QBO class name (e.g. Commercial, MEW, Residential, SLO). Omit for company-wide totals.",
        },
      },
      required: ["period_start", "period_end"],
    },
  },
  {
    name: "list_classes",
    description:
      "List all QBO classes configured in K&D. Returns class names, parent classes, and sync status.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "list_budgets",
    description:
      "List all available budgets and forecasts stored in the K&D QBO database, including budget names, fiscal years, and types. Use this to find the right budget before calling get_budget.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "get_budget",
    description:
      "Get a budget or forecast payload by budget_id. Returns monthly BudgetDetail entries with account references and amounts. Call list_budgets first to find the correct budget_id.",
    inputSchema: {
      type: "object",
      properties: {
        budget_id: {
          type: "string",
          description:
            "The QBO budget ID (e.g. 1000000071). Get this from list_budgets.",
        },
      },
      required: ["budget_id"],
    },
  },
];

// ---------------------------------------------------------------------------
// MCP tool handlers
// ---------------------------------------------------------------------------

async function handleTool(
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  if (name === "list_available_periods") {
    const params: Record<string, string> = {
      order: "period_start.desc",
    };
    if (typeof args.report_type === "string") {
      params["report_type"] = `eq.${args.report_type}`;
    }
    const data = await supabaseSelect(
      "qbo_reports",
      params,
      "report_type,period_start,period_end,class_name,fetched_at"
    );
    const seen = new Set<string>();
    return (data as Record<string, unknown>[]).filter((r) => {
      const k = `${r.report_type}|${r.period_start}|${r.period_end}|${r.class_name}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  if (name === "get_profit_and_loss") {
    if (
      typeof args.period_start !== "string" ||
      typeof args.period_end !== "string"
    ) {
      throw new Error("period_start and period_end are required");
    }
    const params: Record<string, string> = {
      report_type: "eq.ProfitAndLoss",
      period_start: `eq.${args.period_start}`,
      period_end: `eq.${args.period_end}`,
      order: "fetched_at.desc",
      limit: "1",
    };
    if (typeof args.class_name === "string") {
      params["class_name"] = `eq.${args.class_name}`;
    } else {
      params["class_name"] = "is.null";
    }
    const data = await supabaseSelect(
      "qbo_reports",
      params,
      "report_type,period_start,period_end,class_name,payload,fetched_at"
    );
    if (!data || data.length === 0) {
      throw new Error(
        `No P&L found for ${args.period_start} to ${args.period_end}${
          args.class_name ? ` / ${args.class_name}` : ""
        }`
      );
    }
    return data[0];
  }

  if (name === "list_classes") {
    return supabaseSelect(
      "qbo_classes",
      { order: "class_name.asc" },
      "class_name,parent_class_name,qbo_class_id,sync_enabled"
    );
  }

  if (name === "list_budgets") {
    return supabaseSelect(
      "qbo_budgets",
      { order: "start_date.desc" },
      "budget_id,budget_name,start_date,end_date,budget_type,fetched_at"
    );
  }

  if (name === "get_budget") {
    if (typeof args.budget_id !== "string") throw new Error("budget_id is required");
    const data = await supabaseSelect(
      "qbo_budgets",
      { budget_id: `eq.${args.budget_id}`, limit: "1" },
      "budget_id,budget_name,start_date,end_date,budget_type,payload,fetched_at"
    );
    if (!data || data.length === 0) throw new Error(`Budget ${args.budget_id} not found`);
    return data[0];
  }

  throw new Error(`Unknown tool: ${name}`);
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, x-api-key, MCP-Protocol-Version",
};

function jsonRes(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json", ...extra },
  });
}

function htmlRes(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

// ---------------------------------------------------------------------------
// Login form HTML (K&D branded)
// ---------------------------------------------------------------------------

function loginHtml(qs: string, error = ""): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>K&D Landscaping - QBO Data Access</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Montserrat','Segoe UI',sans-serif;background:#212221;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{background:#fff;border-radius:12px;padding:40px 36px;max-width:420px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,.4)}
    .logo{color:#7A9B49;font-size:22px;font-weight:700;margin-bottom:4px}
    .subtitle{color:#546121;font-size:13px;margin-bottom:28px}
    label{display:block;font-size:13px;font-weight:600;color:#212221;margin-bottom:6px}
    input[type=password]{width:100%;padding:10px 14px;border:2px solid #ddd;border-radius:8px;font-size:15px;outline:none;transition:border-color .2s}
    input[type=password]:focus{border-color:#7A9B49}
    .error{color:#c0392b;font-size:13px;margin-top:8px}
    button{margin-top:20px;width:100%;padding:12px;background:#7A9B49;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
    button:hover{background:#546121}
    .note{font-size:12px;color:#888;margin-top:18px;text-align:center}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">K&D Landscaping</div>
    <div class="subtitle">QuickBooks Financial Data - Claude.ai Access</div>
    <form method="POST" action="/authorize?${qs}">
      <label for="secret">API Key</label>
      <input type="password" id="secret" name="secret" placeholder="Enter your K&D API key" required autofocus/>
      ${error ? `<div class="error">${error}</div>` : ""}
      <button type="submit">Connect</button>
    </form>
    <div class="note">This grants read-only access to K&D financial reports.</div>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export default async function handler(req: Request, _ctx: Context) {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

  const url = new URL(req.url);
  const path = url.pathname;
  const MCP_SECRET = env("MCP_SECRET");
  const BASE_URL = env("BASE_URL"); // e.g. https://mcp.kndlandscaping.com

  // -------------------------------------------------------------------------
  // OAuth metadata discovery
  // -------------------------------------------------------------------------
  if (path === "/.well-known/oauth-protected-resource") {
    return jsonRes({
      resource: BASE_URL,
      authorization_servers: [BASE_URL],
    });
  }

  if (path === "/.well-known/oauth-authorization-server") {
    return jsonRes({
      issuer: BASE_URL,
      authorization_endpoint: `${BASE_URL}/authorize`,
      token_endpoint: `${BASE_URL}/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  }

  // -------------------------------------------------------------------------
  // Authorize endpoint
  // -------------------------------------------------------------------------
  if (path === "/authorize") {
    const code_challenge = url.searchParams.get("code_challenge") ?? "";
    const code_challenge_method = url.searchParams.get("code_challenge_method") ?? "S256";
    const state = url.searchParams.get("state") ?? "";
    const redirect_uri = url.searchParams.get("redirect_uri") ?? "";
    const qs = url.searchParams.toString();

    if (req.method === "GET") {
      return htmlRes(loginHtml(qs));
    }

    if (req.method === "POST") {
      let secret = "";
      const ct = req.headers.get("content-type") ?? "";
      if (ct.includes("application/x-www-form-urlencoded")) {
        const form = new URLSearchParams(await req.text());
        secret = form.get("secret") ?? "";
      } else {
        try {
          const j = await req.json();
          secret = j.secret ?? "";
        } catch { /* ignore */ }
      }

      if (secret !== MCP_SECRET) {
        return htmlRes(loginHtml(qs, "Invalid API key. Please try again."), 401);
      }
      if (code_challenge_method !== "S256") {
        return htmlRes(loginHtml(qs, "Unsupported code challenge method."), 400);
      }

      const code = await createCode(code_challenge, MCP_SECRET);
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set("code", code);
      redirectUrl.searchParams.set("state", state);

      return new Response(null, {
        status: 302,
        headers: { ...CORS, Location: redirectUrl.toString() },
      });
    }
  }

  // -------------------------------------------------------------------------
  // Token endpoint
  // -------------------------------------------------------------------------
  if (path === "/token" && req.method === "POST") {
    let code = "", code_verifier = "", grant_type = "";
    const ct = req.headers.get("content-type") ?? "";
    if (ct.includes("application/x-www-form-urlencoded")) {
      const form = new URLSearchParams(await req.text());
      code = form.get("code") ?? "";
      code_verifier = form.get("code_verifier") ?? "";
      grant_type = form.get("grant_type") ?? "";
    } else {
      try {
        const j = await req.json();
        code = j.code ?? ""; code_verifier = j.code_verifier ?? ""; grant_type = j.grant_type ?? "";
      } catch { return jsonRes({ error: "invalid_request" }, 400); }
    }

    if (grant_type !== "authorization_code") {
      return jsonRes({ error: "unsupported_grant_type" }, 400);
    }

    const codeData = await verifyCode(code, MCP_SECRET);
    if (!codeData) {
      return jsonRes({ error: "invalid_grant", error_description: "Code is invalid or expired" }, 400);
    }

    const challenge = await sha256Base64url(code_verifier);
    if (challenge !== codeData.cc) {
      return jsonRes({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
    }

    const access_token = await createAccessToken(MCP_SECRET);
    return jsonRes({ access_token, token_type: "bearer", expires_in: 31536000 });
  }

  // -------------------------------------------------------------------------
  // MCP JSON-RPC (all other requests)
  // -------------------------------------------------------------------------

  const authHeader = req.headers.get("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  const authed =
    token === MCP_SECRET ||
    (token.length > 0 && (await verifyAccessToken(token, MCP_SECRET)));

  let body: { id?: unknown; method?: string; params?: Record<string, unknown> };
  try {
    body = await req.json();
  } catch {
    return jsonRes({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
  }

  const { id, method, params } = body;
  const ok = (result: unknown) => jsonRes({ jsonrpc: "2.0", id, result });
  const err = (code: number, message: string) =>
    jsonRes({ jsonrpc: "2.0", id, error: { code, message } });

  try {
    // Handshake methods allowed without auth so claude.ai can verify the
    // server is reachable before initiating the OAuth flow
    if (method === "initialize") {
      return ok({
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "knd-qbo", version: "3.0.0" },
      });
    }
    if (method === "notifications/initialized") return new Response(null, { status: 204, headers: CORS });
    if (method === "ping") return ok({});
    if (method === "tools/list") return ok({ tools: TOOLS });

    // All tool calls require auth
    if (method === "tools/call") {
      if (!authed) {
        return jsonRes(
          { jsonrpc: "2.0", id, error: { code: -32000, message: "Unauthorized" } },
          401,
          { "WWW-Authenticate": `Bearer realm="${BASE_URL}"` }
        );
      }
      const toolName = params?.name;
      const toolArgs = (params?.arguments ?? {}) as Record<string, unknown>;
      if (typeof toolName !== "string") return err(-32602, "Invalid params: name required");
      const result = await handleTool(toolName, toolArgs);
      return ok({ content: [{ type: "text", text: JSON.stringify(result, null, 2) }] });
    }

    return err(-32601, `Method not found: ${method}`);
  } catch (e) {
    return err(-32603, e instanceof Error ? e.message : String(e));
  }
}
