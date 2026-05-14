// K&D QBO MCP server - Netlify Edge Function
//
// Ported from Supabase qbo-mcp v8.4 (no-fallback) with adaptations for the
// Netlify runtime, preserving production v3.1.0 OAuth surface (/register endpoint,
// scopes_supported: ["read"]) for backward compatibility with the existing
// Claude connector.
//
// Endpoints:
//   GET  /.well-known/oauth-authorization-server  OAuth2 metadata
//   GET  /authorize                                login page (HTML)
//   POST /authorize                                login submit (HTML or redirect)
//   POST /token                                    exchange auth code for access token
//   POST /register                                 RFC 7591 dynamic client registration
//   POST /                                         MCP JSON-RPC (tools/list, tools/call, ...)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const MCP_SECRET            = Netlify.env.get("MCP_SECRET")            ?? ""
const SUPABASE_URL          = Netlify.env.get("SUPABASE_URL")          ?? ""
const SUPABASE_SERVICE_KEY  = Netlify.env.get("SUPABASE_SERVICE_KEY")  ?? ""
const BACKFILL_SECRET       = Netlify.env.get("BACKFILL_SECRET")       ?? ""
const BASE_URL              = Netlify.env.get("BASE_URL")              ?? "https://mcp.kndlandscaping.com"
const DEPLOY_VERSION        = "4.0.0"

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

// ============================================================================
// OAuth/PKCE helpers
// ============================================================================
async function getKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(MCP_SECRET + "_signing_key"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  )
}
async function hmacSign(data: string): Promise<string> {
  const key = await getKey()
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data))
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}
async function hmacVerify(data: string, sig: string): Promise<boolean> {
  return (await hmacSign(data)) === sig
}
async function sha256Base64url(input: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input))
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}
async function createCode(codeChallenge: string, redirectUri: string): Promise<string> {
  const payload = btoa(JSON.stringify({ ts: Date.now(), cc: codeChallenge, ru: redirectUri }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
  return `${payload}.${await hmacSign(payload)}`
}
async function verifyCode(code: string): Promise<{ cc: string; ru: string; ts: number } | null> {
  const parts = code.split(".")
  if (parts.length !== 2) return null
  const [payload, sig] = parts
  if (!(await hmacVerify(payload, sig))) return null
  try {
    const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")))
    if (Date.now() - json.ts > 5 * 60 * 1000) return null
    return json
  } catch { return null }
}
async function createAccessToken(): Promise<string> {
  const exp = String(Date.now() + 365 * 24 * 60 * 60 * 1000)
  return `${exp}.${await hmacSign(exp)}`
}
async function verifyAccessToken(token: string): Promise<boolean> {
  const parts = token.split(".")
  if (parts.length !== 2) return false
  const [exp, sig] = parts
  if (Date.now() > Number(exp)) return false
  return hmacVerify(exp, sig)
}

// ============================================================================
// Response helpers
// ============================================================================
function jsonRes(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...extra },
  })
}
function htmlRes(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  })
}
function loginHtml(params: string, error = ""): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>K&D Landscaping - QBO Data Access</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Montserrat','Segoe UI',sans-serif;background:#212221;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.card{background:#fff;border-radius:12px;padding:40px 36px;max-width:420px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,.4)}.logo{color:#7A9B49;font-size:22px;font-weight:700;margin-bottom:4px}.subtitle{color:#546121;font-size:13px;margin-bottom:28px}label{display:block;font-size:13px;font-weight:600;color:#212221;margin-bottom:6px}input[type=password]{width:100%;padding:10px 14px;border:2px solid #ddd;border-radius:8px;font-size:15px;outline:none;transition:border-color .2s}input[type=password]:focus{border-color:#7A9B49}.error{color:#c0392b;font-size:13px;margin-top:8px}button{margin-top:20px;width:100%;padding:12px;background:#7A9B49;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}button:hover{background:#546121}.note{font-size:12px;color:#888;margin-top:18px;text-align:center}</style>
</head><body><div class="card"><div class="logo">K&D Landscaping</div><div class="subtitle">QuickBooks Financial Data - Claude.ai Access</div>
<form method="POST" action="${BASE_URL}/authorize?${params}"><label for="secret">API Key</label>
<input type="password" id="secret" name="secret" placeholder="Enter your K&D API key" required autofocus/>
${error ? `<div class="error">${error}</div>` : ""}
<button type="submit">Connect</button></form><div class="note">This grants read-only access to K&D financial reports.</div></div></body></html>`
}

// ============================================================================
// P&L extraction (same as Supabase qbo-mcp v8.4)
// ============================================================================
function resolveClassColumn(columnTitles: string[], className: string, includeSubclasses = true): { idx: number; resolved: string } | null {
  const normalized = className.includes(":") ? className.split(":").pop()!.trim() : className.trim()
  if (includeSubclasses) {
    const totalKey = `Total ${normalized}`
    const totalIdx = columnTitles.indexOf(totalKey)
    if (totalIdx >= 0) return { idx: totalIdx, resolved: totalKey }
  }
  const exactIdx = columnTitles.indexOf(normalized)
  if (exactIdx >= 0) return { idx: exactIdx, resolved: normalized }
  if (normalized !== className) {
    const origIdx = columnTitles.indexOf(className)
    if (origIdx >= 0) return { idx: origIdx, resolved: className }
  }
  return null
}
function reduceToClassColumn(payload: any, classIdx: number): unknown {
  function walk(node: any) {
    if (!node || typeof node !== "object") return
    if (Array.isArray(node.ColData) && node.ColData.length > 1) {
      const label = node.ColData[0] ?? { value: "" }
      const val   = node.ColData[classIdx] ?? { value: "" }
      node.ColData = [label, val]
    }
    if (node.Rows && Array.isArray(node.Rows.Row)) node.Rows.Row.forEach(walk)
    if (node.Header) walk(node.Header)
    if (node.Summary) walk(node.Summary)
  }
  if (payload?.Rows && Array.isArray(payload.Rows.Row)) payload.Rows.Row.forEach(walk)
  if (payload?.Columns?.Column && Array.isArray(payload.Columns.Column)) {
    const accountCol = payload.Columns.Column[0]
    const classCol   = payload.Columns.Column[classIdx] ?? { ColType: "Money" }
    payload.Columns.Column = [accountCol, classCol]
  }
  return payload
}

type Section = { group?: string; Header?: { ColData?: Array<{ id?: string; value?: string }> }; Summary?: { ColData?: Array<{ value?: string }> }; Rows?: { Row?: Section[] }; type?: string; ColData?: Array<{ id?: string; value?: string }> }

function num(v: string | undefined | null): number {
  if (!v) return 0
  const n = parseFloat(v)
  return isNaN(n) ? 0 : n
}
function pct(numerator: number, denominator: number): number {
  if (!denominator) return 0
  return Math.round((numerator / denominator) * 10000) / 100
}
function findTopSection(payload: any, group: string): Section | null {
  const rows: Section[] = payload?.Rows?.Row ?? []
  return rows.find((r) => r.group === group) ?? null
}
function sumLeafRows(section: Section | null, nameRegex: RegExp): number {
  if (!section) return 0
  let total = 0
  function walk(node: Section) {
    if (node.type === "Data" && Array.isArray(node.ColData)) {
      const label = node.ColData[0]?.value ?? ""
      if (nameRegex.test(label)) total += num(node.ColData[1]?.value)
    }
    if (node.Rows?.Row) node.Rows.Row.forEach(walk)
  }
  if (section.Rows?.Row) section.Rows.Row.forEach(walk)
  return total
}
function subSectionTotal(section: Section | null, headerRegex: RegExp): number {
  if (!section?.Rows?.Row) return 0
  let total = 0
  function walk(node: Section) {
    const header = node.Header?.ColData?.[0]?.value ?? ""
    if (headerRegex.test(header)) {
      total += num(node.Summary?.ColData?.[1]?.value)
      return
    }
    if (node.Rows?.Row) node.Rows.Row.forEach(walk)
  }
  section.Rows.Row.forEach(walk)
  return total
}
function sectionTotal(section: Section | null): number {
  return num(section?.Summary?.ColData?.[1]?.value)
}
function buildSummary(payload: any, period_start: string, period_end: string, class_name: string | null) {
  const income        = findTopSection(payload, "Income")
  const cogs          = findTopSection(payload, "COGS")
  const expenses      = findTopSection(payload, "Expenses")
  const grossProfit   = findTopSection(payload, "GrossProfit")
  const noi           = findTopSection(payload, "NetOperatingIncome")
  const otherIncome   = findTopSection(payload, "OtherIncome")
  const otherExpenses = findTopSection(payload, "OtherExpenses")
  const netIncome     = findTopSection(payload, "NetIncome")
  const revenue = {
    commercial:   sumLeafRows(income, /Commercial Revenue/i),
    residential:  sumLeafRows(income, /Residential Revenue/i),
    maintenance:  sumLeafRows(income, /Maintenance Revenue/i),
    enhancements: sumLeafRows(income, /Enhancements Revenue/i),
    irrigation:   sumLeafRows(income, /Irrigation Revenue/i),
    design:       sumLeafRows(income, /Design Revenue/i),
    total:        sectionTotal(income),
  }
  const cogsByDiv = {
    commercial:   subSectionTotal(cogs, /CGS\s*-?\s*Commercial/i),
    residential:  subSectionTotal(cogs, /CGS\s*-?\s*Residential/i),
    maintenance:  subSectionTotal(cogs, /CGS\s*-?\s*Maintenance/i),
    enhancements: subSectionTotal(cogs, /CGS\s*-?\s*Enhancements/i),
    irrigation:   subSectionTotal(cogs, /CGS\s*-?\s*Irrigation/i),
    design:       subSectionTotal(cogs, /CGS\s*-?\s*Design/i),
    total:        sectionTotal(cogs),
  }
  const grossProfitTotal = num(grossProfit?.Summary?.ColData?.[1]?.value)
  const grossMarginPct = pct(grossProfitTotal, revenue.total)
  const expensesByCat = {
    general_and_administrative: subSectionTotal(expenses, /General\s*&?\s*Administrative/i),
    operations:                 subSectionTotal(expenses, /Operations/i),
    sales_and_marketing:        subSectionTotal(expenses, /Sales\s*&?\s*Marketing/i),
    total:                      sectionTotal(expenses),
  }
  const noiTotal = num(noi?.Summary?.ColData?.[1]?.value)
  return {
    period_start, period_end, class_name, currency: "USD",
    revenue, cogs: cogsByDiv,
    gross_profit_by_division: {
      commercial:   { gp: revenue.commercial   - cogsByDiv.commercial,   gm_pct: pct(revenue.commercial   - cogsByDiv.commercial,   revenue.commercial)   },
      residential:  { gp: revenue.residential  - cogsByDiv.residential,  gm_pct: pct(revenue.residential  - cogsByDiv.residential,  revenue.residential)  },
      maintenance:  { gp: revenue.maintenance  - cogsByDiv.maintenance,  gm_pct: pct(revenue.maintenance  - cogsByDiv.maintenance,  revenue.maintenance)  },
      enhancements: { gp: revenue.enhancements - cogsByDiv.enhancements, gm_pct: pct(revenue.enhancements - cogsByDiv.enhancements, revenue.enhancements) },
      irrigation:   { gp: revenue.irrigation   - cogsByDiv.irrigation,   gm_pct: pct(revenue.irrigation   - cogsByDiv.irrigation,   revenue.irrigation)   },
      design:       { gp: revenue.design       - cogsByDiv.design,       gm_pct: pct(revenue.design       - cogsByDiv.design,       revenue.design)       },
    },
    gross_profit: grossProfitTotal,
    gross_margin_pct: grossMarginPct,
    expenses: expensesByCat,
    net_operating_income: noiTotal,
    noi_margin_pct: pct(noiTotal, revenue.total),
    other_income:   sectionTotal(otherIncome),
    other_expenses: sectionTotal(otherExpenses),
    net_income:     num(netIncome?.Summary?.ColData?.[1]?.value),
    net_income_margin_pct: pct(num(netIncome?.Summary?.ColData?.[1]?.value), revenue.total),
  }
}

// ============================================================================
// Tools (12 tools, same set as Supabase qbo-mcp v8.4)
// ============================================================================
const TOOLS = [
  {
    name: "list_available_periods",
    description: "Summary index of cached report data. Returns one row per (report_type, class_name) combo with the count of stored snapshots, earliest period_start, latest period_end, and last_fetched_at. Use this to discover what date ranges are queryable. Tiny response (typically <30 rows) regardless of cached data volume.",
    inputSchema: { type: "object", properties: { report_type: { type: "string", description: "Optional filter by report type (e.g. ProfitAndLoss, BalanceSheet, AgedReceivables, CashFlow, ProfitAndLossByClass, AgedPayables)." } } },
  },
  {
    name: "get_profit_and_loss",
    description: "Get the full raw QBO Profit & Loss payload for a specific period and optional class. For most analytical questions prefer `get_pl_summary` which is faster. Use this only when you need the raw QBO structure.",
    inputSchema: { type: "object", properties: { period_start: { type: "string", description: "YYYY-MM-DD" }, period_end: { type: "string", description: "YYYY-MM-DD" }, class_name: { type: "string", description: "Optional QBO class name." }, include_subclasses: { type: "boolean", description: "Default true." } }, required: ["period_start", "period_end"] },
  },
  {
    name: "get_pl_summary",
    description: "Get a clean, structured P&L summary. Preferred for most financial questions.",
    inputSchema: { type: "object", properties: { period_start: { type: "string", description: "YYYY-MM-DD" }, period_end: { type: "string", description: "YYYY-MM-DD" }, class_name: { type: "string", description: "Optional QBO class name." }, include_subclasses: { type: "boolean", description: "Default true." } }, required: ["period_start", "period_end"] },
  },
  {
    name: "get_balance_sheet",
    description: "Get the QBO Balance Sheet as a point-in-time snapshot. Returns assets, liabilities, and equity. If as_of_date is omitted, returns the most recent snapshot. If provided, returns the latest snapshot on or before that date. Daily snapshots run nightly so as_of_date typically returns same-day data.",
    inputSchema: { type: "object", properties: { as_of_date: { type: "string", description: "Optional YYYY-MM-DD. Defaults to most recent snapshot." } } },
  },
  {
    name: "get_cash_flow",
    description: "Get the QBO Cash Flow report (operating, investing, financing). Snapshots are typically YTD (period_start = Jan 1 of the year, period_end = the snapshot date) and run weekly on Mondays. If period_start and period_end are omitted, returns the most recent snapshot. If both are provided, returns that exact period if cached.",
    inputSchema: { type: "object", properties: { period_start: { type: "string", description: "Optional YYYY-MM-DD start date." }, period_end: { type: "string", description: "Optional YYYY-MM-DD end date." } } },
  },
  {
    name: "get_aged_receivables",
    description: "Get the QBO Aged Receivables summary (A/R aging by customer and bucket: Current, 1-30, 31-60, 61-90, 91+). Daily snapshots. If as_of_date is omitted, returns the most recent snapshot. If provided, returns the latest snapshot on or before that date.",
    inputSchema: { type: "object", properties: { as_of_date: { type: "string", description: "Optional YYYY-MM-DD. Defaults to most recent snapshot." } } },
  },
  {
    name: "get_aged_payables",
    description: "Get the QBO Aged Payables summary (A/P aging by vendor and bucket: Current, 1-30, 31-60, 61-90, 91+). Weekly snapshots on Mondays. If as_of_date is omitted, returns the most recent snapshot. If provided, returns the latest snapshot on or before that date.",
    inputSchema: { type: "object", properties: { as_of_date: { type: "string", description: "Optional YYYY-MM-DD. Defaults to most recent snapshot." } } },
  },
  { name: "list_classes", description: "List all QBO classes.", inputSchema: { type: "object", properties: {} } },
  { name: "list_budgets", description: "List budgets and forecasts.", inputSchema: { type: "object", properties: {} } },
  {
    name: "get_budget",
    description: "Get a budget payload by budget_id.",
    inputSchema: { type: "object", properties: { budget_id: { type: "string" } }, required: ["budget_id"] },
  },
  {
    name: "get_budget_vs_actuals",
    description: "Budget vs Actuals for a date range. Returns actual P&L and matched budget side by side, broken down by revenue (Commercial/Residential/Maintenance/Enhancements/Irrigation), COGS by division, expense categories (G&A subcategories: staff, travel, emp_other, training, utilities, rent, insurance, office, comms, prof_services; Operations subcategories: auto_truck, safety, repairs, yard, tools; S&M total), gross profit, OpEx, and NOI. Budget is matched by year prefix on start_date so requires a budget covering the relevant fiscal year in qbo_budgets. Requires actuals for the exact period in qbo_reports.",
    inputSchema: { type: "object", properties: { period_start: { type: "string", description: "YYYY-MM-DD" }, period_end: { type: "string", description: "YYYY-MM-DD" } }, required: ["period_start", "period_end"] },
  },
  {
    name: "get_sync_health",
    description: "Returns staleness status for each QBO data source (report types, budgets) and the OAuth refresh token. Each row has status HEALTHY / STALE / CRITICAL based on expected sync cadence. Use this to verify the data pipeline is current before doing analysis, or as a routine ops check. Sync rows include age_hours in hours; token and budget rows use age_hours to mean days (see detail field on those rows).",
    inputSchema: { type: "object", properties: {} },
  },
]

// ============================================================================
// Tool handlers
// ============================================================================
async function loadByClassReport(period_start: string, period_end: string, class_name: string, includeSubclasses: boolean) {
  const { data, error } = await supabase
    .from("qbo_reports")
    .select("payload, fetched_at")
    .eq("report_type", "ProfitAndLossByClass")
    .eq("period_start", period_start)
    .eq("period_end", period_end)
    .order("fetched_at", { ascending: false })
    .limit(1)
  if (error) throw new Error(error.message)
  if (!data || data.length === 0) throw new Error(`No ProfitAndLossByClass report stored for ${period_start} to ${period_end}.`)
  const row = data[0]
  const cols: string[] = (row.payload?.Columns?.Column ?? []).map((c: any) => String(c.ColTitle ?? ""))
  const resolved = resolveClassColumn(cols, class_name, includeSubclasses)
  if (!resolved) throw new Error(`Class '${class_name}' not found. Available: ${cols.filter(Boolean).join(", ")}`)
  const reduced = reduceToClassColumn(row.payload, resolved.idx)
  return { payload: reduced, fetched_at: row.fetched_at, resolved_class_name: resolved.resolved }
}

async function getPointInTimeReport(reportType: string, asOfDate: string | null) {
  let q = supabase.from("qbo_reports").select("period_start, period_end, payload, fetched_at").eq("report_type", reportType).is("class_name", null).order("period_end", { ascending: false }).limit(1)
  if (asOfDate) q = q.lte("period_end", asOfDate)
  const { data, error } = await q
  if (error) throw new Error(error.message)
  if (!data || data.length === 0) throw new Error(`No ${reportType} report found${asOfDate ? ` on or before ${asOfDate}` : ""}.`)
  return { report_type: reportType, ...data[0] }
}

async function handleTool(name: string, args: Record<string, unknown>) {
  if (name === "list_available_periods") {
    const reportType = typeof args.report_type === "string" ? args.report_type : null
    const { data, error } = await supabase.rpc("list_available_periods_summary", { p_report_type: reportType })
    if (error) throw new Error(error.message)
    return { __deploy: DEPLOY_VERSION, items: data ?? [] }
  }
  if (name === "get_profit_and_loss") {
    if (typeof args.period_start !== "string" || typeof args.period_end !== "string") throw new Error("period_start and period_end are required")
    const className = typeof args.class_name === "string" ? args.class_name : null
    const includeSubclasses = args.include_subclasses === undefined ? true : !!args.include_subclasses
    if (className) {
      const r = await loadByClassReport(args.period_start as string, args.period_end as string, className, includeSubclasses)
      return { report_type: "ProfitAndLoss", period_start: args.period_start, period_end: args.period_end, class_name: className, resolved_class_name: r.resolved_class_name, payload: r.payload, fetched_at: r.fetched_at }
    }
    const { data, error } = await supabase.from("qbo_reports").select("report_type, period_start, period_end, class_name, payload, fetched_at").eq("report_type", "ProfitAndLoss").eq("period_start", args.period_start as string).eq("period_end", args.period_end as string).is("class_name", null)
    if (error) throw new Error(error.message)
    if (!data || data.length === 0) throw new Error(`No P&L found for ${args.period_start} to ${args.period_end}`)
    return data.sort((a: any, b: any) => new Date(b.fetched_at).getTime() - new Date(a.fetched_at).getTime())[0]
  }
  if (name === "get_pl_summary") {
    if (typeof args.period_start !== "string" || typeof args.period_end !== "string") throw new Error("period_start and period_end are required")
    const className = typeof args.class_name === "string" ? args.class_name : null
    const includeSubclasses = args.include_subclasses === undefined ? true : !!args.include_subclasses
    if (className) {
      const r = await loadByClassReport(args.period_start as string, args.period_end as string, className, includeSubclasses)
      const summary: any = buildSummary(r.payload, args.period_start as string, args.period_end as string, className)
      summary.resolved_class_name = r.resolved_class_name
      return summary
    }
    const { data, error } = await supabase.from("qbo_reports").select("payload, fetched_at").eq("report_type", "ProfitAndLoss").eq("period_start", args.period_start as string).eq("period_end", args.period_end as string).is("class_name", null).order("fetched_at", { ascending: false }).limit(1)
    if (error) throw new Error(error.message)
    if (!data || data.length === 0) throw new Error(`No P&L found for ${args.period_start} to ${args.period_end}`)
    return buildSummary(data[0].payload, args.period_start as string, args.period_end as string, null)
  }
  if (name === "get_balance_sheet") {
    const asOfDate = typeof args.as_of_date === "string" ? args.as_of_date : null
    return await getPointInTimeReport("BalanceSheet", asOfDate)
  }
  if (name === "get_aged_receivables") {
    const asOfDate = typeof args.as_of_date === "string" ? args.as_of_date : null
    return await getPointInTimeReport("AgedReceivables", asOfDate)
  }
  if (name === "get_aged_payables") {
    const asOfDate = typeof args.as_of_date === "string" ? args.as_of_date : null
    return await getPointInTimeReport("AgedPayables", asOfDate)
  }
  if (name === "get_cash_flow") {
    const periodStart = typeof args.period_start === "string" ? args.period_start : null
    const periodEnd   = typeof args.period_end   === "string" ? args.period_end   : null
    let q = supabase.from("qbo_reports").select("period_start, period_end, payload, fetched_at").eq("report_type", "CashFlow").is("class_name", null).order("fetched_at", { ascending: false }).limit(1)
    if (periodStart) q = q.eq("period_start", periodStart)
    if (periodEnd)   q = q.eq("period_end",   periodEnd)
    const { data, error } = await q
    if (error) throw new Error(error.message)
    if (!data || data.length === 0) throw new Error(`No CashFlow report found${periodStart || periodEnd ? ` matching ${periodStart} to ${periodEnd}` : ""}.`)
    return { report_type: "CashFlow", ...data[0] }
  }
  if (name === "list_classes") {
    const { data, error } = await supabase.from("qbo_classes").select("class_name, parent_class_name, qbo_class_id, sync_enabled").order("class_name")
    if (error) throw new Error(error.message)
    return data
  }
  if (name === "list_budgets") {
    const { data, error } = await supabase.from("qbo_budgets").select("budget_id, budget_name, start_date, end_date, budget_type, fetched_at").order("start_date", { ascending: false })
    if (error) throw new Error(error.message)
    return data
  }
  if (name === "get_budget") {
    if (typeof args.budget_id !== "string") throw new Error("budget_id is required")
    const { data, error } = await supabase.from("qbo_budgets").select("budget_id, budget_name, start_date, end_date, budget_type, payload, fetched_at").eq("budget_id", args.budget_id).single()
    if (error) throw new Error(error.message)
    return data
  }
  if (name === "get_budget_vs_actuals") {
    if (typeof args.period_start !== "string" || typeof args.period_end !== "string") throw new Error("period_start and period_end are required")
    if (!BACKFILL_SECRET) throw new Error("BACKFILL_SECRET env var not configured on this Netlify project; required to call qbo-budget-vs-actuals.")
    const res = await fetch(`${SUPABASE_URL}/functions/v1/qbo-budget-vs-actuals`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: BACKFILL_SECRET, start_date: args.period_start, end_date: args.period_end }),
    })
    if (!res.ok) {
      const errBody = await res.text()
      throw new Error(`BvA fetch failed (${res.status}): ${errBody}`)
    }
    return await res.json()
  }
  if (name === "get_sync_health") {
    const { data, error } = await supabase.rpc("qbo_sync_health")
    if (error) throw new Error(error.message)
    return {
      items: data ?? [],
      overall_status:
        (data ?? []).some((r: any) => r.status === "CRITICAL") ? "CRITICAL" :
        (data ?? []).some((r: any) => r.status === "STALE")    ? "STALE"    : "HEALTHY",
    }
  }
  throw new Error(`Unknown tool: ${name}`)
}

// ============================================================================
// Main edge function
// ============================================================================
export default async (req: Request, _context: unknown) => {
  const url  = new URL(req.url)
  const path = url.pathname

  // OAuth metadata endpoint (RFC 8414)
  if (path.endsWith("/.well-known/oauth-authorization-server")) {
    return jsonRes({
      issuer: BASE_URL,
      authorization_endpoint: `${BASE_URL}/authorize`,
      token_endpoint:         `${BASE_URL}/token`,
      registration_endpoint:  `${BASE_URL}/register`,
      response_types_supported: ["code"],
      grant_types_supported:    ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["read"],
    })
  }

  // RFC 7591 Dynamic Client Registration. Production exposes this and Claude's
  // MCP client uses it. Minimal implementation that returns a synthesized
  // client_id (the registration is purely informational - we don't enforce
  // client_id matching at /token since we use PKCE).
  if (path.endsWith("/register")) {
    if (req.method !== "POST") return jsonRes({ error: "method_not_allowed" }, 405)
    let body: any = {}
    try { body = await req.json() } catch {}
    const client_id = crypto.randomUUID()
    return jsonRes({
      client_id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      token_endpoint_auth_method: "none",
      grant_types: body.grant_types ?? ["authorization_code"],
      response_types: body.response_types ?? ["code"],
      redirect_uris: body.redirect_uris ?? [],
      client_name: body.client_name ?? "MCP Client",
      scope: body.scope ?? "read",
    }, 201)
  }

  // Authorize endpoint
  if (path.endsWith("/authorize")) {
    const code_challenge        = url.searchParams.get("code_challenge")        ?? ""
    const code_challenge_method = url.searchParams.get("code_challenge_method") ?? "S256"
    const state                 = url.searchParams.get("state")                 ?? ""
    const redirect_uri          = url.searchParams.get("redirect_uri")          ?? ""
    const rawParams             = url.searchParams.toString()
    if (req.method === "GET") return htmlRes(loginHtml(rawParams))
    if (req.method === "POST") {
      let secret = ""
      const ct = req.headers.get("content-type") ?? ""
      if (ct.includes("application/x-www-form-urlencoded")) {
        const form = new URLSearchParams(await req.text())
        secret = form.get("secret") ?? ""
      } else {
        try {
          const j = await req.json()
          secret = j.secret ?? ""
        } catch {}
      }
      if (secret !== MCP_SECRET) return htmlRes(loginHtml(rawParams, "Invalid API key. Please try again."), 401)
      if (code_challenge_method !== "S256") return htmlRes(loginHtml(rawParams, "Unsupported code challenge method."), 400)
      const code = await createCode(code_challenge, redirect_uri)
      const redirectUrl = new URL(redirect_uri)
      redirectUrl.searchParams.set("code", code)
      redirectUrl.searchParams.set("state", state)
      return new Response(null, { status: 302, headers: { Location: redirectUrl.toString() } })
    }
  }

  // Token endpoint
  if (path.endsWith("/token")) {
    if (req.method !== "POST") return jsonRes({ error: "method_not_allowed" }, 405)
    let code = "", code_verifier = "", grant_type = ""
    const ct = req.headers.get("content-type") ?? ""
    if (ct.includes("application/x-www-form-urlencoded")) {
      const form = new URLSearchParams(await req.text())
      code           = form.get("code")           ?? ""
      code_verifier  = form.get("code_verifier")  ?? ""
      grant_type     = form.get("grant_type")     ?? ""
    } else {
      try {
        const j = await req.json()
        code          = j.code          ?? ""
        code_verifier = j.code_verifier ?? ""
        grant_type    = j.grant_type    ?? ""
      } catch {
        return jsonRes({ error: "invalid_request" }, 400)
      }
    }
    if (grant_type !== "authorization_code") return jsonRes({ error: "unsupported_grant_type" }, 400)
    const codeData = await verifyCode(code)
    if (!codeData) return jsonRes({ error: "invalid_grant", error_description: "Code is invalid or expired" }, 400)
    const challenge = await sha256Base64url(code_verifier)
    if (challenge !== codeData.cc) return jsonRes({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400)
    const access_token = await createAccessToken()
    return jsonRes({ access_token, token_type: "bearer", expires_in: 31536000 })
  }

  // MCP JSON-RPC endpoint (everything else)
  let body: { id?: unknown; method?: string; params?: Record<string, unknown> }
  try { body = await req.json() } catch {
    return jsonRes({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400)
  }

  // Discovery and keepalive methods are public to match v3.1.0 production
  // behavior. This lets MCP clients (e.g. Claude's connector) discover server
  // capabilities and tool definitions before initiating the OAuth flow.
  // Data-accessing methods (notably tools/call) still require a valid bearer
  // token or the MCP_SECRET.
  const PUBLIC_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list"])
  const isPublicMethod = typeof body.method === "string" && PUBLIC_METHODS.has(body.method)

  if (!isPublicMethod) {
    const authHeader = req.headers.get("Authorization") ?? ""
    const token = authHeader.replace(/^Bearer\s+/i, "").trim()
    const authed = token === MCP_SECRET || (token.length > 0 && (await verifyAccessToken(token)))
    if (!authed) {
      return jsonRes(
        { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32000, message: "Unauthorized" } },
        401,
        { "WWW-Authenticate": `Bearer realm="${BASE_URL}"` },
      )
    }
  }

  const { id, method, params } = body
  const ok  = (result: unknown) => jsonRes({ jsonrpc: "2.0", id, result })
  const err = (code: number, message: string) => jsonRes({ jsonrpc: "2.0", id, error: { code, message } })
  try {
    if (method === "initialize") return ok({ protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "knd-qbo", version: DEPLOY_VERSION } })
    if (method === "notifications/initialized") return new Response(null, { status: 204 })
    if (method === "ping") return ok({})
    if (method === "tools/list") return ok({ tools: TOOLS })
    if (method === "tools/call") {
      const toolName = params?.name
      const toolArgs = (params?.arguments ?? {}) as Record<string, unknown>
      if (typeof toolName !== "string") return err(-32602, "Invalid params: name required")
      const result = await handleTool(toolName, toolArgs)
      return ok({ content: [{ type: "text", text: JSON.stringify(result) }] })
    }
    return err(-32601, `Method not found: ${method}`)
  } catch (e) {
    return err(-32603, e instanceof Error ? e.message : String(e))
  }
}

export const config = {
  path: "/*",
}
