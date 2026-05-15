--- /home/claude/work/mcp.ts.before	2026-05-15 00:48:14.377819091 +0000
+++ netlify/edge-functions/mcp.ts	2026-05-15 00:49:33.705349793 +0000
@@ -18,7 +18,6 @@
 const MCP_SECRET            = Netlify.env.get("MCP_SECRET")            ?? ""
 const SUPABASE_URL          = Netlify.env.get("SUPABASE_URL")          ?? ""
 const SUPABASE_SERVICE_KEY  = Netlify.env.get("SUPABASE_SERVICE_KEY")  ?? ""
-const BACKFILL_SECRET       = Netlify.env.get("BACKFILL_SECRET")       ?? ""
 const BASE_URL              = Netlify.env.get("BASE_URL")              ?? "https://mcp.kndlandscaping.com"
 const DEPLOY_VERSION        = "4.0.0"
 
@@ -334,6 +333,214 @@
   return { report_type: reportType, ...data[0] }
 }
 
+// ============================================================================
+// Budget vs Actuals helpers
+// ============================================================================
+// Ported inline from the qbo-budget-vs-actuals Supabase edge function (v8) on
+// 2026-05-14 to eliminate the proxy hop, second auth surface (BACKFILL_SECRET),
+// and Deno cold-start penalty. Math is byte-identical to the edge function;
+// only the I/O layer (auth + HTTP wrapper) changed.
+
+function bvaExtractActuals(node: any, out: Record<string, number> = {}): Record<string, number> {
+  if (!node) return out
+  if (Array.isArray(node)) { node.forEach((n: any) => bvaExtractActuals(n, out)); return out }
+  if (node.type === "Data" && node.ColData?.[0]?.id) {
+    const v = parseFloat(node.ColData[1]?.value || "0")
+    if (v) out[String(node.ColData[0].id)] = (out[String(node.ColData[0].id)] || 0) + v
+  }
+  if (node.Rows?.Row) bvaExtractActuals(node.Rows.Row, out)
+  return out
+}
+
+function bvaGroupSummary(rows: any[], group: string): number {
+  for (const row of rows) {
+    if (row.group === group) return parseFloat(row.Summary?.ColData?.[1]?.value || "0") || 0
+    if (row.Rows?.Row) {
+      const sub = bvaGroupSummary(Array.isArray(row.Rows.Row) ? row.Rows.Row : [row.Rows.Row], group)
+      if (sub !== 0) return sub
+    }
+  }
+  return 0
+}
+
+function bvaSectionTotal(rows: any[], sectionId: string): number {
+  for (const row of rows) {
+    if (row.Header?.ColData?.[0]?.id === sectionId)
+      return parseFloat(row.Summary?.ColData?.[1]?.value || "0") || 0
+    if (row.Rows?.Row) {
+      const sub = bvaSectionTotal(Array.isArray(row.Rows.Row) ? row.Rows.Row : [row.Rows.Row], sectionId)
+      if (sub !== 0) return sub
+    }
+  }
+  return 0
+}
+
+async function computeBudgetVsActuals(period_start: string, period_end: string) {
+  // Resolve realm_id from cached tokens
+  const { data: tokenRow } = await supabase
+    .from("qbo_tokens")
+    .select("realm_id")
+    .order("updated_at", { ascending: false })
+    .limit(1)
+    .single()
+  const realm_id = tokenRow?.realm_id
+  if (!realm_id) throw new Error("No realm_id found in qbo_tokens")
+
+  // Match budget from cache by fiscal year on start_date.
+  // (start_date is a DATE column; use range filter, not .like().)
+  const year = period_start.slice(0, 4)
+  const { data: budgetRows, error: budgetErr } = await supabase
+    .from("qbo_budgets")
+    .select("budget_name, payload")
+    .eq("realm_id", realm_id)
+    .gte("start_date", `${year}-01-01`)
+    .lte("start_date", `${year}-12-31`)
+    .eq("budget_type", "ProfitAndLoss")
+    .order("fetched_at", { ascending: false })
+    .limit(1)
+  if (budgetErr || !budgetRows || budgetRows.length === 0)
+    throw new Error(`No cached budget found for year ${year}. Run qbo-cache-budgets first.`)
+
+  const fy = budgetRows[0].payload
+  const budgetName = budgetRows[0].budget_name
+
+  // Build set of months in requested range
+  const monthSet = new Set<string>()
+  const s = new Date(period_start)
+  const e = new Date(period_end)
+  const cur = new Date(s.getFullYear(), s.getMonth(), 1)
+  while (cur <= e) {
+    monthSet.add(cur.toISOString().slice(0, 10))
+    cur.setMonth(cur.getMonth() + 1)
+  }
+
+  // Sum budget entries for those months by account
+  const bMap: Record<string, number> = {}
+  for (const entry of (fy.BudgetDetail || [])) {
+    if (monthSet.has(entry.BudgetDate) && entry.AccountRef?.value) {
+      const id = String(entry.AccountRef.value)
+      bMap[id] = (bMap[id] || 0) + (entry.Amount || 0)
+    }
+  }
+
+  // Fetch actuals from cached qbo_reports
+  const { data: pl, error: plErr } = await supabase.from("qbo_reports").select("payload")
+    .eq("report_type", "ProfitAndLoss")
+    .eq("period_start", period_start)
+    .eq("period_end", period_end)
+    .is("class_name", null)
+    .single()
+  if (plErr || !pl) throw new Error(`Actuals not found for ${period_start} to ${period_end}. Run qbo-backfill first.`)
+
+  const plRows: any[] = pl.payload?.Rows?.Row || []
+  const aq = bvaExtractActuals(pl.payload?.Rows?.Row)
+  const sumB = (ids: string[]): number => ids.reduce((acc, id) => acc + (bMap[id] || 0), 0)
+
+  const actual = {
+    revenue:           bvaGroupSummary(plRows, "Income"),
+    cogs:              bvaGroupSummary(plRows, "COGS"),
+    gross_profit:      bvaGroupSummary(plRows, "GrossProfit"),
+    opex:              bvaGroupSummary(plRows, "Expenses"),
+    net_op_income:     bvaGroupSummary(plRows, "NetOperatingIncome"),
+    other_income:      bvaGroupSummary(plRows, "OtherIncome"),
+    other_expenses:    bvaGroupSummary(plRows, "OtherExpenses"),
+    net_income:        bvaGroupSummary(plRows, "NetIncome"),
+    commercial_rev:    aq["56"]  || 0,
+    residential_rev:   aq["57"]  || 0,
+    maintenance_rev:   aq["48"]  || 0,
+    enhancements_rev:  aq["153"] || 0,
+    irrigation_rev:    aq["353"] || 0,
+    cogs_commercial:   bvaSectionTotal(plRows, "314"),
+    cogs_residential:  bvaSectionTotal(plRows, "320"),
+    cogs_maintenance:  bvaSectionTotal(plRows, "326"),
+    cogs_enhancements: bvaSectionTotal(plRows, "332"),
+    cogs_irrigation:   bvaSectionTotal(plRows, "338"),
+    staff:             bvaSectionTotal(plRows, "414"),
+    travel:            bvaSectionTotal(plRows, "417"),
+    emp_other:         bvaSectionTotal(plRows, "418"),
+    training:          bvaSectionTotal(plRows, "415"),
+    utilities:         bvaSectionTotal(plRows, "541"),
+    rent:              bvaSectionTotal(plRows, "539"),
+    insurance:         bvaSectionTotal(plRows, "267"),
+    office:            bvaSectionTotal(plRows, "627"),
+    comms:             bvaSectionTotal(plRows, "416"),
+    prof_services:     bvaSectionTotal(plRows, "691"),
+    ga_total:          bvaSectionTotal(plRows, "91"),
+    auto_truck:        bvaSectionTotal(plRows, "547"),
+    safety:            bvaSectionTotal(plRows, "569"),
+    repairs:           bvaSectionTotal(plRows, "419"),
+    yard:              bvaSectionTotal(plRows, "628"),
+    tools:             bvaSectionTotal(plRows, "531"),
+    ops_total:         bvaSectionTotal(plRows, "269"),
+    sm_total:          bvaSectionTotal(plRows, "261"),
+  }
+
+  // ==========================================================================
+  // BUDGET ROLLUPS - FRAGILE: HARDCODED QBO ACCOUNT IDs
+  // ==========================================================================
+  // QBO budgets are flat (account_id, month, amount) tuples with no section
+  // hierarchy. So unlike actuals (summed via P&L section headers), budget
+  // rollups MUST list each account ID explicitly below.
+  //
+  // FAILURE MODES:
+  //   1. New account added to QBO Chart of Accounts -> its budget won't roll
+  //      up into any group below. Totals too low; variance misleading.
+  //   2. Account renumbered/merged in QBO -> same effect.
+  //   3. New rollup group added -> needs entry here AND a matching
+  //      bvaSectionTotal() lookup in `actual` above.
+  //
+  // DETECT DRIFT:
+  //   - Compare sum(all rollup totals here) vs sum(all entries in
+  //     fy.BudgetDetail) for the period; they should match.
+  //   - Watch for sudden, unexplained variance widening in one category.
+  //
+  // Last reviewed against K&D Chart of Accounts: 2026-05-14.
+  // ==========================================================================
+  const budget = {
+    commercial_rev:    sumB(["56"]),
+    residential_rev:   sumB(["57"]),
+    maintenance_rev:   sumB(["48"]),
+    enhancements_rev:  sumB(["153"]),
+    irrigation_rev:    sumB(["353"]),
+    cogs_commercial:   sumB(["315","316","317","318","319","346"]),
+    cogs_residential:  sumB(["321","322","323","324","325","347"]),
+    cogs_maintenance:  sumB(["327","328","329","330","331","348"]),
+    cogs_enhancements: sumB(["333","334","335","336","337","349"]),
+    cogs_irrigation:   sumB(["339","340","341","342","343","350"]),
+    staff:             sumB(["677","600","602","601","681","609","733","679","718","528","1150040011","592"]),
+    travel:            sumB(["537","622","587","726","603","719","604"]),
+    emp_other:         sumB(["588","454","421","737","743"]),
+    training:          sumB(["534","420"]),
+    utilities:         sumB(["613","683","614","685","617","686"]),
+    rent:              sumB(["583","581","672","595","597","616","723"]),
+    insurance:         sumB(["758","626","567"]),
+    office:            sumB(["678","759","713","714","722","689","669","752","742"]),
+    comms:             sumB(["422","540","625","671"]),
+    prof_services:     sumB(["750","709","725","756","717","741"]),
+    auto_truck:        sumB(["635","580","666","665","586","585","749","605","620","687","621","724","637","618","623"]),
+    safety:            sumB(["610","582","710","673","693"]),
+    repairs:           sumB(["590","429","430","442","670","599","607","720","608"]),
+    yard:              sumB(["712","667","675","736"]),
+    tools:             sumB(["664","676","680","615","684"]),
+    sm_total:          sumB(["624","412","507","262","486","596","263","264","533","535","463","265","432","271","272","1150040033"]),
+  }
+
+  const bRev  = budget.commercial_rev + budget.residential_rev + budget.maintenance_rev + budget.enhancements_rev + budget.irrigation_rev
+  const bCogs = budget.cogs_commercial + budget.cogs_residential + budget.cogs_maintenance + budget.cogs_enhancements + budget.cogs_irrigation
+  const bGp   = bRev - bCogs
+  const bGa   = budget.staff + budget.travel + budget.emp_other + budget.training + budget.utilities + budget.rent + budget.insurance + budget.office + budget.comms + budget.prof_services
+  const bOps  = budget.auto_truck + budget.safety + budget.repairs + budget.yard + budget.tools
+  const bOpex = bGa + bOps + budget.sm_total
+  const bNoi  = bGp - bOpex
+
+  return {
+    budget_name: budgetName,
+    period: { start: period_start, end: period_end },
+    actual,
+    budget: { ...budget, revenue: bRev, cogs: bCogs, gross_profit: bGp, ga_total: bGa, ops_total: bOps, opex: bOpex, net_op_income: bNoi },
+  }
+}
+
 async function handleTool(name: string, args: Record<string, unknown>) {
   if (name === "list_available_periods") {
     const reportType = typeof args.report_type === "string" ? args.report_type : null
@@ -410,17 +617,7 @@
   }
   if (name === "get_budget_vs_actuals") {
     if (typeof args.period_start !== "string" || typeof args.period_end !== "string") throw new Error("period_start and period_end are required")
-    if (!BACKFILL_SECRET) throw new Error("BACKFILL_SECRET env var not configured on this Netlify project; required to call qbo-budget-vs-actuals.")
-    const res = await fetch(`${SUPABASE_URL}/functions/v1/qbo-budget-vs-actuals`, {
-      method: "POST",
-      headers: { "Content-Type": "application/json" },
-      body: JSON.stringify({ secret: BACKFILL_SECRET, start_date: args.period_start, end_date: args.period_end }),
-    })
-    if (!res.ok) {
-      const errBody = await res.text()
-      throw new Error(`BvA fetch failed (${res.status}): ${errBody}`)
-    }
-    return await res.json()
+    return await computeBudgetVsActuals(args.period_start, args.period_end)
   }
   if (name === "get_sync_health") {
     const { data, error } = await supabase.rpc("qbo_sync_health")
