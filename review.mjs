/** Pure helpers for run.mjs, kept separate so they can be tested without git or the network. */

export const LEVELS = ["pass", "warn", "block"];

const csv = (s) => String(s ?? "").split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const bool = (s) => /^(true|1|yes)$/i.test(String(s ?? "").trim());

/** Hugging Face repo ids referenced from code and config (not prose), deduplicated, in first-seen order. */
export function huggingFaceRefs(text) {
  const models = new Set();
  const datasets = new Set();
  const id = String.raw`([A-Za-z0-9][\w.-]{0,95}\/[A-Za-z0-9][\w.-]{0,95})`;
  const take = (re, set) => { for (const m of text.matchAll(re)) set.add(m[1].replace(/\.git$/, "")); };
  take(new RegExp(String.raw`from_pretrained\(\s*["']${id}["']`, "g"), models);
  take(new RegExp(String.raw`\b(?:model|model_id|model_name|repo_id|pretrained_model_name_or_path)\s*[=:]\s*["']${id}["']`, "g"), models);
  take(new RegExp(String.raw`(?:huggingface\.co|hf\.co)\/(?!datasets\/|spaces\/|docs\/|blog\/|papers\/)${id}`, "g"), models);
  take(new RegExp(String.raw`load_dataset\(\s*["']${id}["']`, "g"), datasets);
  take(new RegExp(String.raw`(?:huggingface\.co|hf\.co)\/datasets\/${id}`, "g"), datasets);
  for (const d of datasets) models.delete(d);
  return { models: [...models], datasets: [...datasets] };
}

/** Body builders for agents that read repository files rather than the PR diff. `ctx` is collected by run.mjs. */
const BUILDERS = {
  "cra-exploit-clock": (ctx, opt) => {
    const body = { sbom: ctx.sbom };
    if (opt.productName) body.product = { name: opt.productName, ...(opt.productVersion ? { version: opt.productVersion } : {}) };
    if (opt.awarenessTime) body.awareness_time = opt.awarenessTime;
    if (opt.fixAvailableAt) body.fix_available_at = opt.fixAvailableAt;
    return body;
  },
  "dependency-advisor": (ctx, opt) => ({ files: ctx.files, mode: opt.mode === "deterministic" ? "deterministic" : "auto", ...(opt.repoLicense ? { repoLicense: opt.repoLicense } : {}) }),
  "ai-bom-license-resolver": (ctx, opt) => {
    const use = { id: "this-repo", commercial: bool(opt.commercial), distribution: opt.distribution, fine_tune: bool(opt.fineTune) };
    if (opt.monthlyActiveUsers) use.monthly_active_users = Number(opt.monthlyActiveUsers);
    if (opt.jurisdiction) use.jurisdiction = opt.jurisdiction.toUpperCase();
    return { models: ctx.models, ...(ctx.datasets.length ? { datasets: ctx.datasets } : {}), uses: [use] };
  },
  "reference-verifier": (ctx, opt) => ({ bibtex: ctx.bibtex, ...(ctx.manuscript ? { manuscript: ctx.manuscript } : {}), ...(bool(opt.checkSupport) && ctx.manuscript ? { checkSupport: true } : {}) }),
};

export const AGENTS = {
  "pre-merge-review": { path: "/api/v1/bundles/pre-merge-review", needsDiff: true, body: (diff) => ({ diff }) },
  "diff-gatekeeper": { path: "/api/v1/gatekeep-diff", needsDiff: true, body: (diff) => ({ gitDiff: diff }) },
  "unicode-safety-gate": { path: "/api/v1/unicode-safety-gate", needsDiff: true, body: (diff) => ({ diff }) },
  "cra-exploit-clock": { path: "/api/v1/cra-exploit-clock", needsDiff: false, build: BUILDERS["cra-exploit-clock"] },
  "dependency-advisor": { path: "/api/v1/audit-dependencies", needsDiff: false, build: BUILDERS["dependency-advisor"] },
  "ai-bom-license-resolver": { path: "/api/v1/ai-bom-license-resolver", needsDiff: false, build: BUILDERS["ai-bom-license-resolver"] },
  "reference-verifier": { path: "/api/v1/verify-references", needsDiff: false, build: BUILDERS["reference-verifier"] },
};

export const FAIL_ON = ["block", "warn", "never"];

export const DISTRIBUTIONS = ["api", "weights", "on_prem"];

/** Options that change correctness and therefore have no default; returns an error message or undefined. */
export function validateOptions(agent, opt) {
  if (agent === "ai-bom-license-resolver") {
    if (!/^(true|false)$/i.test(String(opt.commercial ?? "").trim())) return "commercial must be set to true or false: it decides which license clauses apply";
    if (!DISTRIBUTIONS.includes(opt.distribution)) return `distribution must be one of ${DISTRIBUTIONS.join(", ")}`;
    if (opt.monthlyActiveUsers && !/^\d{1,13}$/.test(opt.monthlyActiveUsers)) return "monthly-active-users must be a whole number";
    if (opt.jurisdiction && !/^[A-Za-z]{2}$/.test(opt.jurisdiction)) return "jurisdiction must be an ISO 3166-1 alpha-2 code such as DE";
  }
  if (agent === "cra-exploit-clock") {
    for (const [k, v] of [["awareness-time", opt.awarenessTime], ["fix-available-at", opt.fixAvailableAt]]) {
      if (v && Number.isNaN(Date.parse(v))) return `${k} must be an ISO 8601 time with a UTC offset, e.g. 2026-11-04T09:30:00Z`;
    }
  }
  return undefined;
}

export { csv };

/** Pass/warn/block decision from any agent's response data. `approved` is false only for block. */
export function decide(agent, data) {
  if (agent === "pre-merge-review" || agent === "diff-gatekeeper" || agent === "unicode-safety-gate") {
    const gate = agent === "pre-merge-review" ? data.results?.["diff-gatekeeper"] : agent === "diff-gatekeeper" ? data : undefined;
    const uni = agent === "pre-merge-review" ? data.results?.["unicode-safety-gate"] : agent === "unicode-safety-gate" ? data : undefined;
    const unicodeVerdict = uni?.verdict;
    const approved = agent === "pre-merge-review" ? data.mergeApproved === true : agent === "diff-gatekeeper" ? gate?.mergeApproved === true : unicodeVerdict !== "block";
    return { approved, level: !approved ? "block" : unicodeVerdict === "warn" ? "warn" : "pass", unicodeVerdict, gate, uni };
  }
  let level = "pass";
  if (agent === "cra-exploit-clock") level = data.verdict === "EXPLOITED_CANDIDATES_FOUND" ? "block" : data.verdict === "NO_EXPLOITED_EVIDENCE" ? "pass" : "warn";
  else if (agent === "ai-bom-license-resolver") level = data.verdict === "CONFLICT" ? "block" : data.verdict === "ALLOWED" ? "pass" : "warn";
  else if (agent === "dependency-advisor") {
    const f = Array.isArray(data.findings) ? data.findings : [];
    level = f.some((x) => x?.kind === "vulnerable" && ["high", "critical"].includes(x?.severity)) ? "block" : f.some((x) => ["high", "critical"].includes(x?.severity)) ? "warn" : "pass";
  } else if (agent === "reference-verifier") {
    const actions = Array.isArray(data.priorityActions) ? data.priorityActions : [];
    level = actions.some((a) => a?.severity === "critical") ? "block" : (data.summary?.flagged ?? 0) > 0 ? "warn" : "pass";
  }
  return { approved: level !== "block", level, data };
}

export function shouldFail(failOn, { approved, level }) {
  if (failOn === "never") return false;
  if (!approved) return true;
  return failOn === "warn" && level === "warn";
}

const esc = (s) => String(s ?? "").replace(/[|<>]/g, (c) => ({ "|": "\\|", "<": "&lt;", ">": "&gt;" })[c]).replace(/\r?\n/g, " ");
const LABEL = { pass: "passed", warn: "needs attention", block: "changes required" };

function bodyLines(agent, d, notes) {
  const lines = [];
  const data = d.data ?? {};
  if (agent === "cra-exploit-clock") {
    lines.push(`Verdict: **${esc(data.verdict)}**. ${esc(data.summary)}`, "");
    const dl = data.deadlines ?? {};
    if (data.verdict === "EXPLOITED_CANDIDATES_FOUND") {
      lines.push(`If you became aware at ${esc(dl.awareness_time ?? data.awareness_time ?? "the time of this run")}, CRA Art. 14(2) deadlines would be: early warning ${esc(dl.early_warning_due)}, notification ${esc(dl.notification_due)}, final report ${esc(dl.final_report_due ?? "14 days after a fix is available")}. Set \`awareness-time\` to your actual awareness time; it defaults to the time of each run.`, "");
    }
    const comps = (Array.isArray(data.components) ? data.components : []).filter((c) => c?.verdict === "EXPLOITED_REPORTABLE_CANDIDATE" || c?.verdict === "INSUFFICIENT_EVIDENCE");
    if (comps.length) {
      lines.push("| Component | Verdict | KEV | EUVD exploited | EPSS |", "|---|---|---|---|---|");
      for (const c of comps.slice(0, 40)) lines.push(`| ${esc(c.purl)} | ${esc(c.verdict)} | ${c.kev ? "yes" : "no"} | ${c.euvd_exploited ? "yes" : "no"} | ${esc(c.epss ?? "")} |`);
      lines.push("");
    }
    lines.push("Evidence and arithmetic, not legal advice: whether to notify is your determination.", "");
  } else if (agent === "dependency-advisor") {
    const s = data.summary ?? {};
    lines.push(`${esc(s.declaredPackages ?? 0)} declared packages, ${esc(s.findings ?? 0)} findings (${esc(s.high ?? 0)} high).`, "");
    const f = (Array.isArray(data.findings) ? data.findings : []).filter((x) => x && typeof x === "object");
    if (f.length) {
      lines.push("| Severity | Package | Kind | Action |", "|---|---|---|---|");
      for (const x of f.slice(0, 50)) lines.push(`| ${esc(x.severity)} | ${esc(x.package)} | ${esc(x.kind)} | ${esc(x.action ?? x.summary)} |`);
      lines.push("");
    }
  } else if (agent === "ai-bom-license-resolver") {
    lines.push(`Verdict: **${esc(data.verdict)}**. ${esc(data.summary)}`, "");
    if (data.next_step) lines.push(`Next step: ${esc(data.next_step)}`, "");
    for (const u of Array.isArray(data.uses) ? data.uses : []) {
      for (const c of (u.conflicts ?? []).slice(0, 10)) for (const cl of (c.clauses ?? []).slice(0, 3)) lines.push(`- Conflict: ${esc(cl.license)} ${esc(cl.ref)}: "${esc(String(cl.quote ?? "").slice(0, 200))}" (${esc(cl.source_url)})`);
      for (const x of (u.undetermined ?? []).slice(0, 10)) lines.push(`- Undetermined: ${esc(x.code)} ${esc(x.node)} ${esc(x.detail)}`);
    }
    lines.push("");
  } else if (agent === "reference-verifier") {
    const s = data.summary ?? {};
    lines.push(`${esc(s.total ?? 0)} references checked, ${esc(s.flagged ?? 0)} flagged.`, "");
    const acts = Array.isArray(data.priorityActions) ? data.priorityActions : [];
    for (const a of acts.slice(0, 10)) lines.push(`- ${esc(a.severity)} [${esc(a.key ?? a.index)}] ${esc(a.status)}: ${esc(a.action)}`);
    if (acts.length) lines.push("");
  }
  for (const n of notes ?? []) lines.push(`Note: ${esc(n)}`);
  if (notes?.length) lines.push("");
  return lines;
}

/** Markdown for $GITHUB_STEP_SUMMARY. */
export function summary(agent, decision, envelope, verifyUrl, notes = []) {
  const { approved, unicodeVerdict, gate, uni } = decision;
  const legacy = AGENTS[agent]?.needsDiff;
  const lines = [`## WritersLogic ${agent}: ${legacy ? (approved ? "approved" : "changes required") : LABEL[decision.level]}`, ""];
  if (gate) {
    lines.push(`Risk score: ${gate.riskScore ?? "n/a"}/100`, "");
    const blockers = Array.isArray(gate.blockers) ? gate.blockers : [];
    for (const b of blockers.slice(0, 30)) lines.push(`- Blocker: ${esc(b)}`);
    if (blockers.length) lines.push("");
    const findings = [...(gate.securityFlaws ?? []), ...(gate.bugs ?? []), ...(gate.breakingChanges ?? [])].filter((f) => f && typeof f === "object");
    if (findings.length) {
      lines.push("| Severity | File | Finding |", "|---|---|---|");
      for (const f of findings.slice(0, 50)) lines.push(`| ${esc(f.severity)} | ${esc(f.file)} | ${esc(f.description)} |`);
      lines.push("");
    }
  }
  if (uni) {
    lines.push(`Unicode / Trojan Source gate: **${esc(unicodeVerdict)}** (${esc(uni.verdictReason)})`, "");
    const findings = Array.isArray(uni.findings) ? uni.findings : [];
    for (const f of findings.slice(0, 30)) lines.push(`- ${esc(f.severity)} ${esc(f.ruleId)} ${esc(f.ruleName)} at ${esc(f.path)}:${esc(f.line)}`);
    if (findings.length) lines.push("");
  }
  if (!legacy) lines.push(...bodyLines(agent, decision, notes));
  const id = envelope?._provenance?.credential?.id;
  lines.push(`Signed by the hub (${esc(envelope?._provenance?.credential?.issuer ?? "unknown issuer")})${id ? `, credential ${esc(id)}` : ""}. Verify the saved report free at ${verifyUrl}.`);
  return lines.join("\n");
}
